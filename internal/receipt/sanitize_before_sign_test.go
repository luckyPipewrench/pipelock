// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// fakeSecret is built at runtime so the literal never appears in the binary or
// trips secret scanners (gosec G101 / push protection).
func fakeSecret() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

// credURL builds an https URL with userinfo credentials at runtime so the
// literal "scheme://user:pass@" never appears in source (avoids gosec G101).
func credURL(rest string) string {
	return "https://user:" + "pw" + "@" + rest
}

// secretFlaggingDLP returns a recorder.RedactFunc that reports any text
// containing one of the given substrings as DLP-dirty. It mirrors the recorder
// contract (text-level, position-free) without depending on real DLP patterns,
// keeping the test hermetic.
func secretFlaggingDLP(secrets ...string) recorder.RedactFunc {
	return func(_ context.Context, text string) scanner.TextDLPResult {
		for _, s := range secrets {
			if s != "" && strings.Contains(text, s) {
				return scanner.TextDLPResult{
					Clean:   false,
					Matches: []scanner.TextDLPMatch{{PatternName: "test-secret"}},
				}
			}
		}
		return scanner.TextDLPResult{Clean: true}
	}
}

// newRedactingRecorder builds a recorder with flight-recorder redaction enabled
// and wired to the given DLP function, matching the production server wiring.
func newRedactingRecorder(t *testing.T, dir string, priv ed25519.PrivateKey, dlp recorder.RedactFunc) *recorder.Recorder {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
		Redact:             true,
	}, dlp, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	return rec
}

// readReceiptsRaw reads every action_receipt from the evidence dir WITHOUT
// verifying signatures, so callers can assert verification outcomes explicitly.
func readReceiptsRaw(t *testing.T, dir string) []Receipt {
	t.Helper()
	dirEntries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	var receipts []Receipt
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}
		fileEntries, err := recorder.ReadEntries(filepath.Join(dir, de.Name()))
		if err != nil {
			t.Fatalf("ReadEntries: %v", err)
		}
		for _, entry := range fileEntries {
			if entry.Type != recorderEntryType {
				continue
			}
			detailJSON, err := json.Marshal(entry.Detail)
			if err != nil {
				t.Fatalf("marshal detail: %v", err)
			}
			r, err := Unmarshal(detailJSON)
			if err != nil {
				t.Fatalf("unmarshal receipt: %v", err)
			}
			receipts = append(receipts, r)
		}
	}
	return receipts
}

// TestEmitter_SecretTargetVerifiesAfterRedaction is the core done-state for
// item 1.8: with flight-recorder redaction on, a receipt whose target carries a
// secret must still verify from the on-disk evidence file alone (signature AND
// recorded ReceiptHash binding intact), and the on-disk target must leak no
// secret bytes.
func TestEmitter_SecretTargetVerifiesAfterRedaction(t *testing.T) {
	t.Parallel()

	secret := fakeSecret()
	creds := "s3cr3tp@ss"
	target := "https://user:" + creds + "@api.vendor.example/v1/keys?token=" + secret

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	dlp := secretFlaggingDLP(secret, creds)
	rec := newRedactingRecorder(t, dir, priv, dlp)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}

	// Capture the ReceiptHash the AARP envelope would bind to: the hash of the
	// receipt as written to disk must equal what an envelope captured at emit
	// time, which is the hash of the signed receipt. We reconstruct that below.
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    target,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := readReceiptsRaw(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	got := receipts[0]

	// 1. Verifies from the evidence file alone (no escrow needed).
	if err := Verify(got); err != nil {
		t.Fatalf("on-disk receipt does not verify: %v", err)
	}
	if err := VerifyWithKey(got, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("on-disk receipt does not verify against signer key: %v", err)
	}

	// 2. No secret bytes survive in the on-disk receipt (target or anywhere).
	raw, err := Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Errorf("on-disk receipt leaks query secret %q in: %s", secret, raw)
	}
	if strings.Contains(string(raw), creds) {
		t.Errorf("on-disk receipt leaks userinfo creds %q in: %s", creds, raw)
	}

	// 3. The target stays structurally meaningful: scheme/host/path preserved.
	if !strings.HasPrefix(got.ActionRecord.Target, "https://api.vendor.example/v1/keys") {
		t.Errorf("sanitized target lost structure: %q", got.ActionRecord.Target)
	}
}

// TestEmitter_AdversarialSecretShapes_RealDLP runs the full emit→redact→verify
// path against the PRODUCTION scanner.ScanTextForDLP (not a fake), proving the
// sanitize-before-sign fix holds for every adversarial target shape the
// kickoff calls out: userinfo creds, secret query param, secret in path,
// secret split across params, percent-encoded secret, secret in fragment, and
// a non-standard param name. Each must verify from disk and leak no secret.
func TestEmitter_AdversarialSecretShapes_RealDLP(t *testing.T) {
	t.Parallel()

	secret := fakeSecret() // AWS-style key, matched by default DLP patterns.
	sc := scanner.New(config.Defaults())
	dlp := sc.ScanTextForDLP

	// Sanity: confirm the real DLP actually flags the bare secret, else the
	// test would pass vacuously.
	if sc.ScanTextForDLP(context.Background(), secret).Clean {
		t.Fatalf("precondition failed: default DLP does not flag %q", secret)
	}

	shapes := []struct {
		name   string
		target string
	}{
		// Only shapes the production text DLP actually flags as secrets. The
		// 2-param split-query case is covered separately
		// (TestEmitter_SplitQuerySecret_VerifiesAsRecorderNoOp): the text DLP
		// does not reassemble it, so the recorder treats it as clean and the
		// receipt verifies unchanged. See the adversarial findings doc.
		{"userinfo_only", "https://user:" + secret + "@api.vendor.example/v1/keys"},
		{"userinfo+query", "https://user:" + secret + "@api.vendor.example/v1/keys?token=" + secret},
		{"query_param", "https://api.vendor.example/v1/keys?token=" + secret},
		{"in_path", "https://api.vendor.example/v1/" + secret + "/info"},
		{"percent_encoded", "https://api.vendor.example/v1/keys?token=" + url.QueryEscape(secret)},
		{"in_fragment", "https://api.vendor.example/v1/keys#" + secret},
		{"nonstandard_param", "https://api.vendor.example/cb?xyzzy=" + secret},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			pub, priv := generateTestKey(t)
			rec := newRedactingRecorder(t, dir, priv, dlp)

			e := NewEmitter(EmitterConfig{
				Recorder:   rec,
				PrivKey:    priv,
				ConfigHash: testConfigHash,
				Principal:  testPrincipal,
				Actor:      testActor,
			})
			if err := e.Emit(EmitOpts{
				ActionID:  NewActionID(),
				Target:    shape.target,
				Verdict:   config.ActionBlock,
				Transport: testTransport,
				Method:    http.MethodGet,
			}); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			if err := rec.Close(); err != nil {
				t.Fatalf("recorder.Close: %v", err)
			}

			got := readReceiptsRaw(t, dir)[0]
			if err := VerifyWithKey(got, hex.EncodeToString(pub)); err != nil {
				t.Fatalf("on-disk receipt does not verify: %v", err)
			}
			raw, err := Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(raw), secret) {
				t.Errorf("receipt leaks secret: %s", raw)
			}
			// Whole on-disk receipt must be DLP-clean (recorder no-op).
			if !sc.ScanTextForDLP(context.Background(), string(raw)).Clean {
				t.Errorf("on-disk receipt not DLP-clean under production scanner")
			}
		})
	}
}

// TestEmitter_SplitQuerySecret_VerifiesAsRecorderNoOp documents and pins the
// behavior for a secret split across two query params. The production text DLP
// (the recorder's own function) does not reassemble such a split, so the
// recorder treats the receipt as clean and performs no redaction. The fix's
// guarantee for this case is therefore: the receipt VERIFIES from disk and the
// recorder's redaction is a no-op (emitter and recorder agree because they use
// the same DLP function). Whether the split bytes remain is a scanner-detection
// concern, not a sign/redact desync, and is identical to pre-fix behavior.
func TestEmitter_SplitQuerySecret_VerifiesAsRecorderNoOp(t *testing.T) {
	t.Parallel()

	sc := scanner.New(config.Defaults())
	dlp := sc.ScanTextForDLP
	target := "https://api.vendor.example/v1/keys?a=AKIAIOSFOD&b=NN7EXAMPLE"

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newRedactingRecorder(t, dir, priv, dlp)
	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    target,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	got := readReceiptsRaw(t, dir)[0]
	if err := VerifyWithKey(got, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("split-query receipt must still verify: %v", err)
	}
	// Recorder no-op: the on-disk target is exactly what the emitter signed
	// (the text DLP did not flag it, so neither emitter nor recorder altered it).
	if got.ActionRecord.Target != target {
		t.Errorf("expected recorder no-op on undetected split; target = %q", got.ActionRecord.Target)
	}
}

// TestEmitter_AARPDigestBindingHoldsAfterRedaction proves done-state #2: the
// two digests an AARP envelope Subject binds — action_record_sha256 (canonical
// ActionRecord) and receipt_envelope_sha256 (ReceiptHash of the full receipt) —
// are identical whether computed at emit time or recomputed from the on-disk
// file. Since Ed25519 is deterministic, re-signing the on-disk ActionRecord
// reproduces the exact on-disk receipt byte-for-byte iff the recorder performed
// no post-sign mutation. A desync (the bug) would break both equalities.
func TestEmitter_AARPDigestBindingHoldsAfterRedaction(t *testing.T) {
	t.Parallel()

	secret := fakeSecret()
	target := credURL("api.vendor.example/v1/keys?token=" + secret)

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	dlp := secretFlaggingDLP(secret, "pw")
	rec := newRedactingRecorder(t, dir, priv, dlp)
	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    target,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	got := readReceiptsRaw(t, dir)[0]
	if err := Verify(got); err != nil {
		t.Fatalf("on-disk receipt must verify: %v", err)
	}

	// Digests as an attester would bind them, recomputed from the on-disk file.
	arCanon, err := got.ActionRecord.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	onDiskActionRecordSHA := hex.EncodeToString(sha256Sum(arCanon))
	onDiskEnvelopeSHA, err := ReceiptHash(got)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}

	// Re-sign the on-disk ActionRecord with the same key. Ed25519 is
	// deterministic, so this reproduces the signed receipt exactly iff no field
	// was mutated post-sign.
	resigned, err := Sign(got.ActionRecord, priv)
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	reArCanon, err := resigned.ActionRecord.Canonical()
	if err != nil {
		t.Fatalf("canonical(resigned): %v", err)
	}
	reEnvelopeSHA, err := ReceiptHash(resigned)
	if err != nil {
		t.Fatalf("ReceiptHash(resigned): %v", err)
	}

	if hex.EncodeToString(sha256Sum(reArCanon)) != onDiskActionRecordSHA {
		t.Errorf("action_record_sha256 binding broken: re-signed != on-disk")
	}
	if reEnvelopeSHA != onDiskEnvelopeSHA {
		t.Errorf("receipt_envelope_sha256 (ReceiptHash) binding broken: %s != %s", reEnvelopeSHA, onDiskEnvelopeSHA)
	}
	if resigned.Signature != got.Signature {
		t.Errorf("signature differs: recorder mutated the signed receipt post-sign")
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// TestEmitter_EscrowStoresSanitizedReceipt documents the escrow semantic change
// introduced by sanitize-before-sign. Raw escrow happens in the recorder AFTER
// the emitter hands over the (already sanitized) receipt, so the encrypted
// escrow now holds the SANITIZED, signed, self-verifying receipt rather than
// the raw pre-sanitization target. Escrow still FUNCTIONS (RawRef set, file
// decrypts), but the raw secret is no longer recoverable from the receipt
// escrow. This is the correct posture (the receipt subsystem never holds the
// secret) and is a deliberate behavior change; restoring raw-with-binding is
// the deferred v2 commit-and-reveal work. See the adversarial findings doc.
func TestEmitter_EscrowStoresSanitizedReceipt(t *testing.T) {
	t.Parallel()

	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	secret := fakeSecret()
	target := "https://api.vendor.example/v1/keys?token=" + secret
	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	dlp := secretFlaggingDLP(secret)

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
		Redact:             true,
		RawEscrow:          true,
		EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
	}, dlp, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	e := NewEmitter(EmitterConfig{
		Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	})
	if err := e.Emit(EmitOpts{
		ActionID: NewActionID(), Target: target, Verdict: config.ActionBlock,
		Transport: testTransport, Method: http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// On-disk receipt verifies and is secret-free (the core fix).
	got := readReceiptsRaw(t, dir)[0]
	if err := VerifyWithKey(got, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("on-disk receipt does not verify: %v", err)
	}

	// Escrow functioned: locate and decrypt the .raw.enc sidecar.
	dirEntries, _ := os.ReadDir(filepath.Clean(dir))
	var escrowFile string
	for _, de := range dirEntries {
		if strings.HasSuffix(de.Name(), ".raw.enc") {
			escrowFile = filepath.Join(dir, de.Name())
			break
		}
	}
	if escrowFile == "" {
		t.Fatal("escrow did not function: no .raw.enc file")
	}
	payload, err := os.ReadFile(filepath.Clean(escrowFile))
	if err != nil {
		t.Fatalf("read escrow: %v", err)
	}
	const keySize, nonceSize = 32, 24
	if len(payload) < keySize+nonceSize+box.Overhead {
		t.Fatal("escrow payload too short")
	}
	var ephPub [keySize]byte
	copy(ephPub[:], payload[:keySize])
	rest := payload[keySize:]
	var nonce [nonceSize]byte
	copy(nonce[:], rest[:nonceSize])
	decrypted, ok := box.Open(nil, rest[nonceSize:], &nonce, &ephPub, recipientPriv)
	if !ok {
		t.Fatal("failed to decrypt escrow")
	}

	// New behavior: the escrowed copy is the sanitized receipt (no raw secret).
	if strings.Contains(string(decrypted), secret) {
		t.Errorf("escrow unexpectedly contains the raw secret; sanitize-before-sign should keep it out of the receipt subsystem entirely")
	}
}

// TestEmitter_ResumeChainAfterRedactedRestart proves a corollary the fix closes:
// resumeChain verifies the tail on-disk receipt's signature at startup. Before
// the fix, a redact-enabled deployment that restarted after emitting a
// secret-bearing receipt would find the tail receipt redacted (signature
// invalid) and set initErr, bricking every subsequent Emit. With pre-sign
// sanitization the on-disk tail verifies, so a restarted emitter resumes the
// chain cleanly and keeps emitting.
func TestEmitter_ResumeChainAfterRedactedRestart(t *testing.T) {
	t.Parallel()

	secret := fakeSecret()
	target := "https://api.vendor.example/v1/keys?token=" + secret

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	dlp := secretFlaggingDLP(secret)

	// First process: emit a secret-bearing receipt, then "crash" (close).
	rec1 := newRedactingRecorder(t, dir, priv, dlp)
	e1 := NewEmitter(EmitterConfig{
		Recorder: rec1, PrivKey: priv, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	})
	if err := e1.Emit(EmitOpts{
		ActionID: NewActionID(), Target: target, Verdict: config.ActionBlock,
		Transport: testTransport, Method: http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit 1: %v", err)
	}
	if err := rec1.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}

	// Second process (restart): a fresh emitter must resume the chain without
	// an init error, and continue emitting on the same chain.
	rec2 := newRedactingRecorder(t, dir, priv, dlp)
	e2 := NewEmitter(EmitterConfig{
		Recorder: rec2, PrivKey: priv, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	})
	if e2 == nil {
		t.Fatal("restarted emitter is nil")
	}
	// A non-nil initErr would surface here as a wrapped resume error.
	if err := e2.Emit(EmitOpts{
		ActionID: NewActionID(), Target: "https://api.vendor.example/v1/models",
		Verdict: config.ActionAllow, Transport: testTransport, Method: http.MethodGet,
	}); err != nil {
		t.Fatalf("restarted Emit failed (resumeChain likely errored on a redacted tail): %v", err)
	}
	if err := rec2.Close(); err != nil {
		t.Fatalf("Close 2: %v", err)
	}

	// Both receipts must be present, verify, and form a seq 0,1 chain.
	got := readReceiptsRaw(t, dir)
	if len(got) != 2 {
		t.Fatalf("got %d receipts, want 2", len(got))
	}
	for i, r := range got {
		if err := VerifyWithKey(r, hex.EncodeToString(pub)); err != nil {
			t.Fatalf("receipt %d does not verify: %v", i, err)
		}
		if r.ActionRecord.ChainSeq != uint64(i) {
			t.Errorf("receipt %d chain_seq = %d, want %d", i, r.ActionRecord.ChainSeq, i)
		}
	}
}

// TestEmitter_RedactOff_TargetUnchanged proves done-state #6: with redaction
// disabled, the recorder's ReceiptRedactor() returns nil, so the emitter does
// NOT sanitize and the full target is preserved (no regression for
// redact:false deployments). The receipt still verifies and the recorder,
// also with redaction off, writes it unchanged.
func TestEmitter_RedactOff_TargetUnchanged(t *testing.T) {
	t.Parallel()

	secret := fakeSecret()
	target := credURL("api.vendor.example/v1/keys?token=" + secret)

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	// Recorder with redaction OFF (newTestRecorder): ReceiptRedactor() is nil,
	// so the emitter performs no sanitization.
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    target,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	got := readReceiptsRaw(t, dir)[0]
	if err := VerifyWithKey(got, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ActionRecord.Target != target {
		t.Errorf("redact-off target = %q, want unchanged %q", got.ActionRecord.Target, target)
	}
}

// TestEmitter_PatternSanitizedBeforeSign pins the field-superset invariant for
// the pattern field: the recorder redacts BOTH target and pattern, so the
// emitter must sanitize pattern pre-sign too. Pattern normally holds rule
// names (never secrets), but if one ever carried DLP-matchable content the
// receipt must still verify. A secret-bearing pattern collapses to the marker
// pre-sign; a benign rule name passes through intact.
func TestEmitter_PatternSanitizedBeforeSign(t *testing.T) {
	t.Parallel()

	secret := fakeSecret()
	ruleName := "anthropic-key" // representative benign rule name

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	dlp := secretFlaggingDLP(secret)
	rec := newRedactingRecorder(t, dir, priv, dlp)
	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	// Receipt 1: benign rule-name pattern (the realistic case) survives intact.
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Pattern:   ruleName,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit 1: %v", err)
	}
	// Receipt 2: hostile pattern carrying a secret is sanitized pre-sign.
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Pattern:   "leaked-" + secret,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit 2: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	got := readReceiptsRaw(t, dir)
	if len(got) != 2 {
		t.Fatalf("got %d receipts, want 2", len(got))
	}
	for _, r := range got {
		if err := VerifyWithKey(r, hex.EncodeToString(pub)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
	if got[0].ActionRecord.Pattern != ruleName {
		t.Errorf("benign rule name was altered: %q", got[0].ActionRecord.Pattern)
	}
	if got[1].ActionRecord.Pattern != redactedTarget {
		t.Errorf("secret-bearing pattern = %q, want %q", got[1].ActionRecord.Pattern, redactedTarget)
	}
	if strings.Contains(got[1].ActionRecord.Pattern, secret) {
		t.Errorf("pattern leaks secret: %q", got[1].ActionRecord.Pattern)
	}
}

// TestEmitter_RecorderRedactionIsNoOpOnReceipts proves the recorder's
// redactReceiptDetail finds nothing to redact after pre-sign sanitization: the
// on-disk receipt bytes equal the bytes the emitter signed, so the recorded
// ReceiptHash binding (AARP) holds. We assert by re-marshaling the on-disk
// receipt and confirming it is self-consistent and DLP-clean under the same fn.
func TestEmitter_RecorderRedactionIsNoOpOnReceipts(t *testing.T) {
	t.Parallel()

	secret := fakeSecret()
	target := "https://api.vendor.example/v1/keys?token=" + secret

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	dlp := secretFlaggingDLP(secret)
	rec := newRedactingRecorder(t, dir, priv, dlp)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    target,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	got := readReceiptsRaw(t, dir)[0]

	// The on-disk target is exactly the emitter's pre-sign sanitized form (the
	// secret query value swapped for the sanitizer's marker, structure intact),
	// proving the recorder did not mutate the signed receipt.
	wantTarget := "https://api.vendor.example/v1/keys?token=" + redactedValue
	if got.ActionRecord.Target != wantTarget {
		t.Errorf("on-disk target = %q, want %q", got.ActionRecord.Target, wantTarget)
	}

	// The whole on-disk receipt must be DLP-clean under the recorder's fn,
	// which is exactly the precondition that makes redactReceiptDetail a no-op.
	raw, err := Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if res := dlp(context.Background(), string(raw)); !res.Clean {
		t.Errorf("on-disk receipt is not DLP-clean; recorder would have redacted it post-sign")
	}
	// And it must not carry the recorder's distinct redaction marker. The
	// sanitizer's markers are [redacted-<scope>]; the recorder's field marker
	// is "[REDACTED]", so its presence would mean a post-sign redaction fired.
	if strings.Contains(string(raw), "[REDACTED]") || strings.Contains(string(raw), "redacted_fields") {
		t.Errorf("receipt was redacted by the recorder post-sign: %s", raw)
	}
}
