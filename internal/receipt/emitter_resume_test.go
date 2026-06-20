// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// stubMetrics records emit-failure reasons for assertion.
type stubMetrics struct {
	mu      sync.Mutex
	reasons []string
}

func (s *stubMetrics) RecordEmitFailure(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reasons = append(s.reasons, reason)
}

func (s *stubMetrics) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reasons...)
}

// emitOne signs and records a single happy-path receipt through e.
func emitOne(t *testing.T, e *Emitter) {
	t.Helper()
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
}

// allReceiptsRaw reads every action_receipt entry from dir WITHOUT verifying
// signatures, so we can inspect chains signed by mixed keys (rotation).
func allReceiptsRaw(t *testing.T, dir string) []Receipt {
	t.Helper()
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var out []Receipt
	for _, de := range entries {
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
			out = append(out, r)
		}
	}
	return out
}

func TestInitError_NilEmitter(t *testing.T) {
	t.Parallel()
	var e *Emitter
	if err := e.InitError(); err != nil {
		t.Errorf("nil emitter InitError = %v, want nil", err)
	}
}

func TestInitError_CleanResumeIsNil(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	if err := e.InitError(); err != nil {
		t.Errorf("fresh emitter InitError = %v, want nil", err)
	}
}

// TestResume_SameKeyValidTail_ResumesUnchanged is case 1: a tail signed by the
// current key with a valid signature resumes the same chain segment.
func TestResume_SameKeyValidTail_ResumesUnchanged(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)

	rec1 := newTestRecorder(t, dir, priv)
	e1 := NewEmitter(EmitterConfig{Recorder: rec1, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	emitOne(t, e1)
	emitOne(t, e1)
	if err := rec1.Close(); err != nil {
		t.Fatalf("close rec1: %v", err)
	}

	// Reopen with the SAME key. Resume should continue the chain.
	rec2 := newTestRecorder(t, dir, priv)
	e2 := NewEmitter(EmitterConfig{Recorder: rec2, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	if err := e2.InitError(); err != nil {
		t.Fatalf("InitError after same-key reopen: %v", err)
	}
	if e2.chainSeq != 2 {
		t.Fatalf("chainSeq = %d, want 2 (resumed)", e2.chainSeq)
	}
	if e2.pendingTransition != nil {
		t.Fatalf("same-key resume must not set a transition marker: %+v", e2.pendingTransition)
	}
	emitOne(t, e2)
	if err := rec2.Close(); err != nil {
		t.Fatalf("close rec2: %v", err)
	}

	receipts := allReceiptsRaw(t, dir)
	if len(receipts) != 3 {
		t.Fatalf("receipt count = %d, want 3", len(receipts))
	}
	// Seq monotonic 0,1,2 and no transition markers anywhere.
	for i, r := range receipts {
		if r.ActionRecord.ChainSeq != uint64(i) {
			t.Errorf("receipt %d chain_seq = %d, want %d", i, r.ActionRecord.ChainSeq, i)
		}
		if r.ActionRecord.KeyTransition != nil {
			t.Errorf("receipt %d unexpectedly carries a key transition marker", i)
		}
	}
}

// TestResume_RotatedKeySelfValidTail_OpensNewSegment is case 2: a tail signed
// by a DIFFERENT key whose own signature is valid is treated as a legitimate
// rotation. A new segment opens, no error, and the new segment's genesis
// receipt carries the prior tail hash + a transition marker.
func TestResume_RotatedKeySelfValidTail_OpensNewSegment(t *testing.T) {
	dir := t.TempDir()
	pubA, privA := generateTestKey(t)

	// Segment under key A.
	recA := newTestRecorder(t, dir, privA)
	eA := NewEmitter(EmitterConfig{Recorder: recA, PrivKey: privA, Principal: testPrincipal, Actor: testActor})
	emitOne(t, eA)
	emitOne(t, eA)
	if err := recA.Close(); err != nil {
		t.Fatalf("close recA: %v", err)
	}

	tailA := allReceiptsRaw(t, dir)
	priorTail := tailA[len(tailA)-1]
	priorTailHash, err := ReceiptHash(priorTail)
	if err != nil {
		t.Fatalf("hash prior tail: %v", err)
	}

	// Rotate the signing key to B and reopen. The recorder uses B too (the
	// recorder's own outer chain resumes by file content, key-agnostic).
	pubB, privB := generateTestKey(t)
	_ = pubA
	recB := newTestRecorder(t, dir, privB)
	metrics := &stubMetrics{}
	eB := NewEmitter(EmitterConfig{Recorder: recB, PrivKey: privB, Principal: testPrincipal, Actor: testActor, Metrics: metrics})
	if err := eB.InitError(); err != nil {
		t.Fatalf("rotation must NOT brick the chain, got InitError: %v", err)
	}
	if eB.chainSeq != 0 {
		t.Fatalf("new segment chainSeq = %d, want 0 (genesis of new segment)", eB.chainSeq)
	}
	if eB.chainPrevHash != priorTailHash {
		t.Fatalf("new segment chainPrevHash = %q, want prior tail hash %q", eB.chainPrevHash, priorTailHash)
	}
	if eB.pendingTransition == nil {
		t.Fatal("expected a pending key-transition marker after rotation")
	}
	if eB.pendingTransition.PriorSignerKey != hex.EncodeToString(pubA) {
		t.Errorf("transition prior_signer_key = %q, want %q", eB.pendingTransition.PriorSignerKey, hex.EncodeToString(pubA))
	}
	if eB.pendingTransition.PriorChainSeq != priorTail.ActionRecord.ChainSeq {
		t.Errorf("transition prior_chain_seq = %d, want %d", eB.pendingTransition.PriorChainSeq, priorTail.ActionRecord.ChainSeq)
	}
	if eB.pendingTransition.PriorChainHash != priorTailHash {
		t.Errorf("transition prior_chain_hash = %q, want %q", eB.pendingTransition.PriorChainHash, priorTailHash)
	}

	// First emit of the new segment must carry the marker; the second must not.
	emitOne(t, eB)
	emitOne(t, eB)
	if err := recB.Close(); err != nil {
		t.Fatalf("close recB: %v", err)
	}

	all := allReceiptsRaw(t, dir)
	if len(all) != 4 {
		t.Fatalf("total receipts = %d, want 4 (2 under A, 2 under B)", len(all))
	}
	segB := all[2:] // new segment
	if segB[0].ActionRecord.KeyTransition == nil {
		t.Fatal("first receipt of new segment must carry a transition marker")
	}
	if segB[0].ActionRecord.ChainPrevHash != priorTailHash {
		t.Errorf("new segment genesis chain_prev_hash = %q, want prior tail hash %q",
			segB[0].ActionRecord.ChainPrevHash, priorTailHash)
	}
	if segB[0].ActionRecord.ChainSeq != 0 {
		t.Errorf("new segment genesis chain_seq = %d, want 0", segB[0].ActionRecord.ChainSeq)
	}
	if segB[1].ActionRecord.KeyTransition != nil {
		t.Error("only the first receipt of the new segment may carry a transition marker")
	}
	if segB[1].ActionRecord.ChainSeq != 1 {
		t.Errorf("second new-segment receipt chain_seq = %d, want 1", segB[1].ActionRecord.ChainSeq)
	}
	// New-segment receipts are signed by B and self-verify.
	for i, r := range segB {
		if err := VerifyWithKey(r, hex.EncodeToString(pubB)); err != nil {
			t.Errorf("new segment receipt %d does not verify under key B: %v", i, err)
		}
	}
	// No emit failures recorded - rotation is not a failure.
	if got := metrics.snapshot(); len(got) != 0 {
		t.Errorf("rotation recorded emit failures %v, want none", got)
	}
}

// TestResume_TamperedTailSameKey_FailsClosed is case 3: a tail whose own
// signature is invalid fails closed even when the signer_key matches the
// current key. Tamper-detection must NOT be weakened by the rotation fix.
func TestResume_TamperedTailSameKey_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)

	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	emitOne(t, e)
	if err := rec.Close(); err != nil {
		t.Fatalf("close rec: %v", err)
	}

	corruptTailSignaturePayload(t, dir)

	rec2 := newTestRecorder(t, dir, priv)
	defer func() { _ = rec2.Close() }()
	metrics := &stubMetrics{}
	e2 := NewEmitter(EmitterConfig{Recorder: rec2, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Metrics: metrics})
	if e2.InitError() == nil {
		t.Fatal("tampered tail (same key) must fail closed, got nil InitError")
	}
	if e2.pendingTransition != nil {
		t.Fatal("a tampered tail must NOT be treated as a rotation")
	}
	// Emit must keep failing and record the chain_init reason.
	if err := e2.Emit(EmitOpts{
		ActionID: NewActionID(), Target: testTarget, Verdict: config.ActionBlock,
		Transport: testTransport, Method: http.MethodGet,
	}); err == nil {
		t.Fatal("Emit after fail-closed init must return an error")
	}
	if got := metrics.snapshot(); len(got) == 0 || got[len(got)-1] != FailReasonChainInit {
		t.Errorf("emit failure reasons = %v, want last = %q", got, FailReasonChainInit)
	}
}

// TestResume_ForgedTailDifferentKey_CannotForceSilentReset proves an attacker
// who substitutes a DIFFERENT signer_key but cannot produce a valid signature
// (case 3 under a foreign key) is rejected - they cannot force a silent chain
// reset that hides history.
func TestResume_ForgedTailDifferentKey_CannotForceSilentReset(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)

	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	emitOne(t, e)
	if err := rec.Close(); err != nil {
		t.Fatalf("close rec: %v", err)
	}

	// Forge: replace the embedded signer_key with an attacker key but leave
	// the (now mismatched) signature in place. VerifyInternalConsistencyOnly(tail) must fail.
	forgeTailSignerKeyOnly(t, dir)

	rec2 := newTestRecorder(t, dir, priv)
	defer func() { _ = rec2.Close() }()
	e2 := NewEmitter(EmitterConfig{Recorder: rec2, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	if e2.InitError() == nil {
		t.Fatal("forged tail (foreign key, bad signature) must fail closed, not silently reset")
	}
	if e2.pendingTransition != nil {
		t.Fatal("a forged tail must NOT be accepted as a legitimate rotation")
	}
}

// TestResume_EmitFailureIncrementsMetric covers the sealed and chain_init
// failure label paths through the metric sink.
func TestResume_EmitFailureIncrementsMetric(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()
	metrics := &stubMetrics{}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Metrics: metrics})
	emitOne(t, e)
	if err := e.EmitTranscriptRoot("session"); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}
	// Chain sealed: a further Emit fails with the sealed reason.
	if err := e.Emit(EmitOpts{
		ActionID: NewActionID(), Target: testTarget, Verdict: config.ActionBlock,
		Transport: testTransport, Method: http.MethodGet,
	}); err == nil {
		t.Fatal("Emit after transcript root must fail (chain sealed)")
	}
	found := false
	for _, r := range metrics.snapshot() {
		if r == FailReasonSealed {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a %q emit-failure metric, got %v", FailReasonSealed, metrics.snapshot())
	}
}

// TestEmitTranscriptRoot_ChainInitFailureRecordsMetric proves that an emitter
// bricked at construction (tampered tail) also records the chain_init failure
// metric when EmitTranscriptRoot is called, not just on Emit.
func TestEmitTranscriptRoot_ChainInitFailureRecordsMetric(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	emitOne(t, e)
	if err := rec.Close(); err != nil {
		t.Fatalf("close rec: %v", err)
	}
	corruptTailSignaturePayload(t, dir)

	rec2 := newTestRecorder(t, dir, priv)
	defer func() { _ = rec2.Close() }()
	metrics := &stubMetrics{}
	e2 := NewEmitter(EmitterConfig{Recorder: rec2, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Metrics: metrics})
	if err := e2.EmitTranscriptRoot("session"); err == nil {
		t.Fatal("EmitTranscriptRoot on a bricked emitter must return an error")
	}
	got := metrics.snapshot()
	if len(got) == 0 || got[len(got)-1] != FailReasonChainInit {
		t.Errorf("metric reasons = %v, want last = %q", got, FailReasonChainInit)
	}
}

// corruptTailSignaturePayload mutates the tail receipt's action record on disk
// so its embedded signature no longer matches (tamper), without changing the
// signer_key. The recorder's outer chain is left intact (we rewrite the entry
// detail in place via a fresh recorder write would re-sign; instead we edit the
// JSONL bytes directly).
func corruptTailSignaturePayload(t *testing.T, dir string) {
	t.Helper()
	mutateTailReceipt(t, dir, func(r *Receipt) {
		// Flip the verdict in the signed record without re-signing: the
		// signature now covers different canonical bytes -> Verify fails.
		if r.ActionRecord.Verdict == "block" {
			r.ActionRecord.Verdict = "allow"
		} else {
			r.ActionRecord.Verdict = "block"
		}
	})
}

// forgeTailSignerKeyOnly swaps the embedded signer_key to a fresh attacker key
// while leaving the original signature bytes, so VerifyInternalConsistencyOnly(tail) fails.
func forgeTailSignerKeyOnly(t *testing.T, dir string) {
	t.Helper()
	attackerPub, _ := generateTestKey(t)
	mutateTailReceipt(t, dir, func(r *Receipt) {
		r.SignerKey = hex.EncodeToString(attackerPub)
	})
}

// mutateTailReceipt rewrites the last action_receipt entry's Detail in the
// newest evidence file using mutate, preserving everything else. It edits the
// recorder JSONL line in place so the recorder's outer hash chain is not
// re-computed (simulating on-disk tampering of the inner receipt).
func mutateTailReceipt(t *testing.T, dir string, mutate func(*Receipt)) {
	t.Helper()
	dirEntries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var target string
	for _, de := range dirEntries {
		if !de.IsDir() && strings.HasSuffix(de.Name(), ".jsonl") {
			target = filepath.Join(dir, de.Name())
		}
	}
	if target == "" {
		t.Fatal("no evidence file found to mutate")
	}
	raw, err := os.ReadFile(filepath.Clean(target)) //nolint:gosec // test file under t.TempDir
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// Find the last line that is an action_receipt entry.
	idx := -1
	for i := len(lines) - 1; i >= 0; i-- {
		var entry recorder.Entry
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			continue
		}
		if entry.Type == recorderEntryType {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("no action_receipt line found")
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[idx]), &entry); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	rcpt, err := Unmarshal(entry["detail"])
	if err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	mutate(&rcpt)
	newDetail, err := Marshal(rcpt)
	if err != nil {
		t.Fatalf("marshal mutated receipt: %v", err)
	}
	entry["detail"] = newDetail
	newLine, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	lines[idx] = string(newLine)
	if err := os.WriteFile(filepath.Clean(target), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// ed25519 import kept meaningful.
var _ = ed25519.PublicKeySize
