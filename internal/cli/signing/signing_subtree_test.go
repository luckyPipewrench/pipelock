// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// Deterministic ed25519 seeds for roster test fixtures, split per G101 lint.
const (
	testSubtreeRosterSeedHex = "" +
		"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
		"4449c569" + "7b326919" + "703bac03" + "1cae7f60"
	testSubtreeRosterPubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	testSubtreeRosterKeyID  = "roster-root-test"
	testSubtreeReceiptKeyID = "receipt-signing-test"
	testSubtreeDataClass    = "internal"
	testSubtreeValidFrom    = "2026-04-01T00:00:00Z"
)

// Deterministic seeds for recovery test fixtures, different from roster.
const (
	testSubtreeRecoverySeedHex = "" +
		"4ccd089b" + "28ff96da" + "9db6c346" + "ec114e0f" +
		"5b8a319f" + "35aba624" + "da8cf6ed" + "4fb8a6fb"

	testSubtreeRecoveryReason     = "roster root key compromised"
	testSubtreeRecoveryOperator   = "ops@example.com"
	testSubtreeRecoveryTargetHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Deterministic seeds for root transition test fixtures (two independent keys).
const (
	testSubtreeRTOldSeedHex = "" +
		"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
		"4449c569" + "8b64e70e" + "1b6ff1ae" + "1b6ff1ae"

	testSubtreeRTNewSeedHex = "" +
		"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
		"4449c569" + "8b64e70e" + "ae1bff6b" + "ae1bff6b"

	testSubtreeRTReason    = "scheduled annual key rotation"
	testSubtreeRTEffective = "2026-04-26T15:00:00Z"
)

// buildRosterFixture creates a signed roster JSON file in a temp dir and
// returns (filePath, pinnedFingerprint).
func buildRosterFixture(t *testing.T) (string, string) {
	t.Helper()

	seed, err := hex.DecodeString(testSubtreeRosterSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	envelope := contract.RosterEnvelope{
		Body: contract.KeyRoster{
			SchemaVersion:  1,
			RosterSignedBy: testSubtreeRosterKeyID,
			Keys: []contract.KeyInfo{
				{
					KeyID:        testSubtreeRosterKeyID,
					KeyPurpose:   string(domsigning.PurposeRosterRoot),
					PublicKeyHex: testSubtreeRosterPubHex,
					ValidFrom:    testSubtreeValidFrom,
					Status:       contract.KeyStatusRoot,
				},
				{
					KeyID:        testSubtreeReceiptKeyID,
					KeyPurpose:   string(domsigning.PurposeReceiptSigning),
					PublicKeyHex: testSubtreeRosterPubHex,
					ValidFrom:    testSubtreeValidFrom,
					Status:       contract.KeyStatusActive,
				},
			},
			DataClassRoot: testSubtreeDataClass,
		},
	}

	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("roster preimage: %v", err)
	}
	sig := ed25519.Sign(priv, preimage)
	envelope.Signature = "ed25519:" + hex.EncodeToString(sig)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "key_roster.json")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	digest := sha256.Sum256(pub)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])

	return fp, fingerprint
}

// buildRecoveryFixture creates a signed recovery authorization JSON file.
// Returns (filePath, pubkeyHex, pinnedFingerprint).
func buildRecoveryFixture(t *testing.T, now time.Time) (string, string, string) {
	t.Helper()

	seed, err := hex.DecodeString(testSubtreeRecoverySeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	envelope := domsigning.RecoveryAuthorizationEnvelope{
		Body: domsigning.RecoveryAuthorizationBody{
			SchemaVersion:    1,
			Reason:           testSubtreeRecoveryReason,
			ExpiresAt:        now.Add(30 * time.Minute).UTC().Format(time.RFC3339),
			TargetRosterHash: testSubtreeRecoveryTargetHash,
			OperatorIdentity: testSubtreeRecoveryOperator,
			IssuedAt:         now.Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		},
	}

	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("recovery preimage: %v", err)
	}
	sig := ed25519.Sign(priv, preimage)
	envelope.Signature = "ed25519:" + hex.EncodeToString(sig)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "recovery_authorization.json")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	pubHex := hex.EncodeToString(pub)
	digest := sha256.Sum256(pub)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])

	return fp, pubHex, fingerprint
}

// buildExpiredRecoveryFixture creates a recovery authorization that expired
// 10 minutes ago.
func buildExpiredRecoveryFixture(t *testing.T, now time.Time) (string, string, string) {
	t.Helper()

	seed, err := hex.DecodeString(testSubtreeRecoverySeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	envelope := domsigning.RecoveryAuthorizationEnvelope{
		Body: domsigning.RecoveryAuthorizationBody{
			SchemaVersion:    1,
			Reason:           testSubtreeRecoveryReason,
			ExpiresAt:        now.Add(-10 * time.Minute).UTC().Format(time.RFC3339),
			TargetRosterHash: testSubtreeRecoveryTargetHash,
			OperatorIdentity: testSubtreeRecoveryOperator,
			IssuedAt:         now.Add(-60 * time.Minute).UTC().Format(time.RFC3339),
		},
	}

	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("recovery preimage: %v", err)
	}
	sig := ed25519.Sign(priv, preimage)
	envelope.Signature = "ed25519:" + hex.EncodeToString(sig)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "recovery_expired.json")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	pubHex := hex.EncodeToString(pub)
	digest := sha256.Sum256(pub)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])

	return fp, pubHex, fingerprint
}

// buildTransitionFixture creates a dual-signed root transition JSON file.
// Returns (filePath, oldPubHex, newPubHex, oldFingerprint).
func buildTransitionFixture(t *testing.T) (string, string, string, string) {
	t.Helper()

	oldSeed, err := hex.DecodeString(testSubtreeRTOldSeedHex)
	if err != nil {
		t.Fatalf("decode old seed: %v", err)
	}
	oldPriv := ed25519.NewKeyFromSeed(oldSeed)
	oldPub := oldPriv.Public().(ed25519.PublicKey)

	newSeed, err := hex.DecodeString(testSubtreeRTNewSeedHex)
	if err != nil {
		t.Fatalf("decode new seed: %v", err)
	}
	newPriv := ed25519.NewKeyFromSeed(newSeed)
	newPub := newPriv.Public().(ed25519.PublicKey)

	oldDigest := sha256.Sum256(oldPub)
	oldFP := "sha256:" + hex.EncodeToString(oldDigest[:])
	newDigest := sha256.Sum256(newPub)
	newFP := "sha256:" + hex.EncodeToString(newDigest[:])

	envelope := domsigning.RootTransitionEnvelope{
		Body: domsigning.RootTransitionBody{
			SchemaVersion:  1,
			RootKind:       domsigning.RootKindRoster,
			OldFingerprint: oldFP,
			NewFingerprint: newFP,
			EffectiveAt:    testSubtreeRTEffective,
			Reason:         testSubtreeRTReason,
		},
	}

	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("transition preimage: %v", err)
	}
	oldSig := ed25519.Sign(oldPriv, preimage)
	envelope.OldSignature = "ed25519:" + hex.EncodeToString(oldSig)
	newSig := ed25519.Sign(newPriv, preimage)
	envelope.NewSignature = "ed25519:" + hex.EncodeToString(newSig)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "root_transition.json")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	return fp, hex.EncodeToString(oldPub), hex.EncodeToString(newPub), oldFP
}

// --- Roster Show tests ---

func TestRosterShow_HappyPath(t *testing.T) {
	t.Parallel()
	rosterPath, fingerprint := buildRosterFixture(t)

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "roster", "show",
		"--path", rosterPath,
		"--root-fingerprint", fingerprint,
	})

	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&strings.Builder{})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "roster_signed_by") {
		t.Errorf("output should contain roster_signed_by, got:\n%s", output)
	}
	if !strings.Contains(output, testSubtreeRosterKeyID) {
		t.Errorf("output should contain key ID %q, got:\n%s", testSubtreeRosterKeyID, output)
	}
}

func TestRosterShow_RejectMissingFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no path",
			args: []string{"signing", "roster", "show", "--root-fingerprint", "sha256:abc"},
		},
		{
			name: "no root-fingerprint",
			args: []string{"signing", "roster", "show", "--path", "/tmp/nonexistent.json"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := testRoot()
			root.AddCommand(SigningSubtreeCmd())
			root.SetArgs(tc.args)
			root.SetOut(&strings.Builder{})
			root.SetErr(&strings.Builder{})

			if err := root.Execute(); err == nil {
				t.Fatal("expected error for missing required flag")
			}
		})
	}
}

func TestRosterShow_FileMissing(t *testing.T) {
	t.Parallel()

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "roster", "show",
		"--path", "/tmp/nonexistent-roster-file-2026.json",
		"--root-fingerprint", "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})

	var stderr strings.Builder
	root.SetOut(&strings.Builder{})
	root.SetErr(&stderr)

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for missing file")
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "load failed") {
		t.Errorf("stderr should contain 'load failed', got:\n%s", errOutput)
	}
}

// --- Roster Verify tests ---

func TestRosterVerify_HappyPath(t *testing.T) {
	t.Parallel()
	rosterPath, fingerprint := buildRosterFixture(t)

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "roster", "verify",
		"--path", rosterPath,
		"--root-fingerprint", fingerprint,
	})

	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&strings.Builder{})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "roster verified") {
		t.Errorf("output should contain 'roster verified', got:\n%s", output)
	}
	if !strings.Contains(output, "2 keys") {
		t.Errorf("output should contain '2 keys', got:\n%s", output)
	}
	if !strings.Contains(output, testSubtreeRosterKeyID) {
		t.Errorf("output should contain root_signed_by key ID, got:\n%s", output)
	}
}

func TestRosterVerify_FingerprintMismatch(t *testing.T) {
	t.Parallel()
	rosterPath, _ := buildRosterFixture(t)

	// Use a wrong fingerprint.
	wrongFP := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "roster", "verify",
		"--path", rosterPath,
		"--root-fingerprint", wrongFP,
	})

	var stderr strings.Builder
	root.SetOut(&strings.Builder{})
	root.SetErr(&stderr)

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for fingerprint mismatch")
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "verify failed") {
		t.Errorf("stderr should contain 'verify failed', got:\n%s", errOutput)
	}
}

// --- Recovery Verify tests ---

func TestRecoveryVerify_HappyPath(t *testing.T) {
	t.Parallel()
	// Use real time.Now() since the CLI calls time.Now() internally.
	now := time.Now()
	path, pubHex, fingerprint := buildRecoveryFixture(t, now)

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "recovery", "verify",
		"--path", path,
		"--recovery-pubkey", pubHex,
		"--pinned-fingerprint", fingerprint,
	})

	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&strings.Builder{})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "recovery authorization verified") {
		t.Errorf("output should contain success message, got:\n%s", output)
	}
	if !strings.Contains(output, testSubtreeRecoveryReason) {
		t.Errorf("output should contain reason, got:\n%s", output)
	}
	if !strings.Contains(output, testSubtreeRecoveryOperator) {
		t.Errorf("output should contain operator, got:\n%s", output)
	}
}

func TestRecoveryVerify_RejectExpired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	path, pubHex, fingerprint := buildExpiredRecoveryFixture(t, now)

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "recovery", "verify",
		"--path", path,
		"--recovery-pubkey", pubHex,
		"--pinned-fingerprint", fingerprint,
	})

	var stderr strings.Builder
	root.SetOut(&strings.Builder{})
	root.SetErr(&stderr)

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for expired recovery authorization")
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "verify failed") {
		t.Errorf("stderr should contain 'verify failed', got:\n%s", errOutput)
	}
}

func TestRecoveryVerify_RejectMalformedPubkey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		pubkey string
	}{
		{name: "too short", pubkey: "abcdef"},
		{name: "non-hex chars", pubkey: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{name: "too long", pubkey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789aa"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := testRoot()
			root.AddCommand(SigningSubtreeCmd())
			root.SetArgs([]string{
				"signing", "recovery", "verify",
				"--path", "/tmp/dummy.json",
				"--recovery-pubkey", tc.pubkey,
				"--pinned-fingerprint", "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			})

			var stderr strings.Builder
			root.SetOut(&strings.Builder{})
			root.SetErr(&stderr)

			if err := root.Execute(); err == nil {
				t.Fatal("expected error for malformed pubkey")
			}

			errOutput := stderr.String()
			if !strings.Contains(errOutput, "verify failed") {
				t.Errorf("stderr should contain 'verify failed', got:\n%s", errOutput)
			}
		})
	}
}

// --- Transition Verify tests ---

func TestTransitionVerify_HappyPath_WithPin(t *testing.T) {
	t.Parallel()
	path, oldPubHex, newPubHex, oldFP := buildTransitionFixture(t)

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "transition", "verify",
		"--path", path,
		"--old-pubkey", oldPubHex,
		"--new-pubkey", newPubHex,
		"--pinned", oldFP,
	})

	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&strings.Builder{})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "transition verified") {
		t.Errorf("output should contain 'transition verified', got:\n%s", output)
	}
	if !strings.Contains(output, string(domsigning.RootKindRoster)) {
		t.Errorf("output should contain root kind, got:\n%s", output)
	}
	if !strings.Contains(output, testSubtreeRTEffective) {
		t.Errorf("output should contain effective_at, got:\n%s", output)
	}
}

func TestTransitionVerify_HappyPath_EmptyPin(t *testing.T) {
	t.Parallel()
	path, oldPubHex, newPubHex, _ := buildTransitionFixture(t)

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "transition", "verify",
		"--path", path,
		"--old-pubkey", oldPubHex,
		"--new-pubkey", newPubHex,
	})

	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&strings.Builder{})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "transition verified") {
		t.Errorf("output should contain 'transition verified', got:\n%s", output)
	}
}

func TestTransitionVerify_RejectFingerprintMismatch(t *testing.T) {
	t.Parallel()
	path, oldPubHex, newPubHex, _ := buildTransitionFixture(t)

	// Use a wrong pinned fingerprint.
	wrongFP := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{
		"signing", "transition", "verify",
		"--path", path,
		"--old-pubkey", oldPubHex,
		"--new-pubkey", newPubHex,
		"--pinned", wrongFP,
	})

	var stderr strings.Builder
	root.SetOut(&strings.Builder{})
	root.SetErr(&stderr)

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for fingerprint mismatch")
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "verify failed") {
		t.Errorf("stderr should contain 'verify failed', got:\n%s", errOutput)
	}
}

func TestTransitionVerify_RejectMalformedPubkey(t *testing.T) {
	t.Parallel()

	// Valid 64-char hex key for the side that's not being tested.
	validHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

	tests := []struct {
		name      string
		oldPubkey string
		newPubkey string
		errText   string
	}{
		{
			name:      "old too short",
			oldPubkey: "abcdef",
			newPubkey: validHex,
			errText:   "invalid old-pubkey",
		},
		{
			name:      "new too short",
			oldPubkey: validHex,
			newPubkey: "abcdef",
			errText:   "invalid new-pubkey",
		},
		{
			name:      "old non-hex",
			oldPubkey: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			newPubkey: validHex,
			errText:   "invalid old-pubkey",
		},
		{
			name:      "new non-hex",
			oldPubkey: validHex,
			newPubkey: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			errText:   "invalid new-pubkey",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := testRoot()
			root.AddCommand(SigningSubtreeCmd())
			root.SetArgs([]string{
				"signing", "transition", "verify",
				"--path", "/tmp/dummy.json",
				"--old-pubkey", tc.oldPubkey,
				"--new-pubkey", tc.newPubkey,
			})

			var stderr strings.Builder
			root.SetOut(&strings.Builder{})
			root.SetErr(&stderr)

			if err := root.Execute(); err == nil {
				t.Fatal("expected error for malformed pubkey")
			}

			errOutput := stderr.String()
			if !strings.Contains(errOutput, tc.errText) {
				t.Errorf("stderr should contain %q, got:\n%s", tc.errText, errOutput)
			}
		})
	}
}

// --- decodeHexPubkey unit tests ---

func TestDecodeHexPubkey_Valid(t *testing.T) {
	t.Parallel()
	b, err := decodeHexPubkey(testSubtreeRosterPubHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != ed25519.PublicKeySize {
		t.Errorf("decoded length = %d, want %d", len(b), ed25519.PublicKeySize)
	}
}

func TestDecodeHexPubkey_WrongLength(t *testing.T) {
	t.Parallel()
	_, err := decodeHexPubkey("abcdef")
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
	if !strings.Contains(err.Error(), "64 characters") {
		t.Errorf("error should mention 64 characters, got: %v", err)
	}
}

func TestDecodeHexPubkey_InvalidHex(t *testing.T) {
	t.Parallel()
	_, err := decodeHexPubkey("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	if !strings.Contains(err.Error(), "invalid hex") {
		t.Errorf("error should mention invalid hex, got: %v", err)
	}
}

// --- Pubkey-file resolution tests ---

// TestReadPubkeyFile_HappyPath confirms a file containing a valid 64-char
// hex Ed25519 key (with or without trailing whitespace) decodes to 32 raw
// bytes.
func TestReadPubkeyFile_HappyPath(t *testing.T) {
	t.Parallel()

	const validHex = "1111111111111111111111111111111111111111111111111111111111111111"
	cases := []struct {
		name    string
		content string
	}{
		{"no_trailing_newline", validHex},
		{"trailing_newline", validHex + "\n"},
		{"crlf_trailing", validHex + "\r\n"},
		{"leading_whitespace", "  " + validHex + "\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := filepath.Join(dir, "pub.hex")
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := readPubkeyFile(p)
			if err != nil {
				t.Fatalf("readPubkeyFile: %v", err)
			}
			if len(got) != 32 {
				t.Errorf("got %d bytes, want 32", len(got))
			}
		})
	}
}

// TestReadPubkeyFile_RejectsOversize confirms the size cap fires on any
// pathologically large input. A 5KB file should not be a public key.
func TestReadPubkeyFile_RejectsOversize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "pub.hex")
	if err := os.WriteFile(p, make([]byte, pubkeyFileMaxSize+1), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := readPubkeyFile(p)
	if err == nil {
		t.Fatal("expected size-cap rejection")
	}
	if !errors.Is(err, errPubkeyFileTooLarge) {
		t.Errorf("got %v, want errPubkeyFileTooLarge", err)
	}
}

// TestResolvePubkey_FileWinsWhenInlineEmpty proves the file flag is consulted
// and decoded when the inline flag is empty.
func TestResolvePubkey_FileWinsWhenInlineEmpty(t *testing.T) {
	t.Parallel()
	const validHex = "2222222222222222222222222222222222222222222222222222222222222222"
	dir := t.TempDir()
	p := filepath.Join(dir, "pub.hex")
	if err := os.WriteFile(p, []byte(validHex), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := resolvePubkey("recovery-pubkey", "", p)
	if err != nil {
		t.Fatalf("resolvePubkey: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("got %d bytes, want 32", len(got))
	}
}

// TestResolvePubkey_BothFlagsSet covers the defense-in-depth rejection of
// passing both inline + file. cobra's MarkFlagsMutuallyExclusive should catch
// this at parse time, but the helper is also called from tests that bypass
// cobra.
func TestResolvePubkey_BothFlagsSet(t *testing.T) {
	t.Parallel()
	const validHex = "3333333333333333333333333333333333333333333333333333333333333333"
	dir := t.TempDir()
	p := filepath.Join(dir, "pub.hex")
	if err := os.WriteFile(p, []byte(validHex), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := resolvePubkey("recovery-pubkey", validHex, p)
	if err == nil {
		t.Fatal("expected rejection when both flags are set")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("error should mention not both, got: %v", err)
	}
}

// TestResolvePubkey_NeitherFlagSet covers the same defense-in-depth case from
// the empty side. Cobra's MarkFlagsOneRequired should catch this at parse
// time.
func TestResolvePubkey_NeitherFlagSet(t *testing.T) {
	t.Parallel()
	_, err := resolvePubkey("recovery-pubkey", "", "")
	if err == nil {
		t.Fatal("expected rejection when neither flag is set")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error should mention required, got: %v", err)
	}
}

// --- sanitizeForTerminal tests ---

// TestSanitizeForTerminal_QuotesControlCharacters proves attacker-controlled
// fields with newlines, escape sequences, and ANSI control bytes render as a
// quoted Go literal rather than landing raw on stdout.
func TestSanitizeForTerminal_QuotesControlCharacters(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		in           string
		mustNotEqual string
	}{
		{"newline_injection", "line1\nFAKE: verified", "line1\nFAKE: verified"},
		{"ansi_escape", "\x1b[31mred", "\x1b[31mred"},
		{"carriage_return", "before\rafter", "before\rafter"},
		{"null_byte", "before\x00after", "before\x00after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeForTerminal(tc.in)
			if got == tc.mustNotEqual {
				t.Errorf("sanitizeForTerminal returned raw input %q", got)
			}
			if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
				t.Errorf("expected quoted form, got %q", got)
			}
			if strings.ContainsAny(got, "\n\r\x00\x1b") {
				t.Errorf("sanitized output still contains control chars: %q", got)
			}
		})
	}
}

// --- Help output test ---

func TestSigningSubtree_Help(t *testing.T) {
	t.Parallel()

	root := testRoot()
	root.AddCommand(SigningSubtreeCmd())
	root.SetArgs([]string{"signing", "--help"})

	var stdout strings.Builder
	root.SetOut(&stdout)

	_ = root.Execute()
	output := stdout.String()

	for _, sub := range []string{"roster", "recovery", "transition"} {
		if !strings.Contains(output, sub) {
			t.Errorf("signing help should list %q subcommand", sub)
		}
	}
}
