// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- Golden test infrastructure ---

// goldenUpdateMode returns true when golden fixture files should be
// (re)written to disk rather than compared. Set via UPDATE_GOLDEN=1.
func goldenUpdateMode() bool {
	return os.Getenv("UPDATE_GOLDEN") == "1"
}

// goldenWriteOrAssert either writes body to path (UPDATE_GOLDEN=1) or
// reads the file at path and asserts byte-identical content.
func goldenWriteOrAssert(t *testing.T, path string, body []byte) {
	t.Helper()
	if goldenUpdateMode() {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if string(got) != string(body) {
		t.Errorf("%s drift\n--- expected\n%s\n--- got\n%s", path, got, body)
	}
}

// --- Deterministic keypairs ---

// goldenRecoveryRootSeedHex is a deterministic Ed25519 seed for the
// recovery-root keypair used in golden fixtures. Split per G101 lint rule.
const goldenRecoveryRootSeedHex = "" +
	"4ccd089b" + "28ff96da" + "9db6c346" + "ec114e0f" +
	"5b8a319f" + "35aba624" + "da8cf6ed" + "4fb8a6fb"

// goldenNewRootSeedHex is a deterministic Ed25519 seed for the new-root
// keypair in root-transition fixtures. One byte flipped vs the recovery
// seed to produce an independent key. Split per G101 lint rule.
const goldenNewRootSeedHex = "" +
	"4ccd089b" + "28ff96da" + "9db6c346" + "ec114e0f" +
	"5b8a319f" + "35aba624" + "da8cf6ed" + "4fb8a6fc"

// goldenOldRootSeedHex is a deterministic Ed25519 seed for the old-root
// keypair in root-transition fixtures. Uses the RFC 8032 section 7.1 test 1
// vector seed (same as the contract package golden tests). Split per G101.
const goldenOldRootSeedHex = "" +
	"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
	"4449c569" + "7b326919" + "703bac03" + "1cae7f60"

// goldenKeyFromSeed derives an Ed25519 private key from a hex-encoded seed.
func goldenKeyFromSeed(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length: got %d want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// goldenRecoveryRootKey returns the deterministic recovery-root keypair.
func goldenRecoveryRootKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return goldenKeyFromSeed(t, goldenRecoveryRootSeedHex)
}

// goldenNewRootKey returns the deterministic new-root keypair for
// root-transition fixtures.
func goldenNewRootKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return goldenKeyFromSeed(t, goldenNewRootSeedHex)
}

// goldenOldRootKey returns the deterministic old-root keypair for
// root-transition fixtures (RFC 8032 test 1 seed).
func goldenOldRootKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return goldenKeyFromSeed(t, goldenOldRootSeedHex)
}

// signEd25519Hex signs preimage with key and returns "ed25519:" + hex(sig).
func goldenSignEd25519Hex(key ed25519.PrivateKey, preimage []byte) string {
	sig := ed25519.Sign(key, preimage)
	return "ed25519:" + hex.EncodeToString(sig)
}

// goldenFingerprint computes the canonical fingerprint for an Ed25519 public key.
func goldenFingerprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	digest := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// --- Golden fixture constants ---

const (
	goldenRecoveryIssuedAt  = "2026-04-26T13:00:00Z"
	goldenRecoveryExpiresAt = "2026-04-26T13:30:00Z"
	goldenRecoveryReason    = "roster root key compromised"
	goldenRecoveryOperator  = "ops@example.com"
	// Deterministic stand-in for a real roster body hash, fixed at the
	// digest of a constant string. Conformance fixtures need a non-zero
	// value so the target-roster-hash binding gate exercises a real
	// comparison instead of trivially matching the all-zero default.
	// Computed from sha256("pipelock-test-recovery-target-roster-body-fixture").
	goldenRecoveryTargetHash = "sha256:d0936185ee07c30a681e5beb49ef01899744df04bef122596467d9aa8ef24f7d"

	goldenRTReason      = "scheduled annual key rotation"
	goldenRTEffectiveAt = "2026-04-26T15:00:00Z"

	goldenDirRel = "testdata/golden"
)

// --- Per-artifact golden round-trip tests ---

func TestGolden_RecoveryAuthorization(t *testing.T) {
	t.Parallel()
	priv := goldenRecoveryRootKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	body := RecoveryAuthorizationBody{
		SchemaVersion:    1,
		Reason:           goldenRecoveryReason,
		ExpiresAt:        goldenRecoveryExpiresAt,
		TargetRosterHash: goldenRecoveryTargetHash,
		OperatorIdentity: goldenRecoveryOperator,
		IssuedAt:         goldenRecoveryIssuedAt,
	}

	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}

	envelope := RecoveryAuthorizationEnvelope{
		Body:      body,
		Signature: goldenSignEd25519Hex(priv, preimage),
	}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	data = append(data, '\n')

	outPath := filepath.Join(goldenDirRel, "valid_recovery_authorization.json")
	goldenWriteOrAssert(t, outPath, data)

	// Read-back verification: decode, recompute preimage, verify signature.
	raw, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got RecoveryAuthorizationEnvelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	gotPre, err := got.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("verify preimage: %v", err)
	}
	if string(gotPre) != string(preimage) {
		t.Error("preimage drift on read-back")
	}

	sigBytes, sigErr := parseSignature(got.Signature)
	if sigErr != nil {
		t.Fatalf("parse signature: %v", sigErr)
	}
	if !ed25519.Verify(pub, gotPre, sigBytes) {
		t.Error("signature verify failed on golden recovery_authorization")
	}
}

func TestGolden_RootTransition(t *testing.T) {
	t.Parallel()
	oldPriv := goldenOldRootKey(t)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	newPriv := goldenNewRootKey(t)
	newPub := newPriv.Public().(ed25519.PublicKey)

	oldFP := goldenFingerprint(t, oldPub)
	newFP := goldenFingerprint(t, newPub)

	body := RootTransitionBody{
		SchemaVersion:  1,
		RootKind:       RootKindRoster,
		OldFingerprint: oldFP,
		NewFingerprint: newFP,
		EffectiveAt:    goldenRTEffectiveAt,
		Reason:         goldenRTReason,
	}

	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}

	envelope := RootTransitionEnvelope{
		Body:         body,
		OldSignature: goldenSignEd25519Hex(oldPriv, preimage),
		NewSignature: goldenSignEd25519Hex(newPriv, preimage),
	}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	data = append(data, '\n')

	outPath := filepath.Join(goldenDirRel, "valid_root_transition.json")
	goldenWriteOrAssert(t, outPath, data)

	// Read-back verification: decode, recompute preimage, verify both sigs.
	raw, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got RootTransitionEnvelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	gotPre, err := got.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("verify preimage: %v", err)
	}
	if string(gotPre) != string(preimage) {
		t.Error("preimage drift on read-back")
	}

	oldSigBytes, err := parseSignature(got.OldSignature)
	if err != nil {
		t.Fatalf("parse old_signature: %v", err)
	}
	if !ed25519.Verify(oldPub, gotPre, oldSigBytes) {
		t.Error("old_signature verify failed on golden root_transition")
	}

	newSigBytes, err := parseSignature(got.NewSignature)
	if err != nil {
		t.Fatalf("parse new_signature: %v", err)
	}
	if !ed25519.Verify(newPub, gotPre, newSigBytes) {
		t.Error("new_signature verify failed on golden root_transition")
	}
}

func TestGolden_AllFixturesParseAndValidate(t *testing.T) {
	if goldenUpdateMode() {
		t.Skip("skipped in UPDATE_GOLDEN mode; individual tests write and verify")
	}

	// Recovery authorization: load via the public API with deterministic
	// time inside the validity window.
	t.Run("recovery_authorization", func(t *testing.T) {
		priv := goldenRecoveryRootKey(t)
		pub := priv.Public().(ed25519.PublicKey)
		fp := goldenFingerprint(t, pub)

		// now must be after issued_at and before expires_at, with
		// expires_at - now <= 1 hour.
		now, err := time.Parse(time.RFC3339, "2026-04-26T13:10:00Z")
		if err != nil {
			t.Fatalf("parse now: %v", err)
		}

		path := filepath.Join(goldenDirRel, "valid_recovery_authorization.json")
		loaded, loadErr := LoadRecoveryAuthorization(path, pub, fp, "", now)
		if loadErr != nil {
			t.Fatalf("LoadRecoveryAuthorization: %v", loadErr)
		}
		if loaded.Body.Reason != goldenRecoveryReason {
			t.Errorf("reason = %q, want %q", loaded.Body.Reason, goldenRecoveryReason)
		}
	})

	// Root transition: load via the public API.
	t.Run("root_transition", func(t *testing.T) {
		oldPriv := goldenOldRootKey(t)
		oldPub := oldPriv.Public().(ed25519.PublicKey)
		newPriv := goldenNewRootKey(t)
		newPub := newPriv.Public().(ed25519.PublicKey)

		oldFP := goldenFingerprint(t, oldPub)

		path := filepath.Join(goldenDirRel, "valid_root_transition.json")
		loaded, loadErr := LoadRootTransition(path, oldPub, newPub, oldFP)
		if loadErr != nil {
			t.Fatalf("LoadRootTransition: %v", loadErr)
		}
		if loaded.Body.Reason != goldenRTReason {
			t.Errorf("reason = %q, want %q", loaded.Body.Reason, goldenRTReason)
		}
	})

	// Existence check for both fixtures.
	expected := []string{
		"valid_recovery_authorization.json",
		"valid_root_transition.json",
	}
	for _, name := range expected {
		path := filepath.Join(goldenDirRel, name)
		if _, err := os.Stat(filepath.Clean(path)); err != nil {
			t.Errorf("missing golden fixture %s: %v", name, err)
		}
	}
}
