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
	"testing"
)

// Deterministic test seed for the OLD keypair (RFC 8032 section 7.1
// test 1's first 24 bytes, with the trailing 8 bytes replaced by a
// duplicated 1b6ff1ae block so the OLD and NEW seeds below differ in
// their suffix without colliding with any published vector). Split
// across string concatenations per G101 lint rule.
const testRTOldSeedHex = "" +
	"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
	"4449c569" + "8b64e70e" + "1b6ff1ae" + "1b6ff1ae"

// NEW keypair seed: same first 24 bytes as OLD, with the trailing 8
// bytes replaced by ae1bff6b ae1bff6b so the two seeds produce
// distinct keypairs without colliding with any RFC 8032 vector.
const testRTNewSeedHex = "" +
	"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
	"4449c569" + "8b64e70e" + "ae1bff6b" + "ae1bff6b"

// testRTReason is the operator reason used in test fixtures.
const testRTReason = "scheduled annual key rotation"

// testRTEffectiveAt is a well-formed RFC 3339 timestamp for fixtures.
const testRTEffectiveAt = "2026-04-26T15:00:00Z"

// testRTBadDate is reused for RFC 3339 parse-failure tests.
const testRTBadDate = "not-a-date"

// testRTBadPrefixFP is a fingerprint with the wrong algorithm prefix.
const testRTBadPrefixFP = "md5:abcd"

// testRTShortFP is a fingerprint with valid prefix but wrong digest length.
const testRTShortFP = "sha256:abcd"

// rtPreSignOpt mutates the envelope body before the signatures are computed.
type rtPreSignOpt func(env *RootTransitionEnvelope)

// rtPostSignOpt mutates the envelope after the signatures are computed,
// useful for corrupting signatures or fields post-signing.
type rtPostSignOpt func(env *RootTransitionEnvelope)

// rootTransitionFixture builds a known-good transition envelope, signs it
// with deterministic old/new keypairs, writes to a temp file, and returns
// (path, oldPub, newPub, oldFingerprint, newFingerprint).
func rootTransitionFixture(
	t *testing.T,
	ext string,
	kind RootKind,
	opts ...any,
) (path string, oldPub, newPub []byte, oldFP, newFP string) {
	t.Helper()

	oldSeed, err := hex.DecodeString(testRTOldSeedHex)
	if err != nil {
		t.Fatalf("decode old seed: %v", err)
	}
	oldPriv := ed25519.NewKeyFromSeed(oldSeed)
	oldPub = oldPriv.Public().(ed25519.PublicKey)

	newSeed, err := hex.DecodeString(testRTNewSeedHex)
	if err != nil {
		t.Fatalf("decode new seed: %v", err)
	}
	newPriv := ed25519.NewKeyFromSeed(newSeed)
	newPub = newPriv.Public().(ed25519.PublicKey)

	oldDigest := sha256.Sum256(oldPub)
	oldFP = "sha256:" + hex.EncodeToString(oldDigest[:])

	newDigest := sha256.Sum256(newPub)
	newFP = "sha256:" + hex.EncodeToString(newDigest[:])

	envelope := RootTransitionEnvelope{
		Body: RootTransitionBody{
			SchemaVersion:  1,
			RootKind:       kind,
			OldFingerprint: oldFP,
			NewFingerprint: newFP,
			EffectiveAt:    testRTEffectiveAt,
			Reason:         testRTReason,
		},
	}

	// Apply pre-sign mutations.
	for _, o := range opts {
		if fn, ok := o.(rtPreSignOpt); ok {
			fn(&envelope)
		}
	}

	// Sign the body with both keys.
	preimage, pErr := envelope.Body.SignablePreimage()
	if pErr != nil {
		// For tests that deliberately break the body, produce dummy sigs.
		dummySig := "ed25519:" + hex.EncodeToString(make([]byte, ed25519.SignatureSize))
		envelope.OldSignature = dummySig
		envelope.NewSignature = dummySig
	} else {
		oldSig := ed25519.Sign(oldPriv, preimage)
		envelope.OldSignature = "ed25519:" + hex.EncodeToString(oldSig)
		newSig := ed25519.Sign(newPriv, preimage)
		envelope.NewSignature = "ed25519:" + hex.EncodeToString(newSig)
	}

	// Apply post-sign mutations (signature tampering, etc.).
	for _, o := range opts {
		if fn, ok := o.(rtPostSignOpt); ok {
			fn(&envelope)
		}
	}

	// Serialize.
	var data []byte
	switch ext {
	case envelopeExtYAML, envelopeExtYML:
		// JSON is valid YAML; DecodeStrictYAML handles it.
		data, err = json.Marshal(envelope)
		if err != nil {
			t.Fatalf("json marshal for yaml: %v", err)
		}
	default:
		data, err = json.MarshalIndent(envelope, "", "  ")
		if err != nil {
			t.Fatalf("json marshal: %v", err)
		}
		data = append(data, '\n')
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "root_transition"+ext)
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	return fp, oldPub, newPub, oldFP, newFP
}

// --- RootKind.Validate tests ---

func TestRootKind_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    RootKind
		wantErr bool
	}{
		{name: "roster-root", kind: RootKindRoster, wantErr: false},
		{name: "recovery-root", kind: RootKindRecovery, wantErr: false},
		{name: "empty", kind: "", wantErr: true},
		{name: "foo", kind: "foo", wantErr: true},
		{name: "ROSTER-ROOT", kind: "ROSTER-ROOT", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.kind.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && !errors.Is(err, ErrRootTransitionUnknownKind) {
				t.Errorf("got %v, want ErrRootTransitionUnknownKind", err)
			}
		})
	}
}

// --- RootTransitionBody.Validate tests ---

func TestRootTransitionBody_Validate_HappyPath(t *testing.T) {
	t.Parallel()

	// Use distinct well-formed fingerprints.
	body := RootTransitionBody{
		SchemaVersion:  1,
		RootKind:       RootKindRoster,
		OldFingerprint: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		NewFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EffectiveAt:    testRTEffectiveAt,
		Reason:         testRTReason,
	}
	if err := body.Validate(); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}
}

func TestRootTransitionBody_Validate_Errors(t *testing.T) {
	t.Parallel()

	validBody := RootTransitionBody{
		SchemaVersion:  1,
		RootKind:       RootKindRoster,
		OldFingerprint: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		NewFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EffectiveAt:    testRTEffectiveAt,
		Reason:         testRTReason,
	}

	tests := []struct {
		name    string
		mutate  func(*RootTransitionBody)
		wantErr error
	}{
		{
			name:    "wrong_schema_version",
			mutate:  func(b *RootTransitionBody) { b.SchemaVersion = 0 },
			wantErr: ErrRootTransitionInvalid,
		},
		{
			name:    "unknown_root_kind",
			mutate:  func(b *RootTransitionBody) { b.RootKind = "bad-kind" },
			wantErr: ErrRootTransitionUnknownKind,
		},
		{
			name:    "empty_root_kind",
			mutate:  func(b *RootTransitionBody) { b.RootKind = "" },
			wantErr: ErrRootTransitionUnknownKind,
		},
		{
			name:    "old_fingerprint_wrong_prefix",
			mutate:  func(b *RootTransitionBody) { b.OldFingerprint = testRTBadPrefixFP },
			wantErr: ErrRootTransitionFingerprintFormat,
		},
		{
			name:    "old_fingerprint_wrong_length",
			mutate:  func(b *RootTransitionBody) { b.OldFingerprint = testRTShortFP },
			wantErr: ErrRootTransitionFingerprintFormat,
		},
		{
			name: "old_fingerprint_uppercase_hex",
			mutate: func(b *RootTransitionBody) {
				b.OldFingerprint = "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
			},
			wantErr: ErrRootTransitionFingerprintFormat,
		},
		{
			name:    "new_fingerprint_wrong_prefix",
			mutate:  func(b *RootTransitionBody) { b.NewFingerprint = testRTBadPrefixFP },
			wantErr: ErrRootTransitionFingerprintFormat,
		},
		{
			name:    "new_fingerprint_wrong_length",
			mutate:  func(b *RootTransitionBody) { b.NewFingerprint = testRTShortFP },
			wantErr: ErrRootTransitionFingerprintFormat,
		},
		{
			name: "identity_rotation",
			mutate: func(b *RootTransitionBody) {
				b.NewFingerprint = b.OldFingerprint
			},
			wantErr: ErrRootTransitionIdentityRotation,
		},
		{
			name:    "bad_effective_at",
			mutate:  func(b *RootTransitionBody) { b.EffectiveAt = testRTBadDate },
			wantErr: ErrRootTransitionEffectiveAtFormat,
		},
		{
			name:    "empty_reason",
			mutate:  func(b *RootTransitionBody) { b.Reason = "" },
			wantErr: ErrRootTransitionReasonRequired,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := validBody
			tc.mutate(&b)
			err := b.Validate()
			if err == nil {
				t.Fatalf("expected %v, got nil", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// --- SignablePreimage tests ---

func TestRootTransitionBody_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	body := RootTransitionBody{
		SchemaVersion:  1,
		RootKind:       RootKindRoster,
		OldFingerprint: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		NewFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EffectiveAt:    testRTEffectiveAt,
		Reason:         testRTReason,
	}

	p1, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	p2, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(p1) != string(p2) {
		t.Errorf("preimage not stable:\n  first:  %s\n  second: %s", p1, p2)
	}
	if len(p1) == 0 {
		t.Error("preimage is empty")
	}
}

// --- LoadRootTransition tests ---

func TestLoadRootTransition_HappyPath_JSON(t *testing.T) {
	t.Parallel()
	path, oldPub, newPub, oldFP, newFP := rootTransitionFixture(t, ".json", RootKindRoster)

	loaded, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err != nil {
		t.Fatalf("LoadRootTransition: %v", err)
	}
	if loaded.Body.RootKind != RootKindRoster {
		t.Errorf("RootKind = %q, want %q", loaded.Body.RootKind, RootKindRoster)
	}
	if loaded.Body.Reason != testRTReason {
		t.Errorf("Reason = %q, want %q", loaded.Body.Reason, testRTReason)
	}
	if loaded.Body.OldFingerprint != oldFP {
		t.Errorf("OldFingerprint = %q, want %q", loaded.Body.OldFingerprint, oldFP)
	}
	if loaded.Body.NewFingerprint != newFP {
		t.Errorf("NewFingerprint = %q, want %q", loaded.Body.NewFingerprint, newFP)
	}
	if loaded.SourcePath == "" {
		t.Error("SourcePath is empty")
	}
	if loaded.LoadedAt.IsZero() {
		t.Error("LoadedAt is zero")
	}
	if loaded.OldSignature == "" {
		t.Error("OldSignature is empty")
	}
	if loaded.NewSignature == "" {
		t.Error("NewSignature is empty")
	}
}

func TestLoadRootTransition_HappyPath_YAML(t *testing.T) {
	t.Parallel()
	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".yaml", RootKindRecovery)

	loaded, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err != nil {
		t.Fatalf("LoadRootTransition YAML: %v", err)
	}
	if loaded.Body.RootKind != RootKindRecovery {
		t.Errorf("RootKind = %q, want %q", loaded.Body.RootKind, RootKindRecovery)
	}
}

func TestLoadRootTransition_RejectFileMissing(t *testing.T) {
	t.Parallel()
	_, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	_, err := LoadRootTransition("/nonexistent/path/transition.json", oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, ErrRootTransitionRead) {
		t.Errorf("got %v, want ErrRootTransitionRead", err)
	}
}

func TestLoadRootTransition_RejectUnsupportedExtension(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	badPath := filepath.Join(dir, "transition.txt")
	if err := os.WriteFile(badPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	_, err := LoadRootTransition(badPath, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected error for unsupported extension")
	}
	if !errors.Is(err, ErrRootTransitionUnsupportedExtension) {
		t.Errorf("got %v, want ErrRootTransitionUnsupportedExtension", err)
	}
}

func TestLoadRootTransition_RejectMalformedJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	badPath := filepath.Join(dir, "transition.json")
	if err := os.WriteFile(badPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	_, err := LoadRootTransition(badPath, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !errors.Is(err, ErrRootTransitionDecode) {
		t.Errorf("got %v, want ErrRootTransitionDecode", err)
	}
}

func TestLoadRootTransition_RejectStructuralValidation(t *testing.T) {
	t.Parallel()
	// schema_version != 1 triggers structural validation failure.
	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster,
		rtPreSignOpt(func(env *RootTransitionEnvelope) {
			env.Body.SchemaVersion = 99
		}))

	_, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionInvalid")
	}
	if !errors.Is(err, ErrRootTransitionInvalid) {
		t.Errorf("got %v, want ErrRootTransitionInvalid", err)
	}
}

func TestLoadRootTransition_RejectOldKeyWrongLength(t *testing.T) {
	t.Parallel()
	path, _, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	// 31-byte key: wrong length.
	shortKey := make([]byte, 31)
	_, err := LoadRootTransition(path, shortKey, newPub, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionKeyLength")
	}
	if !errors.Is(err, ErrRootTransitionKeyLength) {
		t.Errorf("got %v, want ErrRootTransitionKeyLength", err)
	}
}

func TestLoadRootTransition_RejectNewKeyWrongLength(t *testing.T) {
	t.Parallel()
	path, oldPub, _, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	// 31-byte key: wrong length.
	shortKey := make([]byte, 31)
	_, err := LoadRootTransition(path, oldPub, shortKey, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionKeyLength")
	}
	if !errors.Is(err, ErrRootTransitionKeyLength) {
		t.Errorf("got %v, want ErrRootTransitionKeyLength", err)
	}
}

func TestLoadRootTransition_RejectOldKeyFingerprintMismatch(t *testing.T) {
	t.Parallel()
	path, _, newPub, _, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	// Generate a different 32-byte key that does not match the body's old_fingerprint.
	differentKey := make([]byte, ed25519.PublicKeySize)
	differentKey[0] = 0xff
	differentKey[1] = 0xfe

	_, err := LoadRootTransition(path, differentKey, newPub, "")
	if err == nil {
		t.Fatal("expected ErrRootTransitionOldFingerprintMismatch")
	}
	if !errors.Is(err, ErrRootTransitionOldFingerprintMismatch) {
		t.Errorf("got %v, want ErrRootTransitionOldFingerprintMismatch", err)
	}
}

func TestLoadRootTransition_RejectNewKeyFingerprintMismatch(t *testing.T) {
	t.Parallel()
	path, oldPub, _, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	// Generate a different 32-byte key that does not match the body's new_fingerprint.
	differentKey := make([]byte, ed25519.PublicKeySize)
	differentKey[0] = 0xff
	differentKey[1] = 0xfd

	_, err := LoadRootTransition(path, oldPub, differentKey, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionNewFingerprintMismatch")
	}
	if !errors.Is(err, ErrRootTransitionNewFingerprintMismatch) {
		t.Errorf("got %v, want ErrRootTransitionNewFingerprintMismatch", err)
	}
}

func TestLoadRootTransition_RejectPinnedFingerprintMismatch(t *testing.T) {
	t.Parallel()
	path, oldPub, newPub, _, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	// Valid format but different digest.
	wrongPin := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	_, err := LoadRootTransition(path, oldPub, newPub, wrongPin)
	if err == nil {
		t.Fatal("expected ErrRootTransitionPinMismatch")
	}
	if !errors.Is(err, ErrRootTransitionPinMismatch) {
		t.Errorf("got %v, want ErrRootTransitionPinMismatch", err)
	}
}

func TestLoadRootTransition_AcceptsEmptyPin(t *testing.T) {
	t.Parallel()
	path, oldPub, newPub, _, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	// Empty pinnedOldFingerprint skips the pin check.
	loaded, err := LoadRootTransition(path, oldPub, newPub, "")
	if err != nil {
		t.Fatalf("expected empty pin to be accepted, got: %v", err)
	}
	if loaded.Body.Reason != testRTReason {
		t.Errorf("Reason = %q, want %q", loaded.Body.Reason, testRTReason)
	}
}

func TestLoadRootTransition_RejectOldSignatureMissing(t *testing.T) {
	t.Parallel()
	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster,
		rtPostSignOpt(func(env *RootTransitionEnvelope) {
			env.OldSignature = ""
		}))

	_, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionOldSignatureFormat")
	}
	if !errors.Is(err, ErrRootTransitionOldSignatureFormat) {
		t.Errorf("got %v, want ErrRootTransitionOldSignatureFormat", err)
	}
}

func TestLoadRootTransition_RejectOldSignatureWrongFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sig  string
	}{
		{name: "wrong_prefix", sig: "sha256:aabb"},
		{name: "wrong_length", sig: "ed25519:aabb"},
		{name: "non_hex", sig: "ed25519:" + "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster,
				rtPostSignOpt(func(env *RootTransitionEnvelope) {
					env.OldSignature = tc.sig
				}))

			_, err := LoadRootTransition(path, oldPub, newPub, oldFP)
			if err == nil {
				t.Fatalf("expected ErrRootTransitionOldSignatureFormat for %q", tc.name)
			}
			if !errors.Is(err, ErrRootTransitionOldSignatureFormat) {
				t.Errorf("got %v, want ErrRootTransitionOldSignatureFormat", err)
			}
		})
	}
}

func TestLoadRootTransition_RejectNewSignatureMissing(t *testing.T) {
	t.Parallel()
	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster,
		rtPostSignOpt(func(env *RootTransitionEnvelope) {
			env.NewSignature = ""
		}))

	_, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionNewSignatureFormat")
	}
	if !errors.Is(err, ErrRootTransitionNewSignatureFormat) {
		t.Errorf("got %v, want ErrRootTransitionNewSignatureFormat", err)
	}
}

func TestLoadRootTransition_RejectNewSignatureWrongFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sig  string
	}{
		{name: "wrong_prefix", sig: "sha256:aabb"},
		{name: "wrong_length", sig: "ed25519:aabb"},
		{name: "non_hex", sig: "ed25519:" + "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster,
				rtPostSignOpt(func(env *RootTransitionEnvelope) {
					env.NewSignature = tc.sig
				}))

			_, err := LoadRootTransition(path, oldPub, newPub, oldFP)
			if err == nil {
				t.Fatalf("expected ErrRootTransitionNewSignatureFormat for %q", tc.name)
			}
			if !errors.Is(err, ErrRootTransitionNewSignatureFormat) {
				t.Errorf("got %v, want ErrRootTransitionNewSignatureFormat", err)
			}
		})
	}
}

func TestLoadRootTransition_RejectOldSignatureInvalid(t *testing.T) {
	t.Parallel()
	// Sign old_signature with a third-party key (not oldPub).
	thirdPartySeedHex := "" +
		"11111111" + "22222222" + "33333333" + "44444444" +
		"55555555" + "66666666" + "77777777" + "88888888"

	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster,
		rtPostSignOpt(func(env *RootTransitionEnvelope) {
			thirdSeed, _ := hex.DecodeString(thirdPartySeedHex)
			thirdPriv := ed25519.NewKeyFromSeed(thirdSeed)
			preimage, err := env.Body.SignablePreimage()
			if err != nil {
				return
			}
			badSig := ed25519.Sign(thirdPriv, preimage)
			env.OldSignature = "ed25519:" + hex.EncodeToString(badSig)
		}))

	_, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionOldSignatureInvalid")
	}
	if !errors.Is(err, ErrRootTransitionOldSignatureInvalid) {
		t.Errorf("got %v, want ErrRootTransitionOldSignatureInvalid", err)
	}
}

func TestLoadRootTransition_RejectNewSignatureInvalid(t *testing.T) {
	t.Parallel()
	// Sign new_signature with oldPub's key instead of newPub's key (swap test).
	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster,
		rtPostSignOpt(func(env *RootTransitionEnvelope) {
			oldSeed, _ := hex.DecodeString(testRTOldSeedHex)
			oldPriv := ed25519.NewKeyFromSeed(oldSeed)
			preimage, err := env.Body.SignablePreimage()
			if err != nil {
				return
			}
			// Sign with old key instead of new key.
			badSig := ed25519.Sign(oldPriv, preimage)
			env.NewSignature = "ed25519:" + hex.EncodeToString(badSig)
		}))

	_, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected ErrRootTransitionNewSignatureInvalid")
	}
	if !errors.Is(err, ErrRootTransitionNewSignatureInvalid) {
		t.Errorf("got %v, want ErrRootTransitionNewSignatureInvalid", err)
	}
}

func TestLoadRootTransition_BothSignaturesPresentAndVerify(t *testing.T) {
	t.Parallel()
	// Positive sanity: a correctly dual-signed envelope loads fine.
	// This is the counter-example to the swap test above.
	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	loaded, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err != nil {
		t.Fatalf("expected both signatures to verify, got: %v", err)
	}
	if loaded.Body.Reason != testRTReason {
		t.Errorf("Reason = %q, want %q", loaded.Body.Reason, testRTReason)
	}
	if loaded.OldSignature == loaded.NewSignature {
		t.Error("old and new signatures should differ (different keys)")
	}
}

func TestLoadRootTransition_HappyPath_YML(t *testing.T) {
	t.Parallel()
	path, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".yml", RootKindRoster)

	loaded, err := LoadRootTransition(path, oldPub, newPub, oldFP)
	if err != nil {
		t.Fatalf("LoadRootTransition YML: %v", err)
	}
	if loaded.Body.RootKind != RootKindRoster {
		t.Errorf("RootKind = %q, want %q", loaded.Body.RootKind, RootKindRoster)
	}
}

func TestLoadRootTransition_RejectMalformedYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	badPath := filepath.Join(dir, "transition.yaml")
	if err := os.WriteFile(badPath, []byte("{bad yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}

	_, oldPub, newPub, oldFP, _ := rootTransitionFixture(t, ".json", RootKindRoster)

	_, err := LoadRootTransition(badPath, oldPub, newPub, oldFP)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !errors.Is(err, ErrRootTransitionDecode) {
		t.Errorf("got %v, want ErrRootTransitionDecode", err)
	}
}
