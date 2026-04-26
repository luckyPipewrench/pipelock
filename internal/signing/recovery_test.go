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
	"time"
)

// RFC 8032 section 7.1 test 2 private seed, split per G101 lint rule.
// This is a DIFFERENT seed from the roster tests so the two keypairs are
// independent.
const testRecoverySeedHex = "" +
	"4ccd089b" + "28ff96da" + "9db6c346" + "ec114e0f" +
	"5b8a319f" + "35aba624" + "da8cf6ed" + "4fb8a6fb"

// testRecoveryReason is the operator reason used in test fixtures.
const testRecoveryReason = "roster root key compromised"

// testRecoveryOperator is the operator identity used in test fixtures.
const testRecoveryOperator = "ops@example.com"

// testRecoveryTargetHash is a well-formed target roster hash for fixtures.
const testRecoveryTargetHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// testRecoveryBadDate is reused for RFC 3339 parse-failure tests.
const testRecoveryBadDate = "not-a-date"

// recoveryPreSignOpt mutates the envelope body before the signature is computed.
type recoveryPreSignOpt func(env *RecoveryAuthorizationEnvelope)

// recoveryPostSignOpt mutates the envelope after the signature is computed,
// useful for corrupting signature or body post-signing.
type recoveryPostSignOpt func(env *RecoveryAuthorizationEnvelope)

// recoveryFixture builds a known-good recovery authorization, signs it with
// a deterministic recovery-root keypair, writes the envelope to a temp file,
// and returns (path, recoveryRootPublicKey, recoveryRootFingerprint).
//
// The default fixture has:
//   - issued_at  = now - 10 minutes
//   - expires_at = now + 30 minutes
//
// so that time-window checks pass with the returned "now" (also returned).
//
// Pass recoveryPreSignOpt to mutate the body before signing, or
// recoveryPostSignOpt to tamper with the envelope after signing.
func recoveryFixture(t *testing.T, now time.Time, ext string, opts ...any) (path string, pub []byte, fingerprint string) {
	t.Helper()

	seed, err := hex.DecodeString(testRecoverySeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub = priv.Public().(ed25519.PublicKey)

	envelope := RecoveryAuthorizationEnvelope{
		Body: RecoveryAuthorizationBody{
			SchemaVersion:    1,
			Reason:           testRecoveryReason,
			ExpiresAt:        now.Add(30 * time.Minute).UTC().Format(time.RFC3339),
			TargetRosterHash: testRecoveryTargetHash,
			OperatorIdentity: testRecoveryOperator,
			IssuedAt:         now.Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		},
	}

	// Apply pre-sign mutations.
	for _, o := range opts {
		if fn, ok := o.(recoveryPreSignOpt); ok {
			fn(&envelope)
		}
	}

	// Sign the body.
	preimage, pErr := envelope.Body.SignablePreimage()
	if pErr != nil {
		// For tests that deliberately break the body, produce a dummy sig.
		envelope.Signature = "ed25519:" + hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	} else {
		sig := ed25519.Sign(priv, preimage)
		envelope.Signature = "ed25519:" + hex.EncodeToString(sig)
	}

	// Apply post-sign mutations (signature tampering, etc.).
	for _, o := range opts {
		if fn, ok := o.(recoveryPostSignOpt); ok {
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
	fp := filepath.Join(dir, "recovery_authorization"+ext)
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Compute fingerprint.
	digest := sha256.Sum256(pub)
	fpStr := "sha256:" + hex.EncodeToString(digest[:])

	return fp, pub, fpStr
}

// --- LoadRecoveryAuthorization tests ---

func TestLoadRecoveryAuthorization_HappyPath_JSON(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json")

	loaded, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err != nil {
		t.Fatalf("LoadRecoveryAuthorization: %v", err)
	}
	if loaded.Body.Reason != testRecoveryReason {
		t.Errorf("Reason = %q, want %q", loaded.Body.Reason, testRecoveryReason)
	}
	if loaded.Body.OperatorIdentity != testRecoveryOperator {
		t.Errorf("OperatorIdentity = %q, want %q", loaded.Body.OperatorIdentity, testRecoveryOperator)
	}
	if loaded.RecoveryRootFingerprint != fp {
		t.Errorf("RecoveryRootFingerprint = %q, want %q", loaded.RecoveryRootFingerprint, fp)
	}
	if loaded.SourcePath == "" {
		t.Error("SourcePath is empty")
	}
	if loaded.LoadedAt.IsZero() {
		t.Error("LoadedAt is zero")
	}
}

func TestLoadRecoveryAuthorization_HappyPath_YAML(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".yaml")

	loaded, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err != nil {
		t.Fatalf("LoadRecoveryAuthorization YAML: %v", err)
	}
	if loaded.Body.Reason != testRecoveryReason {
		t.Errorf("Reason = %q, want %q", loaded.Body.Reason, testRecoveryReason)
	}
}

func TestLoadRecoveryAuthorization_HappyPath_YML(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".yml")

	loaded, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err != nil {
		t.Fatalf("LoadRecoveryAuthorization YML: %v", err)
	}
	if loaded.Body.Reason != testRecoveryReason {
		t.Errorf("Reason = %q, want %q", loaded.Body.Reason, testRecoveryReason)
	}
}

func TestLoadRecoveryAuthorization_RejectFileMissing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	_, pub, fp := recoveryFixture(t, now, ".json")

	_, err := LoadRecoveryAuthorization("/nonexistent/path/recovery.json", pub, fp, now)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, ErrRecoveryRead) {
		t.Errorf("got %v, want ErrRecoveryRead", err)
	}
}

func TestLoadRecoveryAuthorization_RejectUnsupportedExtension(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	_, pub, fp := recoveryFixture(t, now, ".json")

	dir := t.TempDir()
	badPath := filepath.Join(dir, "recovery.txt")
	if err := os.WriteFile(badPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadRecoveryAuthorization(badPath, pub, fp, now)
	if err == nil {
		t.Fatal("expected error for unsupported extension")
	}
	if !errors.Is(err, ErrRecoveryUnsupportedExtension) {
		t.Errorf("got %v, want ErrRecoveryUnsupportedExtension", err)
	}
}

func TestLoadRecoveryAuthorization_RejectMalformedJSON(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	_, pub, fp := recoveryFixture(t, now, ".json")

	dir := t.TempDir()
	badPath := filepath.Join(dir, "recovery.json")
	if err := os.WriteFile(badPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadRecoveryAuthorization(badPath, pub, fp, now)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !errors.Is(err, ErrRecoveryDecode) {
		t.Errorf("got %v, want ErrRecoveryDecode", err)
	}
}

func TestLoadRecoveryAuthorization_RejectSchemaVersionWrong(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.SchemaVersion = 99
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoverySchemaVersion")
	}
	if !errors.Is(err, ErrRecoverySchemaVersion) {
		t.Errorf("got %v, want ErrRecoverySchemaVersion", err)
	}
}

func TestLoadRecoveryAuthorization_RejectMissingReason(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.Reason = ""
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryReasonRequired")
	}
	if !errors.Is(err, ErrRecoveryReasonRequired) {
		t.Errorf("got %v, want ErrRecoveryReasonRequired", err)
	}
}

func TestLoadRecoveryAuthorization_RejectMissingOperator(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.OperatorIdentity = ""
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryOperatorRequired")
	}
	if !errors.Is(err, ErrRecoveryOperatorRequired) {
		t.Errorf("got %v, want ErrRecoveryOperatorRequired", err)
	}
}

func TestLoadRecoveryAuthorization_RejectExpiresAtNotRFC3339(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.ExpiresAt = testRecoveryBadDate
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryExpiryFormat")
	}
	if !errors.Is(err, ErrRecoveryExpiryFormat) {
		t.Errorf("got %v, want ErrRecoveryExpiryFormat", err)
	}
}

func TestLoadRecoveryAuthorization_RejectIssuedAtNotRFC3339(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.IssuedAt = testRecoveryBadDate
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryIssuedAtFormat")
	}
	if !errors.Is(err, ErrRecoveryIssuedAtFormat) {
		t.Errorf("got %v, want ErrRecoveryIssuedAtFormat", err)
	}
}

func TestLoadRecoveryAuthorization_RejectTargetHashWrongPrefix(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.TargetRosterHash = "md5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryTargetHashFormat")
	}
	if !errors.Is(err, ErrRecoveryTargetHashFormat) {
		t.Errorf("got %v, want ErrRecoveryTargetHashFormat", err)
	}
}

func TestLoadRecoveryAuthorization_RejectTargetHashWrongLength(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.TargetRosterHash = "sha256:aabb"
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryTargetHashFormat")
	}
	if !errors.Is(err, ErrRecoveryTargetHashFormat) {
		t.Errorf("got %v, want ErrRecoveryTargetHashFormat", err)
	}
}

func TestLoadRecoveryAuthorization_RejectTargetHashNonHex(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	// 64 chars but with non-hex 'g'.
	badHash := "sha256:g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.TargetRosterHash = badHash
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryTargetHashFormat")
	}
	if !errors.Is(err, ErrRecoveryTargetHashFormat) {
		t.Errorf("got %v, want ErrRecoveryTargetHashFormat", err)
	}
}

func TestLoadRecoveryAuthorization_RejectIssuedInTheFuture(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	// Set issued_at to 1 hour in the future.
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.IssuedAt = now.Add(1 * time.Hour).UTC().Format(time.RFC3339)
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryNotYetValid")
	}
	if !errors.Is(err, ErrRecoveryNotYetValid) {
		t.Errorf("got %v, want ErrRecoveryNotYetValid", err)
	}
}

func TestLoadRecoveryAuthorization_RejectExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	// Set expires_at to 1 minute ago.
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.ExpiresAt = now.Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryExpired")
	}
	if !errors.Is(err, ErrRecoveryExpired) {
		t.Errorf("got %v, want ErrRecoveryExpired", err)
	}
}

func TestLoadRecoveryAuthorization_RejectExpiryMoreThan1HourOut(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	// Set expires_at to 2 hours in the future.
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.ExpiresAt = now.Add(2 * time.Hour).UTC().Format(time.RFC3339)
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryExpiryTooFar")
	}
	if !errors.Is(err, ErrRecoveryExpiryTooFar) {
		t.Errorf("got %v, want ErrRecoveryExpiryTooFar", err)
	}
}

func TestLoadRecoveryAuthorization_AcceptsExpiryExactly1Hour(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	// Set expires_at to exactly now + 1h. The check is > 1h, so exactly 1h passes.
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPreSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		env.Body.ExpiresAt = now.Add(recoveryExpiryCeiling).UTC().Format(time.RFC3339)
	}))

	loaded, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err != nil {
		t.Fatalf("expected exactly 1h expiry to be accepted, got: %v", err)
	}
	if loaded.Body.Reason != testRecoveryReason {
		t.Errorf("Reason = %q, want %q", loaded.Body.Reason, testRecoveryReason)
	}
}

func TestLoadRecoveryAuthorization_RejectFingerprintMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	path, pub, _ := recoveryFixture(t, now, ".json")

	// Use a wrong pinned fingerprint (valid format but different digest).
	wrongFP := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	_, err := LoadRecoveryAuthorization(path, pub, wrongFP, now)
	if err == nil {
		t.Fatal("expected ErrRecoveryFingerprintMismatch")
	}
	if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
		t.Errorf("got %v, want ErrRecoveryFingerprintMismatch", err)
	}
}

func TestLoadRecoveryAuthorization_RejectSignatureFormatBad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sig  string
	}{
		{name: "empty", sig: ""},
		{name: "wrong_prefix", sig: "sha256:aabb"},
		{name: "wrong_length", sig: "ed25519:aabb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
			path, pub, fp := recoveryFixture(t, now, ".json", recoveryPostSignOpt(func(env *RecoveryAuthorizationEnvelope) {
				env.Signature = tc.sig
			}))

			_, err := LoadRecoveryAuthorization(path, pub, fp, now)
			if err == nil {
				t.Fatalf("expected ErrRecoverySignatureFormat for %q", tc.name)
			}
			if !errors.Is(err, ErrRecoverySignatureFormat) {
				t.Errorf("got %v, want ErrRecoverySignatureFormat", err)
			}
		})
	}
}

func TestLoadRecoveryAuthorization_RejectSignatureInvalid(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 14, 0, 0, 0, time.UTC)
	// Flip last hex char in the signature to make it cryptographically invalid.
	path, pub, fp := recoveryFixture(t, now, ".json", recoveryPostSignOpt(func(env *RecoveryAuthorizationEnvelope) {
		sig := env.Signature
		lastChar := sig[len(sig)-1]
		var replacement byte
		if lastChar == '0' {
			replacement = '1'
		} else {
			replacement = '0'
		}
		env.Signature = sig[:len(sig)-1] + string(replacement)
	}))

	_, err := LoadRecoveryAuthorization(path, pub, fp, now)
	if err == nil {
		t.Fatal("expected ErrRecoverySignatureInvalid")
	}
	if !errors.Is(err, ErrRecoverySignatureInvalid) {
		t.Errorf("got %v, want ErrRecoverySignatureInvalid", err)
	}
}

// --- SignablePreimage tests ---

func TestRecoveryAuthorizationBody_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	body := RecoveryAuthorizationBody{
		SchemaVersion:    1,
		Reason:           testRecoveryReason,
		ExpiresAt:        "2026-04-26T15:00:00Z",
		TargetRosterHash: testRecoveryTargetHash,
		OperatorIdentity: testRecoveryOperator,
		IssuedAt:         "2026-04-26T13:00:00Z",
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

// --- Validate tests (table-driven, isolated from time-window checks) ---

func TestRecoveryAuthorizationBody_Validate_HappyPath(t *testing.T) {
	t.Parallel()
	body := RecoveryAuthorizationBody{
		SchemaVersion:    1,
		Reason:           testRecoveryReason,
		ExpiresAt:        "2026-04-26T15:00:00Z",
		TargetRosterHash: testRecoveryTargetHash,
		OperatorIdentity: testRecoveryOperator,
		IssuedAt:         "2026-04-26T13:00:00Z",
	}
	if err := body.Validate(); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}
}

func TestRecoveryAuthorizationBody_Validate_Errors(t *testing.T) {
	t.Parallel()

	validBody := RecoveryAuthorizationBody{
		SchemaVersion:    1,
		Reason:           testRecoveryReason,
		ExpiresAt:        "2026-04-26T15:00:00Z",
		TargetRosterHash: testRecoveryTargetHash,
		OperatorIdentity: testRecoveryOperator,
		IssuedAt:         "2026-04-26T13:00:00Z",
	}

	tests := []struct {
		name    string
		mutate  func(*RecoveryAuthorizationBody)
		wantErr error
	}{
		{
			name:    "wrong_schema_version",
			mutate:  func(b *RecoveryAuthorizationBody) { b.SchemaVersion = 0 },
			wantErr: ErrRecoverySchemaVersion,
		},
		{
			name:    "empty_reason",
			mutate:  func(b *RecoveryAuthorizationBody) { b.Reason = "" },
			wantErr: ErrRecoveryReasonRequired,
		},
		{
			name:    "bad_expires_at",
			mutate:  func(b *RecoveryAuthorizationBody) { b.ExpiresAt = "nope" },
			wantErr: ErrRecoveryExpiryFormat,
		},
		{
			name:    "bad_issued_at",
			mutate:  func(b *RecoveryAuthorizationBody) { b.IssuedAt = "nope" },
			wantErr: ErrRecoveryIssuedAtFormat,
		},
		{
			name:    "target_hash_wrong_prefix",
			mutate:  func(b *RecoveryAuthorizationBody) { b.TargetRosterHash = "md5:abcd" },
			wantErr: ErrRecoveryTargetHashFormat,
		},
		{
			name:    "target_hash_wrong_length",
			mutate:  func(b *RecoveryAuthorizationBody) { b.TargetRosterHash = "sha256:abcd" },
			wantErr: ErrRecoveryTargetHashFormat,
		},
		{
			name: "target_hash_uppercase_hex",
			mutate: func(b *RecoveryAuthorizationBody) {
				b.TargetRosterHash = "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
			},
			wantErr: ErrRecoveryTargetHashFormat,
		},
		{
			name:    "empty_operator",
			mutate:  func(b *RecoveryAuthorizationBody) { b.OperatorIdentity = "" },
			wantErr: ErrRecoveryOperatorRequired,
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
