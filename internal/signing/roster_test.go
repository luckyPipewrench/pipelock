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

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// RFC 8032 section 7.1 test 1 private seed, split per G101 lint rule.
const testRosterSeedHex = "" +
	"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
	"4449c569" + "7b326919" + "703bac03" + "1cae7f60"

// testRosterPubHex is the corresponding public key hex.
const testRosterPubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

// testRosterValidFrom is the validity start used in test fixtures.
const testRosterValidFrom = "2026-04-01T00:00:00Z"

// testRosterKeyIDRoot is the key_id for the root key in test fixtures.
const testRosterKeyIDRoot = "roster-root-test"

// testRosterKeyIDReceipt is the key_id for the receipt-signing key in test fixtures.
const testRosterKeyIDReceipt = "receipt-signing-test"

// testRosterDataClass is the data_class_root used in test fixtures.
const testRosterDataClass = "internal"

// preSignOpt mutates the envelope body before the signature is computed.
type preSignOpt func(env *contract.RosterEnvelope)

// postSignOpt mutates the envelope after the signature is computed, useful
// for corrupting signature or body post-signing.
type postSignOpt func(env *contract.RosterEnvelope)

// withExtension controls the file extension written by rosterFixture.
type withExtension struct {
	ext string
}

// rosterFixture generates a known-good roster with a deterministic
// roster-root keypair. Returns the temp file path and pinned fingerprint.
func rosterFixture(t *testing.T, opts ...any) (path, fingerprint string) {
	t.Helper()

	seed, err := hex.DecodeString(testRosterSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	envelope := contract.RosterEnvelope{
		Body: contract.KeyRoster{
			SchemaVersion:  1,
			RosterSignedBy: testRosterKeyIDRoot,
			Keys: []contract.KeyInfo{
				{
					KeyID:        testRosterKeyIDRoot,
					KeyPurpose:   string(PurposeRosterRoot),
					PublicKeyHex: testRosterPubHex,
					ValidFrom:    testRosterValidFrom,
					Status:       contract.KeyStatusRoot,
				},
				{
					KeyID:        testRosterKeyIDReceipt,
					KeyPurpose:   string(PurposeReceiptSigning),
					PublicKeyHex: testRosterPubHex,
					ValidFrom:    testRosterValidFrom,
					Status:       contract.KeyStatusActive,
				},
			},
			DataClassRoot: testRosterDataClass,
		},
	}

	// Determine file extension and apply pre-sign mutations.
	ext := ".json"
	for _, o := range opts {
		switch v := o.(type) {
		case preSignOpt:
			v(&envelope)
		case withExtension:
			ext = v.ext
		case postSignOpt:
			// applied after signing
		}
	}

	// Sign the body (even if mutations made it invalid — the test checks that).
	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		// For tests that deliberately break the body, produce a dummy sig.
		envelope.Signature = "ed25519:" + hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	} else {
		sig := ed25519.Sign(priv, preimage)
		envelope.Signature = "ed25519:" + hex.EncodeToString(sig)
	}

	// Apply post-sign mutations (signature tampering, etc.).
	for _, o := range opts {
		if fn, ok := o.(postSignOpt); ok {
			fn(&envelope)
		}
	}

	// Serialize based on extension.
	var data []byte
	switch ext {
	case ".yaml", ".yml":
		// Build a map that serialises cleanly to YAML-compatible JSON keys.
		// DecodeStrictYAML goes YAML -> generic tree -> JSON -> struct,
		// so the YAML keys must match JSON tags.
		m := map[string]any{
			"body":      envelopeBodyToMap(envelope.Body),
			"signature": envelope.Signature,
		}
		data, err = yamlMarshal(m)
		if err != nil {
			t.Fatalf("yaml marshal: %v", err)
		}
	default:
		data, err = json.MarshalIndent(envelope, "", "  ")
		if err != nil {
			t.Fatalf("json marshal: %v", err)
		}
		data = append(data, '\n')
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "key_roster"+ext)
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Compute pinned fingerprint from the public key.
	pubBytes, err := hex.DecodeString(testRosterPubHex)
	if err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	fp2, err := Fingerprint(pubBytes)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	return fp, fp2
}

// envelopeBodyToMap converts a KeyRoster to a map for YAML serialisation.
func envelopeBodyToMap(body contract.KeyRoster) map[string]any {
	keys := make([]map[string]any, len(body.Keys))
	for i, k := range body.Keys {
		km := map[string]any{
			"key_id":         k.KeyID,
			"key_purpose":    k.KeyPurpose,
			"public_key_hex": k.PublicKeyHex,
			"valid_from":     k.ValidFrom,
			"valid_until":    nil,
			"status":         k.Status,
		}
		if k.ValidUntil != nil {
			km["valid_until"] = *k.ValidUntil
		}
		if k.Principal != "" {
			km["principal"] = k.Principal
		}
		keys[i] = km
	}
	return map[string]any{
		"schema_version":   body.SchemaVersion,
		"roster_signed_by": body.RosterSignedBy,
		"keys":             keys,
		"data_class_root":  body.DataClassRoot,
	}
}

// yamlMarshal produces YAML text. We use a simple hand-rolled approach
// to avoid importing gopkg.in/yaml.v3 in test code; the YAML is simple
// enough that json.Marshal -> contract.DecodeStrictYAML works because
// DecodeStrictYAML parses YAML that happens to look like JSON. Instead,
// we produce actual YAML text.
func yamlMarshal(m map[string]any) ([]byte, error) {
	// Use the gopkg.in/yaml.v3 encoder that's already a transitive dep.
	// Import is via the contract package's own YAML support.
	// Actually, we can just produce JSON and rename the file — DecodeStrictYAML
	// handles JSON-like YAML. But for a proper YAML test, let's produce
	// flow-style via json.Marshal which is valid YAML.
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// computeTestFingerprint computes sha256 fingerprint of the test public key.
func computeTestFingerprint(t *testing.T) string {
	t.Helper()
	pubBytes, err := hex.DecodeString(testRosterPubHex)
	if err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	digest := sha256.Sum256(pubBytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// --- LoadRoster tests ---

func TestLoadRoster_HappyPath_JSON(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}
	if roster.Body.RosterSignedBy != testRosterKeyIDRoot {
		t.Errorf("RosterSignedBy = %q, want %q", roster.Body.RosterSignedBy, testRosterKeyIDRoot)
	}
	if roster.RosterRootFingerprint != fp {
		t.Errorf("RosterRootFingerprint = %q, want %q", roster.RosterRootFingerprint, fp)
	}
	if roster.SourcePath == "" {
		t.Error("SourcePath is empty")
	}
	if roster.LoadedAt.IsZero() {
		t.Error("LoadedAt is zero")
	}
	if len(roster.Body.Keys) != 2 {
		t.Errorf("Keys count = %d, want 2", len(roster.Body.Keys))
	}
}

func TestLoadRoster_HappyPath_YAML(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t, withExtension{ext: ".yaml"})
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster YAML: %v", err)
	}
	if roster.Body.RosterSignedBy != testRosterKeyIDRoot {
		t.Errorf("RosterSignedBy = %q, want %q", roster.Body.RosterSignedBy, testRosterKeyIDRoot)
	}
}

func TestLoadRoster_HappyPath_YML(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t, withExtension{ext: ".yml"})
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster YML: %v", err)
	}
	if roster.Body.RosterSignedBy != testRosterKeyIDRoot {
		t.Errorf("RosterSignedBy = %q, want %q", roster.Body.RosterSignedBy, testRosterKeyIDRoot)
	}
}

func TestLoadRoster_RejectFileMissing(t *testing.T) {
	t.Parallel()
	_, err := LoadRoster("/nonexistent/path/roster.json", computeTestFingerprint(t))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, ErrRosterRead) {
		t.Errorf("got %v, want ErrRosterRead", err)
	}
}

func TestLoadRoster_RejectUnsupportedExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "roster.txt")
	if err := os.WriteFile(fp, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoster(fp, computeTestFingerprint(t))
	if err == nil {
		t.Fatal("expected error for unsupported extension")
	}
	if !errors.Is(err, ErrRosterUnsupportedExtension) {
		t.Errorf("got %v, want ErrRosterUnsupportedExtension", err)
	}
}

func TestLoadRoster_RejectMalformedJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(fp, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoster(fp, computeTestFingerprint(t))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !errors.Is(err, ErrRosterDecode) {
		t.Errorf("got %v, want ErrRosterDecode", err)
	}
}

func TestLoadRoster_RejectMalformedYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "roster.yaml")
	// Produce invalid YAML: tab indentation is fine, but unmatched braces aren't.
	if err := os.WriteFile(fp, []byte("body:\n  - [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoster(fp, computeTestFingerprint(t))
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !errors.Is(err, ErrRosterDecode) {
		t.Errorf("got %v, want ErrRosterDecode", err)
	}
}

func TestLoadRoster_RejectBodyValidationFails(t *testing.T) {
	t.Parallel()
	// Remove the root key so Validate() fails (no key with status=root).
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		// Keep only the receipt-signing key, remove root.
		env.Body.Keys = []contract.KeyInfo{
			{
				KeyID:        testRosterKeyIDReceipt,
				KeyPurpose:   string(PurposeReceiptSigning),
				PublicKeyHex: testRosterPubHex,
				ValidFrom:    testRosterValidFrom,
				Status:       contract.KeyStatusActive,
			},
		}
	}))
	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterInvalid")
	}
	if !errors.Is(err, ErrRosterInvalid) {
		t.Errorf("got %v, want ErrRosterInvalid", err)
	}
}

func TestLoadRoster_RejectMissingSignature(t *testing.T) {
	t.Parallel()
	// Write a fixture where the signature is empty.
	path, fp := rosterFixture(t, postSignOpt(func(env *contract.RosterEnvelope) {
		env.Signature = ""
	}))
	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterSignatureFormat")
	}
	if !errors.Is(err, ErrRosterSignatureFormat) {
		t.Errorf("got %v, want ErrRosterSignatureFormat", err)
	}
}

func TestLoadRoster_RejectSignatureBadPrefix(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t, postSignOpt(func(env *contract.RosterEnvelope) {
		env.Signature = "sha256:" + env.Signature[len("ed25519:"):]
	}))
	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterSignatureFormat")
	}
	if !errors.Is(err, ErrRosterSignatureFormat) {
		t.Errorf("got %v, want ErrRosterSignatureFormat", err)
	}
}

func TestLoadRoster_RejectSignatureWrongLength(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t, postSignOpt(func(env *contract.RosterEnvelope) {
		// Truncate the hex part.
		env.Signature = "ed25519:aabb"
	}))
	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterSignatureFormat")
	}
	if !errors.Is(err, ErrRosterSignatureFormat) {
		t.Errorf("got %v, want ErrRosterSignatureFormat", err)
	}
}

func TestLoadRoster_RejectSignedByKeyNotInRoster(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t, postSignOpt(func(env *contract.RosterEnvelope) {
		env.Body.RosterSignedBy = "nonexistent-key"
		// Also add a root key to keep Validate() happy.
		env.Body.Keys = append(env.Body.Keys, contract.KeyInfo{
			KeyID:        "nonexistent-key",
			KeyPurpose:   string(PurposeRosterRoot),
			PublicKeyHex: testRosterPubHex,
			ValidFrom:    testRosterValidFrom,
			Status:       contract.KeyStatusRoot,
		})
	}))

	// The fixture was signed with the original body, but then we mutated
	// RosterSignedBy. The body now has "nonexistent-key" as RosterSignedBy,
	// and there IS a key with that ID and root status (we added it), so
	// Validate() passes. But the signature won't verify because the body
	// was mutated after signing.
	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected error")
	}
	// Should fail at signature verification since body was mutated.
	if !errors.Is(err, ErrRosterSignatureInvalid) {
		t.Errorf("got %v, want ErrRosterSignatureInvalid", err)
	}
}

func TestLoadRoster_RejectSignedByWrongPurpose(t *testing.T) {
	t.Parallel()
	// Build a roster where the signing key has purpose=receipt-signing.
	seed, _ := hex.DecodeString(testRosterSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)

	envelope := contract.RosterEnvelope{
		Body: contract.KeyRoster{
			SchemaVersion:  1,
			RosterSignedBy: testRosterKeyIDRoot,
			Keys: []contract.KeyInfo{
				{
					KeyID:        testRosterKeyIDRoot,
					KeyPurpose:   string(PurposeReceiptSigning),
					PublicKeyHex: testRosterPubHex,
					ValidFrom:    testRosterValidFrom,
					Status:       contract.KeyStatusRoot,
				},
			},
			DataClassRoot: testRosterDataClass,
		},
	}

	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	sig := ed25519.Sign(priv, preimage)
	envelope.Signature = "ed25519:" + hex.EncodeToString(sig)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadRoster(fp, computeTestFingerprint(t))
	if err == nil {
		t.Fatal("expected ErrRosterRootWrongPurpose")
	}
	if !errors.Is(err, ErrRosterRootWrongPurpose) {
		t.Errorf("got %v, want ErrRosterRootWrongPurpose", err)
	}
}

func TestLoadRoster_RejectRulesOfficialSigningPurpose(t *testing.T) {
	t.Parallel()
	// Design doc line 861: roster signed by rules-official-signing is rejected.
	seed, _ := hex.DecodeString(testRosterSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)

	envelope := contract.RosterEnvelope{
		Body: contract.KeyRoster{
			SchemaVersion:  1,
			RosterSignedBy: testRosterKeyIDRoot,
			Keys: []contract.KeyInfo{
				{
					KeyID:        testRosterKeyIDRoot,
					KeyPurpose:   string(PurposeRulesOfficialSigning),
					PublicKeyHex: testRosterPubHex,
					ValidFrom:    testRosterValidFrom,
					Status:       contract.KeyStatusRoot,
				},
			},
			DataClassRoot: testRosterDataClass,
		},
	}

	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	sig := ed25519.Sign(priv, preimage)
	envelope.Signature = "ed25519:" + hex.EncodeToString(sig)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadRoster(fp, computeTestFingerprint(t))
	if err == nil {
		t.Fatal("expected ErrRosterRootWrongPurpose")
	}
	if !errors.Is(err, ErrRosterRootWrongPurpose) {
		t.Errorf("got %v, want ErrRosterRootWrongPurpose", err)
	}
}

func TestLoadRoster_RejectFingerprintMismatch(t *testing.T) {
	t.Parallel()
	path, _ := rosterFixture(t)
	// Use a different pinned fingerprint.
	wrongFP := "sha256:" + "aa" + testRosterPubHex[2:]
	// Ensure it's a valid length. We just need it to differ.
	_, err := LoadRoster(path, wrongFP)
	if err == nil {
		t.Fatal("expected ErrRosterRootFingerprintMismatch")
	}
	if !errors.Is(err, ErrRosterRootFingerprintMismatch) {
		t.Errorf("got %v, want ErrRosterRootFingerprintMismatch", err)
	}
}

func TestLoadRoster_RejectSignatureInvalid(t *testing.T) {
	t.Parallel()
	// Flip a bit in the signature.
	path, fp := rosterFixture(t, postSignOpt(func(env *contract.RosterEnvelope) {
		// Swap last hex char to corrupt signature.
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
	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterSignatureInvalid")
	}
	if !errors.Is(err, ErrRosterSignatureInvalid) {
		t.Errorf("got %v, want ErrRosterSignatureInvalid", err)
	}
}

// --- ResolveKey tests ---

func TestResolveKey_HappyPath(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	key, err := roster.ResolveKey(testRosterKeyIDReceipt, now)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	if key.KeyID != testRosterKeyIDReceipt {
		t.Errorf("KeyID = %q, want %q", key.KeyID, testRosterKeyIDReceipt)
	}
	if key.Status != contract.KeyStatusActive {
		t.Errorf("Status = %q, want %q", key.Status, contract.KeyStatusActive)
	}
}

func TestResolveKey_RejectRootStatus(t *testing.T) {
	t.Parallel()
	// Root keys sign rosters and root transitions, never runtime payloads,
	// so ResolveKey must reject them even though they are otherwise valid.
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	if _, err := roster.ResolveKey(testRosterKeyIDRoot, now); !errors.Is(err, ErrRosterKeyNotActive) {
		t.Errorf("got %v, want ErrRosterKeyNotActive", err)
	}
}

func TestResolveKey_RejectUnknown(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	_, err = roster.ResolveKey("nonexistent", now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyUnknown")
	}
	if !errors.Is(err, ErrRosterKeyUnknown) {
		t.Errorf("got %v, want ErrRosterKeyUnknown", err)
	}
}

func TestResolveKey_RejectRevoked(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		for i := range env.Body.Keys {
			if env.Body.Keys[i].KeyID == testRosterKeyIDReceipt {
				env.Body.Keys[i].Status = contract.KeyStatusRevoked
			}
		}
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	_, err = roster.ResolveKey(testRosterKeyIDReceipt, now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyRevoked")
	}
	if !errors.Is(err, ErrRosterKeyRevoked) {
		t.Errorf("got %v, want ErrRosterKeyRevoked", err)
	}
}

func TestResolveKey_RejectNotYetValid(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	// Use a time before the valid_from.
	now, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	_, err = roster.ResolveKey(testRosterKeyIDReceipt, now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyNotYetValid")
	}
	if !errors.Is(err, ErrRosterKeyNotYetValid) {
		t.Errorf("got %v, want ErrRosterKeyNotYetValid", err)
	}
}

func TestResolveKey_RejectExpired(t *testing.T) {
	t.Parallel()
	validUntil := "2026-06-01T00:00:00Z"
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		for i := range env.Body.Keys {
			if env.Body.Keys[i].KeyID == testRosterKeyIDReceipt {
				env.Body.Keys[i].ValidUntil = &validUntil
			}
		}
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	// Use a time after the valid_until.
	now, _ := time.Parse(time.RFC3339, "2026-07-01T00:00:00Z")
	_, err = roster.ResolveKey(testRosterKeyIDReceipt, now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyExpired")
	}
	if !errors.Is(err, ErrRosterKeyExpired) {
		t.Errorf("got %v, want ErrRosterKeyExpired", err)
	}
}

func TestResolveKey_ValidUntilBoundary(t *testing.T) {
	t.Parallel()
	// When now == valid_until, key should still be valid (not expired).
	validUntil := "2026-06-01T00:00:00Z"
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		for i := range env.Body.Keys {
			if env.Body.Keys[i].KeyID == testRosterKeyIDReceipt {
				env.Body.Keys[i].ValidUntil = &validUntil
			}
		}
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, validUntil)
	_, err = roster.ResolveKey(testRosterKeyIDReceipt, now)
	if err != nil {
		t.Errorf("key at exact valid_until should be valid, got: %v", err)
	}
}

// --- AuthorizeSignerForPayload tests ---

func TestAuthorizeSignature_HappyPath(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	// receipt-signing key should be authorised for proxy_decision.
	if err := roster.AuthorizeSignerForPayload("proxy_decision", testRosterKeyIDReceipt, now); err != nil {
		t.Errorf("AuthorizeSignature proxy_decision: %v", err)
	}
}

func TestAuthorizeSignature_RejectWrongPurpose(t *testing.T) {
	t.Parallel()
	// Add a contract-activation-signing key to test purpose mismatch.
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		env.Body.Keys = append(env.Body.Keys, contract.KeyInfo{
			KeyID:        "activation-test",
			KeyPurpose:   string(PurposeContractActivationSigning),
			PublicKeyHex: testRosterPubHex,
			ValidFrom:    testRosterValidFrom,
			Status:       contract.KeyStatusActive,
		})
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	// proxy_decision requires receipt-signing, not contract-activation-signing.
	err = roster.AuthorizeSignerForPayload("proxy_decision", "activation-test", now)
	if err == nil {
		t.Fatal("expected ErrWrongKeyPurpose")
	}
	if !errors.Is(err, contract.ErrWrongKeyPurpose) {
		t.Errorf("got %v, want contract.ErrWrongKeyPurpose", err)
	}
}

func TestAuthorizeSignature_RejectUnknownPayloadKind(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	err = roster.AuthorizeSignerForPayload("nonexistent_payload", testRosterKeyIDReceipt, now)
	if err == nil {
		t.Fatal("expected ErrUnknownPayloadKind")
	}
	if !errors.Is(err, contract.ErrUnknownPayloadKind) {
		t.Errorf("got %v, want contract.ErrUnknownPayloadKind", err)
	}
}

func TestAuthorizeSignature_RejectKeyNotResolved_Revoked(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		for i := range env.Body.Keys {
			if env.Body.Keys[i].KeyID == testRosterKeyIDReceipt {
				env.Body.Keys[i].Status = contract.KeyStatusRevoked
			}
		}
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	err = roster.AuthorizeSignerForPayload("proxy_decision", testRosterKeyIDReceipt, now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyRevoked")
	}
	if !errors.Is(err, ErrRosterKeyRevoked) {
		t.Errorf("got %v, want ErrRosterKeyRevoked", err)
	}
}

func TestAuthorizeSignature_RejectKeyNotResolved_Expired(t *testing.T) {
	t.Parallel()
	validUntil := "2026-04-15T00:00:00Z"
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		for i := range env.Body.Keys {
			if env.Body.Keys[i].KeyID == testRosterKeyIDReceipt {
				env.Body.Keys[i].ValidUntil = &validUntil
			}
		}
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	err = roster.AuthorizeSignerForPayload("proxy_decision", testRosterKeyIDReceipt, now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyExpired")
	}
	if !errors.Is(err, ErrRosterKeyExpired) {
		t.Errorf("got %v, want ErrRosterKeyExpired", err)
	}
}

func TestAuthorizeSignature_RejectKeyNotResolved_Unknown(t *testing.T) {
	t.Parallel()
	path, fp := rosterFixture(t)
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	err = roster.AuthorizeSignerForPayload("proxy_decision", "nonexistent", now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyUnknown")
	}
	if !errors.Is(err, ErrRosterKeyUnknown) {
		t.Errorf("got %v, want ErrRosterKeyUnknown", err)
	}
}

func TestAuthorizeSignature_ContractPromoteIntent(t *testing.T) {
	t.Parallel()
	// contract_promote_intent requires contract-activation-signing.
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		env.Body.Keys = append(env.Body.Keys, contract.KeyInfo{
			KeyID:        "activation-test",
			KeyPurpose:   string(PurposeContractActivationSigning),
			PublicKeyHex: testRosterPubHex,
			ValidFrom:    testRosterValidFrom,
			Status:       contract.KeyStatusActive,
		})
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	if err := roster.AuthorizeSignerForPayload("contract_promote_intent", "activation-test", now); err != nil {
		t.Errorf("AuthorizeSignature contract_promote_intent: %v", err)
	}
}

// --- Coverage boost tests for edge cases ---

func TestLoadRoster_RejectSignatureHexInvalidChars(t *testing.T) {
	t.Parallel()
	// 128-char hex but with invalid hex chars (gg is not hex).
	badHex := "gg" + testRosterPubHex[2:] + testRosterPubHex
	path, fp := rosterFixture(t, postSignOpt(func(env *contract.RosterEnvelope) {
		env.Signature = "ed25519:" + badHex
	}))
	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterSignatureFormat")
	}
	if !errors.Is(err, ErrRosterSignatureFormat) {
		t.Errorf("got %v, want ErrRosterSignatureFormat", err)
	}
}

func TestLoadRoster_RejectsUnknownKeyStatus(t *testing.T) {
	t.Parallel()
	// A signed roster entry with status="disabled" must reject at LoadRoster
	// even though the rest of the entry is well-formed. Fail-open on unknown
	// status would let an attacker smuggle a key that ResolveKey treats as
	// active because the only explicit reject historically was "revoked".
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		env.Body.Keys = append(env.Body.Keys, contract.KeyInfo{
			KeyID:        "disabled-key",
			KeyPurpose:   string(PurposeReceiptSigning),
			PublicKeyHex: testRosterPubHex,
			ValidFrom:    testRosterValidFrom,
			Status:       "disabled",
		})
	}))

	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterKeyInvalidStatus")
	}
	if !errors.Is(err, ErrRosterKeyInvalidStatus) {
		t.Errorf("got %v, want ErrRosterKeyInvalidStatus", err)
	}
}

func TestLoadRoster_RejectsBadPublicKeyHex(t *testing.T) {
	t.Parallel()
	// Strict per-key validation must reject a non-32-byte public key even
	// when the rest of the roster is otherwise valid.
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		env.Body.Keys = append(env.Body.Keys, contract.KeyInfo{
			KeyID:        "short-key",
			KeyPurpose:   string(PurposeReceiptSigning),
			PublicKeyHex: "deadbeef", // 4 bytes, not 32
			ValidFrom:    testRosterValidFrom,
			Status:       contract.KeyStatusActive,
		})
	}))

	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterKeyMissingPublicKey")
	}
	if !errors.Is(err, ErrRosterKeyMissingPublicKey) {
		t.Errorf("got %v, want ErrRosterKeyMissingPublicKey", err)
	}
}

func TestLoadRoster_RejectsUnknownKeyPurpose(t *testing.T) {
	t.Parallel()
	// A key with an unrecognised purpose must reject at LoadRoster (strict
	// per-key validation runs before any signature lookup).
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		env.Body.Keys = append(env.Body.Keys, contract.KeyInfo{
			KeyID:        "bogus-purpose-key",
			KeyPurpose:   "bogus-purpose",
			PublicKeyHex: testRosterPubHex,
			ValidFrom:    testRosterValidFrom,
			Status:       contract.KeyStatusActive,
		})
	}))

	_, err := LoadRoster(path, fp)
	if err == nil {
		t.Fatal("expected ErrRosterKeyInvalidPurpose")
	}
	if !errors.Is(err, ErrRosterKeyInvalidPurpose) {
		t.Errorf("got %v, want ErrRosterKeyInvalidPurpose", err)
	}
}

func TestResolveKey_InvalidValidFromFormat(t *testing.T) {
	t.Parallel()
	// Key with invalid valid_from string.
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		env.Body.Keys = append(env.Body.Keys, contract.KeyInfo{
			KeyID:        "bad-from-key",
			KeyPurpose:   string(PurposeReceiptSigning),
			PublicKeyHex: testRosterPubHex,
			ValidFrom:    "not-a-date",
			Status:       contract.KeyStatusActive,
		})
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	_, err = roster.ResolveKey("bad-from-key", now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyNotYetValid")
	}
	if !errors.Is(err, ErrRosterKeyNotYetValid) {
		t.Errorf("got %v, want ErrRosterKeyNotYetValid", err)
	}
}

func TestResolveKey_InvalidValidUntilFormat(t *testing.T) {
	t.Parallel()
	// Key with invalid valid_until string.
	badUntil := "not-a-date"
	path, fp := rosterFixture(t, preSignOpt(func(env *contract.RosterEnvelope) {
		for i := range env.Body.Keys {
			if env.Body.Keys[i].KeyID == testRosterKeyIDReceipt {
				env.Body.Keys[i].ValidUntil = &badUntil
			}
		}
	}))
	roster, err := LoadRoster(path, fp)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	_, err = roster.ResolveKey(testRosterKeyIDReceipt, now)
	if err == nil {
		t.Fatal("expected ErrRosterKeyExpired")
	}
	if !errors.Is(err, ErrRosterKeyExpired) {
		t.Errorf("got %v, want ErrRosterKeyExpired", err)
	}
}

func TestLoadRoster_GoldenJSON(t *testing.T) {
	t.Parallel()
	// Load the existing golden fixture from PR 1.1 to verify cross-compat.
	goldenPath := filepath.Join("..", "contract", "testdata", "golden", "valid_key_roster.json")
	fp := computeTestFingerprint(t)
	roster, err := LoadRoster(goldenPath, fp)
	if err != nil {
		t.Fatalf("LoadRoster golden: %v", err)
	}
	if roster.Body.RosterSignedBy != testRosterKeyIDRoot {
		t.Errorf("RosterSignedBy = %q, want %q", roster.Body.RosterSignedBy, testRosterKeyIDRoot)
	}
	if len(roster.Body.Keys) != 2 {
		t.Errorf("Keys count = %d, want 2", len(roster.Body.Keys))
	}
}

func TestLoadRoster_RejectBadPinnedFingerprintFormat(t *testing.T) {
	t.Parallel()
	path, _ := rosterFixture(t)
	// Pass a malformed pinned fingerprint (wrong algorithm, not wrong digest).
	_, err := LoadRoster(path, "md5:aabbccdd")
	if err == nil {
		t.Fatal("expected ErrRosterRootFingerprintMismatch")
	}
	if !errors.Is(err, ErrRosterRootFingerprintMismatch) {
		t.Errorf("got %v, want ErrRosterRootFingerprintMismatch", err)
	}
}

func TestLoadRoster_RejectRootKeyBadHex(t *testing.T) {
	t.Parallel()
	// Root key with invalid hex in public_key_hex.
	seed, _ := hex.DecodeString(testRosterSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)

	// Pad with 'zz' to get 64-char hex that won't decode.
	badHex := "zz" + testRosterPubHex[2:]
	envelope := contract.RosterEnvelope{
		Body: contract.KeyRoster{
			SchemaVersion:  1,
			RosterSignedBy: testRosterKeyIDRoot,
			Keys: []contract.KeyInfo{
				{
					KeyID:        testRosterKeyIDRoot,
					KeyPurpose:   string(PurposeRosterRoot),
					PublicKeyHex: badHex,
					ValidFrom:    testRosterValidFrom,
					Status:       contract.KeyStatusRoot,
				},
			},
			DataClassRoot: testRosterDataClass,
		},
	}

	preimage, err := envelope.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	sig := ed25519.Sign(priv, preimage)
	envelope.Signature = "ed25519:" + hex.EncodeToString(sig)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	fp := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadRoster(fp, computeTestFingerprint(t))
	if err == nil {
		t.Fatal("expected ErrRosterKeyMissingPublicKey")
	}
	// Strict per-key validation in LoadRoster catches the bad hex before any
	// root-specific lookup runs, so the surfaced sentinel is the missing /
	// malformed public-key sentinel.
	if !errors.Is(err, ErrRosterKeyMissingPublicKey) {
		t.Errorf("got %v, want ErrRosterKeyMissingPublicKey", err)
	}
}
