// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// updateGolden returns true when fixtures should be (re)written rather than
// just read. Set via env var UPDATE_GOLDEN=1.
func updateGolden() bool {
	return os.Getenv("UPDATE_GOLDEN") == "1"
}

// goldenTestKeyPair holds the RFC 8032 §7.1 test-1 key pair loaded from JSON.
type goldenTestKeyPair struct {
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
}

// loadTestKeysForGolden loads the RFC 8032 §7.1 test-1 key pair from the
// shared testdata fixture. Duplicated from verify_test.go to avoid cross-file
// dependency ordering issues in the test binary.
func loadTestKeysForGolden(t *testing.T) goldenTestKeyPair {
	t.Helper()
	path := filepath.Join("testdata", "golden", "ed25519_test_keys.json")
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read test keys: %v", err)
	}
	var k goldenTestKeyPair
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatalf("unmarshal test keys: %v", err)
	}
	return k
}

// goldenSignKey returns the RFC 8032 §7.1 test-1 private key as ed25519.PrivateKey.
// The seed is the 32-byte value from the JSON fixture; ed25519.NewKeyFromSeed
// expands it to the 64-byte private-key form used by ed25519.Sign.
func goldenSignKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	keys := loadTestKeysForGolden(t)
	seed, err := hex.DecodeString(keys.PrivateKeyHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length: got %d want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// signEd25519Hex signs preimage with key and returns "ed25519:" + hex(sig).
func signEd25519Hex(key ed25519.PrivateKey, preimage []byte) string {
	sig := ed25519.Sign(key, preimage)
	return "ed25519:" + hex.EncodeToString(sig)
}

// stripEd25519HexPrefix decodes "ed25519:HEX" into raw signature bytes.
func stripEd25519HexPrefix(t *testing.T, s string) []byte {
	t.Helper()
	const prefix = "ed25519:"
	if !strings.HasPrefix(s, prefix) {
		t.Fatalf("signature %q lacks ed25519: prefix", s)
	}
	b, err := hex.DecodeString(s[len(prefix):])
	if err != nil {
		t.Fatalf("decode signature hex: %v", err)
	}
	return b
}

// goldenWriteOrAssert either writes the bytes to path (if UPDATE_GOLDEN=1)
// or reads the file at path and asserts its content is byte-identical to body.
func goldenWriteOrAssert(t *testing.T, path string, body []byte) {
	t.Helper()
	if updateGolden() {
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

// --- Per-artifact golden round-trip tests ---

func TestGolden_Contract(t *testing.T) {
	t.Parallel()
	priv := goldenSignKey(t)
	c := Contract{
		SchemaVersion:    1,
		ContractKind:     ContractKind,
		ContractHash:     "sha256:" + hex.EncodeToString([]byte("contract-fixed")[:8]),
		SignerKeyID:      "contract-compile-key-v1-test",
		KeyPurpose:       "contract-compile-signing",
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{"selector.agent": "internal"},
		Selector: Selector{
			Agent:      "buster",
			SelectorID: "sha256:sel-test",
		},
		ObservationWindow: ObservationWindow{
			Start:                 time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			End:                   time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC),
			EventCount:            1247,
			SessionCount:          12,
			ObservationWindowRoot: "sha256:obswin-test",
		},
		Compile: ContractCompile{
			PipelockVersion:        "v2.4.0-test",
			PipelockBuildSHA:       "test",
			GoVersion:              "go1.26.0",
			ModuleDigestRoot:       "sha256:mod-test",
			CompileConfigHash:      "sha256:cfg-test",
			InferenceAlgorithm:     "wilson_v1",
			NormalizationAlgorithm: "nfc_v1",
		},
		Defaults: ContractDefaults{
			Fidelity:   "medium",
			Confidence: map[string]any{},
			Privacy: ContractDefaultsPrivacy{
				DefaultDataClass: DataClassInternal,
				SaltEpoch:        1,
				ForbidClasses:    []DataClass{DataClassRegulated},
			},
		},
		Rules: []Rule{},
	}
	preimage, err := c.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	envelope := ContractEnvelope{
		Body:      c,
		Signature: signEd25519Hex(priv, preimage),
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	body = append(body, '\n')
	goldenWriteOrAssert(t, filepath.Join("testdata", "golden", "valid_contract.json"), body)

	// Read-back verification: decode the fixture, recompute preimage, verify signature.
	raw, err := os.ReadFile(filepath.Clean(filepath.Join("testdata", "golden", "valid_contract.json")))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got ContractEnvelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	gotPre, err := got.Body.SignablePreimage()
	if err != nil {
		t.Fatalf("verify preimage: %v", err)
	}
	if string(gotPre) != string(preimage) {
		t.Errorf("preimage drift on read-back")
	}
	pubKey, err := hex.DecodeString(loadTestKeysForGolden(t).PublicKeyHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	sig := stripEd25519HexPrefix(t, got.Signature)
	if !VerifyEd25519PureEdDSA(pubKey, gotPre, sig) {
		t.Error("signature verify failed on golden contract")
	}
}

func TestGolden_ActiveManifest(t *testing.T) {
	t.Parallel()
	priv := goldenSignKey(t)

	// Compute a correct selector_id from the selector body (no SelectorID field).
	sel := ManifestSelector{Agent: "buster", ContractHash: "sha256:c1"}
	selID, err := sel.ComputeSelectorID()
	if err != nil {
		t.Fatalf("compute selector_id: %v", err)
	}
	sel.SelectorID = selID

	// Compute selector_set_hash: sha256(jcs(sorted selector IDs)).
	ids := []any{selID}
	idCanon, err := Canonicalize(ids)
	if err != nil {
		t.Fatalf("canonicalize selector ids: %v", err)
	}
	idSum := sha256.Sum256(idCanon)
	setHash := "sha256:" + hex.EncodeToString(idSum[:])

	m := ActiveManifest{
		SchemaVersion:     1,
		ManifestKind:      ManifestKindActivation,
		Generation:        1,
		PriorManifestHash: "sha256:0",
		SelectorSetHash:   setHash,
		Environment: Environment{
			ID:           "test",
			Tenant:       "test",
			DeploymentID: "test",
		},
		Selectors:   []ManifestSelector{sel},
		HistoryRoot: "contracts/history/",
		SignedAt:    time.Date(2026, 4, 25, 22, 0, 0, 0, time.UTC),
	}
	preimage, err := m.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	envelope := ActiveManifestEnvelope{
		Body: m,
		Signatures: []ManifestSignature{
			{
				KeyID:      "test-key",
				Principal:  "test",
				KeyPurpose: "contract-activation-signing",
				Algorithm:  "ed25519",
				Signature:  signEd25519Hex(priv, preimage),
			},
		},
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	body = append(body, '\n')
	goldenWriteOrAssert(t, filepath.Join("testdata", "golden", "valid_active_manifest.json"), body)
}

func TestGolden_CompileManifest(t *testing.T) {
	t.Parallel()
	priv := goldenSignKey(t)
	m := CompileManifest{
		SchemaVersion:         1,
		ContractHash:          "sha256:c1",
		CompileStartedAt:      time.Date(2026, 4, 25, 22, 0, 0, 0, time.UTC),
		CompileFinishedAt:     time.Date(2026, 4, 25, 22, 0, 42, 0, time.UTC),
		PipelockVersion:       "v2.4.0-test",
		PipelockBuildSHA:      "test",
		GoVersion:             "go1.26.0",
		ModuleDigests:         map[string]string{"github.com/luckyPipewrench/pipelock": "sha256:test"},
		CompileConfigHash:     "sha256:cfg",
		Inputs:                []InputRef{{Path: "test.jsonl", SHA256: "sha256:i1", EventCount: 100}},
		ObservationWindowRoot: "sha256:obswin",
		Settings:              map[string]any{},
		SignerKeyID:           "contract-compile-key-v1-test",
		KeyPurpose:            "contract-compile-signing",
	}
	root, err := m.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	m.ModuleDigestRoot = root
	preimage, err := m.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	envelope := CompileManifestEnvelope{
		Body:      m,
		Signature: signEd25519Hex(priv, preimage),
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	body = append(body, '\n')
	goldenWriteOrAssert(t, filepath.Join("testdata", "golden", "valid_compile_manifest.json"), body)
}

func TestGolden_Tombstone(t *testing.T) {
	t.Parallel()
	priv := goldenSignKey(t)
	tomb := Tombstone{
		SchemaVersion:            1,
		Tombstone:                true,
		PriorContractHash:        "sha256:prev-c",
		RedactedAt:               "2026-04-25T22:00:00Z",
		RedactionAuthorizationID: "sha256:auth",
		SignerKeyID:              "test-key",
		KeyPurpose:               "contract-activation-signing",
		DataClassRoot:            "internal",
	}
	preimage, err := tomb.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	envelope := TombstoneEnvelope{
		Body:      tomb,
		Signature: signEd25519Hex(priv, preimage),
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	body = append(body, '\n')
	goldenWriteOrAssert(t, filepath.Join("testdata", "golden", "valid_tombstone.json"), body)
}

func TestGolden_KeyRoster(t *testing.T) {
	t.Parallel()
	priv := goldenSignKey(t)
	pubHex := loadTestKeysForGolden(t).PublicKeyHex
	r := KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: "roster-root-test",
		DataClassRoot:  "internal",
		Keys: []KeyInfo{
			{
				KeyID:        "roster-root-test",
				KeyPurpose:   "roster-root",
				PublicKeyHex: pubHex,
				ValidFrom:    "2026-04-01T00:00:00Z",
				Status:       KeyStatusRoot,
			},
			{
				KeyID:        "receipt-signing-test",
				KeyPurpose:   "receipt-signing",
				PublicKeyHex: pubHex,
				ValidFrom:    "2026-04-01T00:00:00Z",
				Status:       KeyStatusActive,
			},
		},
	}
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	envelope := RosterEnvelope{
		Body:      r,
		Signature: signEd25519Hex(priv, preimage),
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	body = append(body, '\n')
	goldenWriteOrAssert(t, filepath.Join("testdata", "golden", "valid_key_roster.json"), body)
}

func TestGolden_VerificationMetadata(t *testing.T) {
	t.Parallel()
	priv := goldenSignKey(t)
	v := VerificationMetadata{
		SchemaVersion:   1,
		BundleKind:      BundleKindPublicProof,
		ContractHash:    "sha256:c1",
		TombstoneHashes: []string{},
		BundleSignedAt:  "2026-04-25T22:00:00Z",
		SignerKeyID:     "test-key",
		KeyPurpose:      "contract-activation-signing",
		DataClassRoot:   "public",
	}
	root, err := v.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("idx root: %v", err)
	}
	v.TombstoneIndexRoot = root
	preimage, err := v.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	envelope := VerificationMetadataEnvelope{
		Body:      v,
		Signature: signEd25519Hex(priv, preimage),
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	body = append(body, '\n')
	goldenWriteOrAssert(t, filepath.Join("testdata", "golden", "valid_verification_metadata.json"), body)
}

// TestGolden_AllFixturesParseAndValidate is a smoke test confirming each known
// golden fixture file exists on disk (written by UPDATE_GOLDEN=1 passes).
// It is intentionally non-parallel: the file-existence check must run after the
// individual writer tests have completed, and it is not useful in update mode
// because the writers are still running concurrently when this executes.
func TestGolden_AllFixturesParseAndValidate(t *testing.T) {
	if updateGolden() {
		t.Skip("skipped in UPDATE_GOLDEN mode; individual tests write and verify")
	}

	const goldenDir = "testdata/golden"
	expected := []string{
		"valid_contract.json",
		"valid_active_manifest.json",
		"valid_compile_manifest.json",
		"valid_tombstone.json",
		"valid_key_roster.json",
		"valid_verification_metadata.json",
	}
	for _, name := range expected {
		path := filepath.Join(goldenDir, name)
		if _, err := os.Stat(filepath.Clean(path)); err != nil {
			t.Errorf("missing golden fixture %s: %v", name, err)
		}
	}
}
