// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

const (
	testModulePath    = "github.com/luckyPipewrench/pipelock"
	testModuleDigest  = "sha256:abc123"
	testModulePath2   = "golang.org/x/crypto"
	testModuleDigest2 = "sha256:def456"
)

func baseCompileManifest() CompileManifest {
	digests := map[string]string{
		testModulePath:  testModuleDigest,
		testModulePath2: testModuleDigest2,
	}
	root, _ := CompileManifest{ModuleDigests: digests}.ComputeModuleDigestRoot()
	return CompileManifest{
		SchemaVersion:         1,
		ContractHash:          "sha256:c0ffee",
		PipelockVersion:       "v2.4.0",
		PipelockBuildSHA:      "deadbeef",
		GoVersion:             "go1.25.0",
		ModuleDigestRoot:      root,
		ModuleDigests:         digests,
		CompileConfigHash:     "sha256:00cc",
		ObservationWindowRoot: "sha256:00bb",
		SignerKeyID:           "key-1",
		KeyPurpose:            "contract-compile-signing",
	}
}

func TestCompileManifest_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	pa, err := m.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	pb, err := m.SignablePreimage()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(pa) != string(pb) {
		t.Errorf("preimage is non-deterministic")
	}
}

func TestCompileManifest_ComputeModuleDigestRoot_Deterministic(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	r1, err := m.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("first ComputeModuleDigestRoot: %v", err)
	}
	r2, err := m.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("second ComputeModuleDigestRoot: %v", err)
	}
	if r1 != r2 {
		t.Errorf("root is non-deterministic: %q vs %q", r1, r2)
	}
	if r1 == "" {
		t.Error("root is empty")
	}
}

func TestCompileManifest_ComputeModuleDigestRoot_KeyOrderInvariant(t *testing.T) {
	t.Parallel()
	// Build same digest map two ways; Go map iteration is non-deterministic so
	// we test the property with equivalent content maps (same keys+values).
	m1 := CompileManifest{
		ModuleDigests: map[string]string{
			testModulePath:  testModuleDigest,
			testModulePath2: testModuleDigest2,
		},
	}
	m2 := CompileManifest{
		ModuleDigests: map[string]string{
			testModulePath2: testModuleDigest2,
			testModulePath:  testModuleDigest,
		},
	}
	r1, err := m1.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("m1 ComputeModuleDigestRoot: %v", err)
	}
	r2, err := m2.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("m2 ComputeModuleDigestRoot: %v", err)
	}
	if r1 != r2 {
		t.Errorf("key insertion order affected root: %q vs %q", r1, r2)
	}
}

func TestCompileManifest_Validate_RejectsMismatchedRoot(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	m.ModuleDigestRoot = "sha256:wrongvalue"
	if err := m.Validate(); !errors.Is(err, ErrModuleDigestRootMismatch) {
		t.Errorf("expected ErrModuleDigestRootMismatch, got %v", err)
	}
}

func TestCompileManifest_Validate_AcceptsCorrectRoot(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	if err := m.Validate(); err != nil {
		t.Errorf("expected nil error for correct root, got %v", err)
	}
}

func TestCompileManifest_Validate_RejectsBadSchemaVersion(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	m.SchemaVersion = 2
	if err := m.Validate(); !errors.Is(err, ErrCompileManifestSchemaVersion) {
		t.Errorf("expected ErrCompileManifestSchemaVersion, got %v", err)
	}
}

func TestCompileManifest_Validate_RejectsDisallowedTopLevelKey(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	m.Settings = map[string]any{"escrow_keys": "secret"}
	if err := m.Validate(); !errors.Is(err, ErrCompileSettingsDisallowedKey) {
		t.Errorf("got %v, want ErrCompileSettingsDisallowedKey", err)
	}
}

func TestCompileManifest_Validate_RejectsDisallowedPrivacyKey(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	m.Settings = map[string]any{
		"privacy": map[string]any{"raw_pii_storage": "yes"},
	}
	if err := m.Validate(); !errors.Is(err, ErrCompileSettingsDisallowedKey) {
		t.Errorf("got %v, want ErrCompileSettingsDisallowedKey", err)
	}
}

func TestCompileManifest_Validate_AcceptsAllowedSettings(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	m.Settings = map[string]any{
		"confidence":    map[string]any{"min": "0.95"},
		"normalization": map[string]any{},
		"privacy":       map[string]any{"default_data_class": "internal"},
		"redaction": map[string]any{
			"public_allowlist": []any{},
			"salt_hash":        map[string]any{"salt_epoch": "1"},
		},
	}
	if err := m.Validate(); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestCompileManifest_Validate_RejectsDisallowedSaltHashKey(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	m.Settings = map[string]any{
		"redaction": map[string]any{
			"salt_hash": map[string]any{"raw_salt_value": "exposed"},
		},
	}
	if err := m.Validate(); !errors.Is(err, ErrCompileSettingsDisallowedKey) {
		t.Errorf("got %v, want ErrCompileSettingsDisallowedKey", err)
	}
}

func TestCompileManifest_Validate_RejectsDisallowedRedactionKey(t *testing.T) {
	t.Parallel()
	m := baseCompileManifest()
	m.Settings = map[string]any{
		"redaction": map[string]any{"secret_sink": "exfil"},
	}
	if err := m.Validate(); !errors.Is(err, ErrCompileSettingsDisallowedKey) {
		t.Errorf("got %v, want ErrCompileSettingsDisallowedKey", err)
	}
}

func TestCompileManifest_SignablePreimage_MarshalError(t *testing.T) {
	t.Parallel()
	// Settings is map[string]any; a channel value makes json.Marshal fail,
	// exercising the marshal error branch in SignablePreimage.
	m := CompileManifest{
		Settings: map[string]any{"ch": make(chan int)},
	}
	_, err := m.SignablePreimage()
	if err == nil {
		t.Error("expected error from SignablePreimage with unmarshalable Settings, got nil")
	}
}
