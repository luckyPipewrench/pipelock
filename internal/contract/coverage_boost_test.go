// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

// validateSettingsAllowlist rejects scalar values for structured settings
// namespaces. Otherwise an allowed top-level key could smuggle arbitrary text.

func TestCompileManifestAllowlist_PrivacyNonMapValueRejected(t *testing.T) {
	t.Parallel()
	m := CompileManifest{
		SchemaVersion: 1,
		ModuleDigests: map[string]string{},
		Settings:      map[string]any{"privacy": "scalar-not-map"},
	}
	root, err := m.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	m.ModuleDigestRoot = root
	if err := m.Validate(); !errors.Is(err, ErrCompileSettingsDisallowedKey) {
		t.Errorf("got %v, want ErrCompileSettingsDisallowedKey", err)
	}
}

func TestCompileManifestAllowlist_RedactionNonMapValueRejected(t *testing.T) {
	t.Parallel()
	m := CompileManifest{
		SchemaVersion: 1,
		ModuleDigests: map[string]string{},
		Settings:      map[string]any{"redaction": "scalar-not-map"},
	}
	root, err := m.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	m.ModuleDigestRoot = root
	if err := m.Validate(); !errors.Is(err, ErrCompileSettingsDisallowedKey) {
		t.Errorf("got %v, want ErrCompileSettingsDisallowedKey", err)
	}
}

func TestCompileManifestAllowlist_SaltHashNonMapValueRejected(t *testing.T) {
	t.Parallel()
	m := CompileManifest{
		SchemaVersion: 1,
		ModuleDigests: map[string]string{},
		Settings: map[string]any{
			"redaction": map[string]any{
				"salt_hash": "scalar-not-map",
			},
		},
	}
	root, err := m.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	m.ModuleDigestRoot = root
	if err := m.Validate(); !errors.Is(err, ErrCompileSettingsDisallowedKey) {
		t.Errorf("got %v, want ErrCompileSettingsDisallowedKey", err)
	}
}

// Contract.Validate covers the marshal-then-parse path. Exercise the happy
// path with a non-empty selector to reach more branches in the walker.

func TestContract_Validate_CoverageHappyPathWithSelector(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{"selector.agent": "internal"},
		Selector:         Selector{Agent: "buster", SelectorID: "sha256:any"},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("happy path failed: %v", err)
	}
}

// ParseYAMLStrict happy-path with a sequence-of-maps body, exercising the
// SequenceNode → MappingNode recursion in walkRejectBannedNodes.

func TestParseYAMLStrict_AcceptsSequenceOfMaps(t *testing.T) {
	t.Parallel()
	in := []byte("items:\n  - name: a\n    value: 1\n  - name: b\n    value: 2\n")
	got, err := ParseYAMLStrict(in)
	if err != nil {
		t.Fatalf("ParseYAMLStrict: %v", err)
	}
	if got == nil {
		t.Fatal("got nil, want map")
	}
}

// ManifestSelector.ComputeSelectorID with a glob/default-match selector:
// covers the AgentGlob and Default fields in the marshalled signable body.

func TestComputeSelectorID_WithAgentGlob(t *testing.T) {
	t.Parallel()
	s := ManifestSelector{AgentGlob: "buster-*", ContractHash: "sha256:abc"}
	id, err := s.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	if id == "" {
		t.Error("empty selector_id")
	}
}

func TestComputeSelectorID_WithDefaultFlag(t *testing.T) {
	t.Parallel()
	s := ManifestSelector{Default: true, ContractHash: "sha256:abc"}
	id, err := s.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	if id == "" {
		t.Error("empty selector_id")
	}
}

// VerificationMetadata.ComputeTombstoneIndexRoot with a single hash:
// exercises the path between empty and many-element cases.

func TestVerificationMetadata_ComputeTombstoneIndexRoot_SingleHash(t *testing.T) {
	t.Parallel()
	v := VerificationMetadata{TombstoneHashes: []string{"sha256:single"}}
	root, err := v.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("ComputeTombstoneIndexRoot: %v", err)
	}
	if root == "" {
		t.Error("empty root for single-hash list")
	}
}

// Multi-hash tombstone index covers the order-after-sort path.
func TestVerificationMetadata_ComputeTombstoneIndexRoot_MultiHashSorted(t *testing.T) {
	t.Parallel()
	v1 := VerificationMetadata{TombstoneHashes: []string{"sha256:b", "sha256:a", "sha256:c"}}
	v2 := VerificationMetadata{TombstoneHashes: []string{"sha256:c", "sha256:a", "sha256:b"}}
	r1, err := v1.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	r2, err := v2.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	if r1 != r2 {
		t.Errorf("order should not affect root after sort: %q vs %q", r1, r2)
	}
}

// CompileManifest.ComputeModuleDigestRoot with a multi-key map.
func TestCompileManifest_ComputeModuleDigestRoot_MultipleEntries(t *testing.T) {
	t.Parallel()
	m1 := CompileManifest{ModuleDigests: map[string]string{
		"github.com/luckyPipewrench/pipelock": "sha256:a",
		"github.com/spf13/cobra":              "sha256:b",
		"github.com/goccy/go-yaml":            "sha256:c",
	}}
	m2 := CompileManifest{ModuleDigests: map[string]string{
		"github.com/goccy/go-yaml":            "sha256:c",
		"github.com/luckyPipewrench/pipelock": "sha256:a",
		"github.com/spf13/cobra":              "sha256:b",
	}}
	r1, err := m1.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("m1: %v", err)
	}
	r2, err := m2.ComputeModuleDigestRoot()
	if err != nil {
		t.Fatalf("m2: %v", err)
	}
	if r1 != r2 {
		t.Errorf("map iteration order leaked into root: %q vs %q", r1, r2)
	}
}

// Sentinel errors should be distinguishable from generic errors.
func TestSentinelErrors_AreDistinct(t *testing.T) {
	t.Parallel()
	if errors.Is(ErrContractKind, ErrContractSchemaVersion) {
		t.Error("ErrContractKind should not match ErrContractSchemaVersion")
	}
	if errors.Is(ErrManifestSelectorIDMismatch, ErrManifestSelectorSetHashMismatch) {
		t.Error("ErrManifestSelectorIDMismatch should not match ErrManifestSelectorSetHashMismatch")
	}
}
