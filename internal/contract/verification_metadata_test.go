// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

func baseVerificationMetadata() VerificationMetadata {
	hashes := []string{
		"sha256:aaaa",
		"sha256:bbbb",
	}
	vm := VerificationMetadata{
		TombstoneHashes: hashes,
	}
	root, _ := vm.ComputeTombstoneIndexRoot()
	return VerificationMetadata{
		SchemaVersion:      1,
		BundleKind:         BundleKindPublicProof,
		ContractHash:       "sha256:c0ffee",
		TombstoneIndexRoot: root,
		TombstoneHashes:    hashes,
		BundleSignedAt:     "2026-04-26T00:00:00Z",
		SignerKeyID:        "key-1",
		KeyPurpose:         "contract-activation-signing",
		DataClassRoot:      "public",
	}
}

func TestVerificationMetadata_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	vm := baseVerificationMetadata()
	pa, err := vm.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	pb, err := vm.SignablePreimage()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(pa) != string(pb) {
		t.Errorf("preimage is non-deterministic")
	}
}

func TestVerificationMetadata_ComputeTombstoneIndexRoot_Empty(t *testing.T) {
	t.Parallel()
	vm := VerificationMetadata{TombstoneHashes: []string{}}
	r1, err := vm.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("ComputeTombstoneIndexRoot on empty list: %v", err)
	}
	if r1 == "" {
		t.Error("empty list produced empty root")
	}
	// Deterministic across calls.
	r2, err := vm.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if r1 != r2 {
		t.Errorf("empty-list root is non-deterministic: %q vs %q", r1, r2)
	}
}

func TestVerificationMetadata_ComputeTombstoneIndexRoot_OrderInvariant(t *testing.T) {
	t.Parallel()
	vm1 := VerificationMetadata{TombstoneHashes: []string{"sha256:aaaa", "sha256:bbbb"}}
	vm2 := VerificationMetadata{TombstoneHashes: []string{"sha256:bbbb", "sha256:aaaa"}}
	r1, err := vm1.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("vm1 ComputeTombstoneIndexRoot: %v", err)
	}
	r2, err := vm2.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("vm2 ComputeTombstoneIndexRoot: %v", err)
	}
	if r1 != r2 {
		t.Errorf("insertion order affected tombstone_index_root: %q vs %q", r1, r2)
	}
}

func TestVerificationMetadata_Validate_AcceptsCorrectRoot(t *testing.T) {
	t.Parallel()
	vm := baseVerificationMetadata()
	if err := vm.Validate(); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestVerificationMetadata_Validate_RejectsMismatchedRoot(t *testing.T) {
	t.Parallel()
	vm := baseVerificationMetadata()
	vm.TombstoneIndexRoot = "sha256:wrongvalue"
	if err := vm.Validate(); !errors.Is(err, ErrTombstoneIndexRootMismatch) {
		t.Errorf("expected ErrTombstoneIndexRootMismatch, got %v", err)
	}
}

func TestVerificationMetadata_Validate_RejectsBadBundleKind(t *testing.T) {
	t.Parallel()
	vm := baseVerificationMetadata()
	vm.BundleKind = "unknown_bundle"
	if err := vm.Validate(); !errors.Is(err, ErrVerificationMetadataBundleKind) {
		t.Errorf("expected ErrVerificationMetadataBundleKind, got %v", err)
	}
}

func TestVerificationMetadata_Validate_RejectsBadSchemaVersion(t *testing.T) {
	t.Parallel()
	vm := baseVerificationMetadata()
	vm.SchemaVersion = 3
	if err := vm.Validate(); !errors.Is(err, ErrVerificationMetadataSchemaVersion) {
		t.Errorf("expected ErrVerificationMetadataSchemaVersion, got %v", err)
	}
}

func TestVerificationMetadata_Validate_RejectsInvalidDataClassRoot(t *testing.T) {
	t.Parallel()
	vm := baseVerificationMetadata()
	vm.DataClassRoot = invalidDataClassName
	if err := vm.Validate(); !errors.Is(err, ErrInvalidDataClass) {
		t.Errorf("expected ErrInvalidDataClass, got %v", err)
	}
}

func TestVerificationMetadata_Validate_RejectsRegulatedDataClassRoot(t *testing.T) {
	t.Parallel()
	vm := baseVerificationMetadata()
	vm.DataClassRoot = string(DataClassRegulated)
	if err := vm.Validate(); !errors.Is(err, ErrRegulatedField) {
		t.Errorf("expected ErrRegulatedField, got %v", err)
	}
}

func TestVerificationMetadata_ComputeTombstoneIndexRoot_NonEmpty(t *testing.T) {
	t.Parallel()
	// Non-empty list produces a root that differs from the empty-list root.
	empty := VerificationMetadata{TombstoneHashes: []string{}}
	emptyRoot, err := empty.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("empty ComputeTombstoneIndexRoot: %v", err)
	}

	nonempty := VerificationMetadata{TombstoneHashes: []string{
		"sha256:aabbcc",
		"sha256:ddeeff",
	}}
	nonemptyRoot, err := nonempty.ComputeTombstoneIndexRoot()
	if err != nil {
		t.Fatalf("non-empty ComputeTombstoneIndexRoot: %v", err)
	}

	if nonemptyRoot == emptyRoot {
		t.Error("non-empty root matches empty root; expected them to differ")
	}
	if nonemptyRoot == "" {
		t.Error("non-empty root is empty string")
	}
}

func TestVerificationMetadata_ComputeSelectorID_DefaultSelector(t *testing.T) {
	t.Parallel()
	// A selector with Default=true and no agent/agentGlob fields.
	s := ManifestSelector{
		Default:      true,
		ContractHash: "sha256:abc",
	}
	id, err := s.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	if id == "" {
		t.Error("expected non-empty selector_id, got empty")
	}
	// Verify it differs from a non-default selector with same contract hash.
	s2 := ManifestSelector{
		Agent:        "buster",
		ContractHash: "sha256:abc",
	}
	id2, err := s2.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID (agent selector): %v", err)
	}
	if id == id2 {
		t.Error("default selector and agent selector produced same ID")
	}
}
