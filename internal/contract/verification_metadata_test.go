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
