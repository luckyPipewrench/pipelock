// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
	"time"
)

func TestActiveManifest_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	m := ActiveManifest{
		SchemaVersion:     1,
		ManifestKind:      ManifestKindActivation,
		Generation:        47,
		PriorManifestHash: "sha256:0c",
		SelectorSetHash:   "sha256:5a",
		Environment:       Environment{ID: "production", Tenant: "acme", DeploymentID: "ed25519:70b9"},
		Selectors: []ManifestSelector{
			{SelectorID: "sha256:s1", Agent: "buster", ContractHash: "sha256:abc"},
		},
		HistoryRoot:    "contracts/history/",
		RollbackTarget: "sha256:prev",
		SignedAt:       time.Date(2026, 4, 25, 22, 0, 0, 0, time.UTC),
	}
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

func TestActiveManifest_RecomputeSelectorID(t *testing.T) {
	t.Parallel()
	s := ManifestSelector{Agent: "buster", ContractHash: "sha256:abc"}
	id, err := s.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	if id == "" {
		t.Error("empty selector_id")
	}
	other := ManifestSelector{Agent: "buster", ContractHash: "sha256:def"}
	id2, err := other.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	if id == id2 {
		t.Error("different contract_hash produced same selector_id")
	}
}

func TestActiveManifest_DuplicateSelectorIDsReject(t *testing.T) {
	t.Parallel()
	m := ActiveManifest{
		SchemaVersion: 1,
		ManifestKind:  ManifestKindActivation,
		Generation:    1,
		Selectors: []ManifestSelector{
			{SelectorID: "sha256:dup", Agent: "a", ContractHash: "sha256:1"},
			{SelectorID: "sha256:dup", Agent: "b", ContractHash: "sha256:2"},
		},
	}
	if err := m.Validate(); err == nil {
		t.Error("expected duplicate selector_id rejection, got nil")
	}
}

func TestActiveManifest_RejectsUnknownManifestKind(t *testing.T) {
	t.Parallel()
	m := ActiveManifest{SchemaVersion: 1, ManifestKind: "nonsense_manifest"}
	if err := m.Validate(); err == nil {
		t.Error("expected unknown manifest_kind rejection")
	}
}

func TestActiveManifest_Validate_RejectsBadSchemaVersion(t *testing.T) {
	t.Parallel()
	m := ActiveManifest{SchemaVersion: 99, ManifestKind: ManifestKindActivation}
	if err := m.Validate(); !errors.Is(err, ErrManifestSchemaVersion) {
		t.Errorf("got %v, want ErrManifestSchemaVersion", err)
	}
}

func TestActiveManifest_Validate_RejectsSelectorIDMismatch(t *testing.T) {
	t.Parallel()
	m := ActiveManifest{
		SchemaVersion: 1,
		ManifestKind:  ManifestKindActivation,
		Selectors: []ManifestSelector{
			{SelectorID: "sha256:claimed-but-wrong", Agent: "a", ContractHash: "sha256:c1"},
		},
	}
	if err := m.Validate(); !errors.Is(err, ErrManifestSelectorIDMismatch) {
		t.Errorf("got %v, want ErrManifestSelectorIDMismatch", err)
	}
}

func TestActiveManifest_Validate_AcceptsRecomputedSelectorID(t *testing.T) {
	t.Parallel()
	sel := ManifestSelector{Agent: "buster", ContractHash: "sha256:c1"}
	id, err := sel.ComputeSelectorID()
	if err != nil {
		t.Fatalf("compute id: %v", err)
	}
	sel.SelectorID = id
	m := ActiveManifest{
		SchemaVersion: 1,
		ManifestKind:  ManifestKindActivation,
		Selectors:     []ManifestSelector{sel},
	}
	if err := m.Validate(); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestActiveManifest_Validate_RejectsSelectorSetHashMismatch(t *testing.T) {
	t.Parallel()
	sel := ManifestSelector{Agent: "buster", ContractHash: "sha256:c1"}
	id, err := sel.ComputeSelectorID()
	if err != nil {
		t.Fatalf("compute id: %v", err)
	}
	sel.SelectorID = id
	m := ActiveManifest{
		SchemaVersion:   1,
		ManifestKind:    ManifestKindActivation,
		Selectors:       []ManifestSelector{sel},
		SelectorSetHash: "sha256:wrong",
	}
	if err := m.Validate(); !errors.Is(err, ErrManifestSelectorSetHashMismatch) {
		t.Errorf("got %v, want ErrManifestSelectorSetHashMismatch", err)
	}
}

func TestActiveManifest_Validate_AcceptsValidManifest(t *testing.T) {
	t.Parallel()
	// Compute correct selector_ids so Validate passes identity checks.
	s1 := ManifestSelector{Agent: "buster", ContractHash: "sha256:c1"}
	id1, err := s1.ComputeSelectorID()
	if err != nil {
		t.Fatalf("compute id1: %v", err)
	}
	s1.SelectorID = id1

	s2 := ManifestSelector{Agent: "rook", ContractHash: "sha256:c2"}
	id2, err := s2.ComputeSelectorID()
	if err != nil {
		t.Fatalf("compute id2: %v", err)
	}
	s2.SelectorID = id2

	m := ActiveManifest{
		SchemaVersion: 1,
		ManifestKind:  ManifestKindActivation,
		Generation:    1,
		Selectors:     []ManifestSelector{s1, s2},
	}
	if err := m.Validate(); err != nil {
		t.Errorf("expected nil for valid manifest, got %v", err)
	}
}
