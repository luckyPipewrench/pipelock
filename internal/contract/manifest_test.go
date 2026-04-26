// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
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
