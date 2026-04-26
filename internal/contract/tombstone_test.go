// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

const (
	tombstoneKeyPurpose = "contract-activation-signing"
)

func baseTombstone() Tombstone {
	return Tombstone{
		SchemaVersion:            1,
		Tombstone:                true,
		PriorContractHash:        "sha256:deadc0de",
		RedactedAt:               "2026-04-26T00:00:00Z",
		RedactionAuthorizationID: "auth-001",
		SignerKeyID:              "key-1",
		KeyPurpose:               tombstoneKeyPurpose,
		DataClassRoot:            "internal",
	}
}

func TestTombstone_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	ts := baseTombstone()
	pa, err := ts.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	pb, err := ts.SignablePreimage()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(pa) != string(pb) {
		t.Errorf("preimage is non-deterministic")
	}
}

func TestTombstone_Validate_RejectsTombstoneFalse(t *testing.T) {
	t.Parallel()
	ts := baseTombstone()
	ts.Tombstone = false
	if err := ts.Validate(); !errors.Is(err, ErrTombstoneFlagFalse) {
		t.Errorf("expected ErrTombstoneFlagFalse, got %v", err)
	}
}

func TestTombstone_Validate_RejectsWrongKeyPurpose(t *testing.T) {
	t.Parallel()
	ts := baseTombstone()
	ts.KeyPurpose = "wrong-purpose"
	if err := ts.Validate(); !errors.Is(err, ErrTombstoneWrongKeyPurpose) {
		t.Errorf("expected ErrTombstoneWrongKeyPurpose, got %v", err)
	}
}

func TestTombstone_Validate_AcceptsCorrectShape(t *testing.T) {
	t.Parallel()
	ts := baseTombstone()
	if err := ts.Validate(); err != nil {
		t.Errorf("expected nil error for correct tombstone, got %v", err)
	}
}

func TestTombstone_Validate_RejectsBadSchemaVersion(t *testing.T) {
	t.Parallel()
	ts := baseTombstone()
	ts.SchemaVersion = 2
	if err := ts.Validate(); !errors.Is(err, ErrTombstoneSchemaVersion) {
		t.Errorf("expected ErrTombstoneSchemaVersion, got %v", err)
	}
}
