// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

const (
	testRootKeyID  = "root-key-1"
	testRootKeyHex = "70b991eb77816fc4ef0ae6a54d8a4119ddc5a16c9711c332c39e743079f6c63e"
)

func baseKeyRoster() KeyRoster {
	return KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: testRootKeyID,
		Keys: []KeyInfo{
			{
				KeyID:        testRootKeyID,
				KeyPurpose:   "contract-activation-signing",
				PublicKeyHex: testRootKeyHex,
				ValidFrom:    "2026-01-01T00:00:00Z",
				ValidUntil:   nil,
				Status:       KeyStatusRoot,
				Principal:    "josh",
			},
		},
		DataClassRoot: "internal",
	}
}

func TestKeyRoster_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	pa, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	pb, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(pa) != string(pb) {
		t.Errorf("preimage is non-deterministic")
	}
}

func TestKeyRoster_Validate_AcceptsValidRoster(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	if err := r.Validate(); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestKeyRoster_Validate_RejectsMissingRoot_NotInKeys(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	r.RosterSignedBy = "nonexistent-key"
	if err := r.Validate(); !errors.Is(err, ErrRosterMissingRoot) {
		t.Errorf("expected ErrRosterMissingRoot when signer not in keys, got %v", err)
	}
}

func TestKeyRoster_Validate_RejectsMissingRoot_WrongStatus(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	// RosterSignedBy points to a key that exists but has status=active, not root.
	r.Keys[0].Status = KeyStatusActive
	if err := r.Validate(); !errors.Is(err, ErrRosterMissingRoot) {
		t.Errorf("expected ErrRosterMissingRoot when signer status != root, got %v", err)
	}
}

func TestKeyRoster_Validate_RejectsDuplicateKeyID(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	// Add a second key with the same ID.
	dup := r.Keys[0]
	dup.Status = KeyStatusActive
	r.Keys = append(r.Keys, dup)
	if err := r.Validate(); !errors.Is(err, ErrRosterDuplicateKeyID) {
		t.Errorf("expected ErrRosterDuplicateKeyID, got %v", err)
	}
}

func TestKeyRoster_Validate_RejectsBadSchemaVersion(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	r.SchemaVersion = 0
	if err := r.Validate(); !errors.Is(err, ErrRosterSchemaVersion) {
		t.Errorf("expected ErrRosterSchemaVersion, got %v", err)
	}
}

func TestKeyRoster_Validate_RejectsInvalidDataClassRoot(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	r.DataClassRoot = invalidDataClassName
	if err := r.Validate(); !errors.Is(err, ErrInvalidDataClass) {
		t.Errorf("expected ErrInvalidDataClass, got %v", err)
	}
}

func TestKeyRoster_Validate_RejectsRegulatedDataClassRoot(t *testing.T) {
	t.Parallel()
	r := baseKeyRoster()
	r.DataClassRoot = string(DataClassRegulated)
	if err := r.Validate(); !errors.Is(err, ErrRegulatedField) {
		t.Errorf("expected ErrRegulatedField, got %v", err)
	}
}
