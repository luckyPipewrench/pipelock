// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Key status constants for KeyInfo.Status.
const (
	// KeyStatusActive marks a key that is in normal use.
	KeyStatusActive = "active"
	// KeyStatusRevoked marks a key that has been revoked and must not be trusted.
	KeyStatusRevoked = "revoked"
	// KeyStatusRoot marks a key that is authorised to sign the roster itself.
	KeyStatusRoot = "root"
)

// ErrRosterSchemaVersion rejects KeyRosters with unsupported schema versions.
var ErrRosterSchemaVersion = errors.New("unsupported key_roster schema_version; expected 1")

// ErrRosterMissingRoot rejects KeyRosters where roster_signed_by does not
// reference a key in Keys with status=root.
var ErrRosterMissingRoot = errors.New("roster_signed_by must reference a key with status=root")

// ErrRosterDuplicateKeyID rejects KeyRosters with duplicate key_id values.
var ErrRosterDuplicateKeyID = errors.New("duplicate key_id in key_roster")

// schemaVersionKeyRoster is the current KeyRoster schema version.
const schemaVersionKeyRoster = 1

// KeyInfo describes a single key entry in a KeyRoster.
type KeyInfo struct {
	KeyID        string  `json:"key_id"`
	KeyPurpose   string  `json:"key_purpose"`
	PublicKeyHex string  `json:"public_key_hex"`
	ValidFrom    string  `json:"valid_from"`
	ValidUntil   *string `json:"valid_until"` // null = no expiry
	Status       string  `json:"status"`
	Principal    string  `json:"principal,omitempty"`
}

// KeyRoster is the typed signable body of a key roster document.
// It carries the authoritative set of signing keys and is itself signed
// by the root key it names in roster_signed_by.
type KeyRoster struct {
	SchemaVersion  int       `json:"schema_version"`
	RosterSignedBy string    `json:"roster_signed_by"`
	Keys           []KeyInfo `json:"keys"`
	DataClassRoot  string    `json:"data_class_root"`
}

// RosterEnvelope wraps a KeyRoster body with its detached signature.
type RosterEnvelope struct {
	Body      KeyRoster `json:"body"`
	Signature string    `json:"signature"`
}

// SignablePreimage returns JCS bytes over the roster body.
// ValidUntil *string marshals to JSON null when nil; ParseJSONStrict
// preserves this as Go nil in the generic tree, which Canonicalize
// renders as the JSON literal null. Round-trip is correct.
func (r KeyRoster) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal key_roster: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse key_roster for canonicalization: %w", err)
	}
	return Canonicalize(tree)
}

// Validate runs structural checks on the KeyRoster.
// Cryptographic signature verification is in verify.go.
func (r KeyRoster) Validate() error {
	if r.SchemaVersion != schemaVersionKeyRoster {
		return fmt.Errorf("%w: got %d", ErrRosterSchemaVersion, r.SchemaVersion)
	}

	// Check for duplicate key IDs and simultaneously verify that
	// roster_signed_by references a root key.
	seen := make(map[string]struct{}, len(r.Keys))
	hasRoot := false
	for _, k := range r.Keys {
		if _, dup := seen[k.KeyID]; dup {
			return fmt.Errorf("%w: %q", ErrRosterDuplicateKeyID, k.KeyID)
		}
		seen[k.KeyID] = struct{}{}
		if k.KeyID == r.RosterSignedBy && k.Status == KeyStatusRoot {
			hasRoot = true
		}
	}
	if !hasRoot {
		return fmt.Errorf("%w: key_id %q not found with status %q", ErrRosterMissingRoot, r.RosterSignedBy, KeyStatusRoot)
	}
	return nil
}
