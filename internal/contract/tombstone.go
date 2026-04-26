// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrTombstoneSchemaVersion rejects Tombstones with unsupported schema versions.
var ErrTombstoneSchemaVersion = errors.New("unsupported tombstone schema_version; expected 1")

// ErrTombstoneFlagFalse rejects Tombstones where the tombstone flag is false.
var ErrTombstoneFlagFalse = errors.New("tombstone flag must be true")

// ErrTombstoneWrongKeyPurpose rejects Tombstones signed with the wrong key purpose.
var ErrTombstoneWrongKeyPurpose = errors.New("tombstone key_purpose must be \"contract-activation-signing\"")

// schemaVersionTombstone is the current Tombstone schema version.
const schemaVersionTombstone = 1

// keyPurposeTombstone is the required key_purpose for Tombstone signers.
const keyPurposeTombstone = "contract-activation-signing"

// dataClassRootTombstoneDefault is the default data_class_root for tombstones.
const dataClassRootTombstoneDefault = "internal"

// Tombstone is the typed signable body of a contract tombstone record.
// A tombstone marks a prior contract as redacted and prevents its reactivation.
type Tombstone struct {
	SchemaVersion            int    `json:"schema_version"`
	Tombstone                bool   `json:"tombstone"`
	PriorContractHash        string `json:"prior_contract_hash"`
	RedactedAt               string `json:"redacted_at"`
	RedactionAuthorizationID string `json:"redaction_authorization_id"`
	SignerKeyID              string `json:"signer_key_id"`
	KeyPurpose               string `json:"key_purpose"`
	DataClassRoot            string `json:"data_class_root"`
}

// TombstoneEnvelope wraps a Tombstone body with its detached signature.
type TombstoneEnvelope struct {
	Body      Tombstone `json:"body"`
	Signature string    `json:"signature"`
}

// NewTombstone constructs a Tombstone with required defaults applied:
// Tombstone=true and DataClassRoot="internal".
func NewTombstone(priorContractHash, redactedAt, authorizationID, signerKeyID string) Tombstone {
	return Tombstone{
		SchemaVersion:            schemaVersionTombstone,
		Tombstone:                true,
		PriorContractHash:        priorContractHash,
		RedactedAt:               redactedAt,
		RedactionAuthorizationID: authorizationID,
		SignerKeyID:              signerKeyID,
		KeyPurpose:               keyPurposeTombstone,
		DataClassRoot:            dataClassRootTombstoneDefault,
	}
}

// SignablePreimage returns JCS bytes over the tombstone body.
// The signature is detached (stored in TombstoneEnvelope.Signature).
func (t Tombstone) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("marshal tombstone: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse tombstone for canonicalization: %w", err)
	}
	return Canonicalize(tree)
}

// Validate runs structural checks on the Tombstone.
// Cryptographic signature verification is in verify.go.
func (t Tombstone) Validate() error {
	if t.SchemaVersion != schemaVersionTombstone {
		return fmt.Errorf("%w: got %d", ErrTombstoneSchemaVersion, t.SchemaVersion)
	}
	if !t.Tombstone {
		return ErrTombstoneFlagFalse
	}
	if t.KeyPurpose != keyPurposeTombstone {
		return fmt.Errorf("%w: got %q", ErrTombstoneWrongKeyPurpose, t.KeyPurpose)
	}
	if _, err := validateDataClassRoot(t.DataClassRoot); err != nil {
		return err
	}
	return nil
}
