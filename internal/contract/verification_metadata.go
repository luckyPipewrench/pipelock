// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// BundleKindPublicProof is the only valid bundle_kind for VerificationMetadata.
const BundleKindPublicProof = "public_proof_bundle"

// ErrVerificationMetadataSchemaVersion rejects VerificationMetadata with unsupported schema versions.
var ErrVerificationMetadataSchemaVersion = errors.New("unsupported verification_metadata schema_version; expected 1")

// ErrVerificationMetadataBundleKind rejects VerificationMetadata with an unsupported bundle_kind.
var ErrVerificationMetadataBundleKind = errors.New("unsupported bundle_kind; expected \"public_proof_bundle\"")

// ErrTombstoneIndexRootMismatch rejects VerificationMetadata whose tombstone_index_root
// does not match the value derived from tombstone_hashes.
var ErrTombstoneIndexRootMismatch = errors.New("tombstone_index_root does not match computed value")

// schemaVersionVerificationMetadata is the current VerificationMetadata schema version.
const schemaVersionVerificationMetadata = 1

// VerificationMetadata is the typed signable body of a public proof bundle header.
// It binds a contract hash and a sorted index of tombstone hashes into a
// single JCS-canonicalized structure suitable for public distribution.
type VerificationMetadata struct {
	SchemaVersion      int      `json:"schema_version"`
	BundleKind         string   `json:"bundle_kind"`
	ContractHash       string   `json:"contract_hash"`
	TombstoneIndexRoot string   `json:"tombstone_index_root"`
	TombstoneHashes    []string `json:"tombstone_hashes"`
	BundleSignedAt     string   `json:"bundle_signed_at"`
	SignerKeyID        string   `json:"signer_key_id"`
	KeyPurpose         string   `json:"key_purpose"`
	DataClassRoot      string   `json:"data_class_root"`
}

// VerificationMetadataEnvelope wraps a VerificationMetadata body with its detached signature.
type VerificationMetadataEnvelope struct {
	Body      VerificationMetadata `json:"body"`
	Signature string               `json:"signature"`
}

// SignablePreimage returns JCS bytes over the metadata body.
// The signature is detached (stored in VerificationMetadataEnvelope.Signature).
func (v VerificationMetadata) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal verification_metadata: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse verification_metadata for canonicalization: %w", err)
	}
	return Canonicalize(tree)
}

// ComputeTombstoneIndexRoot derives the canonical tombstone_index_root from v.TombstoneHashes.
// Recipe: sha256(jcs(sorted_tombstone_hashes)). Hashes are sorted lexicographically so
// the result is insertion-order-invariant. An empty list produces a valid, stable root.
func (v VerificationMetadata) ComputeTombstoneIndexRoot() (string, error) {
	// Sort a copy so we do not mutate the receiver's slice.
	sorted := make([]string, len(v.TombstoneHashes))
	copy(sorted, v.TombstoneHashes)
	sort.Strings(sorted)

	raw, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("marshal tombstone_hashes: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return "", fmt.Errorf("parse tombstone_hashes for canonicalization: %w", err)
	}
	canon, err := Canonicalize(tree)
	if err != nil {
		return "", fmt.Errorf("canonicalize tombstone_hashes: %w", err)
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Validate runs structural checks on the VerificationMetadata.
// Cryptographic signature verification is in verify.go.
func (v VerificationMetadata) Validate() error {
	if v.SchemaVersion != schemaVersionVerificationMetadata {
		return fmt.Errorf("%w: got %d", ErrVerificationMetadataSchemaVersion, v.SchemaVersion)
	}
	if v.BundleKind != BundleKindPublicProof {
		return fmt.Errorf("%w: got %q", ErrVerificationMetadataBundleKind, v.BundleKind)
	}
	computed, err := v.ComputeTombstoneIndexRoot()
	if err != nil {
		return fmt.Errorf("compute tombstone_index_root: %w", err)
	}
	if v.TombstoneIndexRoot != computed {
		return fmt.Errorf("%w: stored %q, computed %q", ErrTombstoneIndexRootMismatch, v.TombstoneIndexRoot, computed)
	}
	return nil
}
