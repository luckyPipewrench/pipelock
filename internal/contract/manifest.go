// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ManifestKindActivation is the only valid manifest_kind for v2.4.
const ManifestKindActivation = "activation_manifest"

var validManifestKinds = map[string]struct{}{
	ManifestKindActivation: {},
}

// ErrUnknownManifestKind rejects manifests with non-enumerated manifest_kind.
var ErrUnknownManifestKind = errors.New("unknown manifest_kind")

// ErrDuplicateSelectorID rejects manifests with duplicate selector_id values.
var ErrDuplicateSelectorID = errors.New("duplicate selector_id in manifest")

// ActiveManifest is the typed signable body of the active manifest.
type ActiveManifest struct {
	SchemaVersion     int                `json:"schema_version"`
	ManifestKind      string             `json:"manifest_kind"`
	Generation        uint64             `json:"generation"`
	PriorManifestHash string             `json:"prior_manifest_hash"`
	SelectorSetHash   string             `json:"selector_set_hash"`
	Environment       Environment        `json:"environment"`
	Selectors         []ManifestSelector `json:"selectors"`
	HistoryRoot       string             `json:"history_root"`
	RollbackTarget    string             `json:"rollback_target,omitempty"`
	SignedAt          time.Time          `json:"signed_at"`
}

// Environment binds a manifest to a specific deployment.
type Environment struct {
	ID           string `json:"id"`
	Tenant       string `json:"tenant"`
	DeploymentID string `json:"deployment_id"`
}

// ManifestSelector maps a selector to a contract.
type ManifestSelector struct {
	SelectorID   string `json:"selector_id"`
	Agent        string `json:"agent,omitempty"`
	AgentGlob    string `json:"agent_glob,omitempty"`
	Default      bool   `json:"default,omitempty"`
	ContractHash string `json:"contract_hash"`
}

// ManifestSignature is one entry in the dual-control signers array.
type ManifestSignature struct {
	KeyID      string `json:"key_id"`
	Principal  string `json:"principal"`
	KeyPurpose string `json:"key_purpose"`
	Algorithm  string `json:"algorithm"`
	Signature  string `json:"signature"`
}

// ActiveManifestEnvelope wraps body + detached signatures.
type ActiveManifestEnvelope struct {
	Body       ActiveManifest      `json:"body"`
	Signatures []ManifestSignature `json:"signatures"`
}

// Validate runs structural checks. Cryptographic verification is in verify.go.
func (m ActiveManifest) Validate() error {
	if _, ok := validManifestKinds[m.ManifestKind]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownManifestKind, m.ManifestKind)
	}
	seen := make(map[string]struct{}, len(m.Selectors))
	for _, s := range m.Selectors {
		if _, dup := seen[s.SelectorID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateSelectorID, s.SelectorID)
		}
		seen[s.SelectorID] = struct{}{}
	}
	return nil
}

// SignablePreimage returns JCS bytes over the manifest body with signatures excluded.
func (m ActiveManifest) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse manifest for canonicalization: %w", err)
	}
	return Canonicalize(tree)
}

// ComputeSelectorID derives the canonical selector_id from a selector body.
// Recipe: sha256(jcs(selector_without_selector_id)).
func (s ManifestSelector) ComputeSelectorID() (string, error) {
	body := ManifestSelector{
		Agent:        s.Agent,
		AgentGlob:    s.AgentGlob,
		Default:      s.Default,
		ContractHash: s.ContractHash,
		// SelectorID intentionally omitted.
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal selector: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return "", fmt.Errorf("parse selector for canonicalization: %w", err)
	}
	canon, err := Canonicalize(tree)
	if err != nil {
		return "", fmt.Errorf("canonicalize selector: %w", err)
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
