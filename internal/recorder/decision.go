// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// DecisionRecordVersion is the current decision record schema version.
	DecisionRecordVersion = 1
	// DecisionRecordType is the typed identifier for decision record payloads.
	DecisionRecordType = "decision_record"

	decisionSignaturePrefix = "ed25519:"
	decisionEntryType       = "decision"
)

// DecisionRecord is a signed proof for an enforcement verdict.
type DecisionRecord struct {
	Version        int             `json:"version"`
	Type           string          `json:"type"`
	SessionID      string          `json:"session_id"`
	ManifestRef    string          `json:"manifest_ref,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
	Verdict        string          `json:"verdict"`
	ScannerResult  ScannerEvidence `json:"scanner_result"`
	PolicyRule     PolicyEvidence  `json:"policy_rule"`
	RequestContext RequestEvidence `json:"request_context"`
	Signature      string          `json:"signature,omitempty"`
}

// ScannerEvidence records scanner context for a verdict.
type ScannerEvidence struct {
	Layer      string `json:"layer"`
	Pattern    string `json:"pattern,omitempty"`
	MatchText  string `json:"match_text,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// PolicyEvidence records the policy source for a verdict.
type PolicyEvidence struct {
	Source  string `json:"source"`
	Section string `json:"section,omitempty"`
	Action  string `json:"action,omitempty"`
}

// RequestEvidence records request context for a verdict.
type RequestEvidence struct {
	Transport string `json:"transport"`
	ToolName  string `json:"tool_name,omitempty"`
	Direction string `json:"direction,omitempty"`
}

// Normalize returns a copy with required defaults applied.
func (dr DecisionRecord) Normalize() DecisionRecord {
	normalized := dr
	if normalized.Version == 0 {
		normalized.Version = DecisionRecordVersion
	}
	if normalized.Type == "" {
		normalized.Type = DecisionRecordType
	}
	if normalized.Timestamp.IsZero() {
		normalized.Timestamp = time.Now().UTC()
	} else {
		normalized.Timestamp = normalized.Timestamp.UTC()
	}
	return normalized
}

// Validate checks required fields and schema compatibility.
func (dr DecisionRecord) Validate() error {
	if dr.Version != DecisionRecordVersion {
		return fmt.Errorf("unsupported decision record version %d (expected %d)", dr.Version, DecisionRecordVersion)
	}
	if dr.Type != DecisionRecordType {
		return fmt.Errorf("invalid decision record type %q", dr.Type)
	}
	if dr.SessionID == "" {
		return errors.New("decision record session_id is required")
	}
	if dr.Verdict == "" {
		return errors.New("decision record verdict is required")
	}
	if dr.RequestContext.Transport == "" {
		return errors.New("decision record request_context.transport is required")
	}
	return nil
}

// Sign signs the record with Ed25519 over SHA-256(canonical JSON without signature).
func (dr DecisionRecord) Sign(privKey ed25519.PrivateKey) (DecisionRecord, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return DecisionRecord{}, errors.New("invalid private key")
	}

	normalized := dr.Normalize()
	if err := normalized.Validate(); err != nil {
		return DecisionRecord{}, err
	}

	data, err := normalized.signable()
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("marshal for signing: %w", err)
	}

	sum := sha256.Sum256(data)
	sig := ed25519.Sign(privKey, sum[:])
	normalized.Signature = decisionSignaturePrefix + hex.EncodeToString(sig)
	return normalized, nil
}

// Verify validates and verifies the detached signature field.
func (dr DecisionRecord) Verify(pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}

	normalized := dr.Normalize()
	if err := normalized.Validate(); err != nil {
		return err
	}
	if normalized.Signature == "" {
		return errors.New("decision record has no signature")
	}
	if !strings.HasPrefix(normalized.Signature, decisionSignaturePrefix) {
		return errors.New("invalid signature format")
	}

	sigHex := strings.TrimPrefix(normalized.Signature, decisionSignaturePrefix)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	data, err := normalized.signable()
	if err != nil {
		return fmt.Errorf("marshal for verification: %w", err)
	}
	sum := sha256.Sum256(data)
	if !ed25519.Verify(pubKey, sum[:], sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func (dr DecisionRecord) signable() ([]byte, error) {
	noSig := dr
	noSig.Signature = ""
	return json.Marshal(noSig)
}
