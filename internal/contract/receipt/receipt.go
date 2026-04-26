// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package receipt defines the EvidenceReceipt v2 envelope, the 13 typed payload
// structs, and the payload-kind → validator dispatch registry.
//
// The EvidenceReceipt envelope is the v2 replacement for the legacy ActionReceipt
// (v1). Payload dispatch happens at validation time, not at decode time: the
// Payload field stays json.RawMessage so the outer envelope can be decoded and
// routed before paying the cost of payload parsing.
//
// Signing uses Ed25519 PureEdDSA over a JCS-canonicalized preimage that excludes
// the Signature field. See SignablePreimage for the exact recipe.
package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// RecordType identifies the schema version of a receipt record.
type RecordType string

const (
	// RecordTypeActionV1 is the legacy action_receipt v1 record type.
	RecordTypeActionV1 RecordType = "action_receipt_v1"
	// RecordTypeEvidenceV2 is the v2 evidence receipt record type handled by this package.
	RecordTypeEvidenceV2 RecordType = "evidence_receipt_v2"
)

const (
	signatureAlgorithmEd25519 = "ed25519"
	signaturePrefixEd25519    = "ed25519:"
)

// PayloadKind identifies the payload structure carried inside an EvidenceReceipt.
type PayloadKind string

const (
	PayloadProxyDecision              PayloadKind = "proxy_decision"
	PayloadContractRatified           PayloadKind = "contract_ratified"
	PayloadContractPromoteIntent      PayloadKind = "contract_promote_intent"
	PayloadContractPromoteCommitted   PayloadKind = "contract_promote_committed"
	PayloadContractRollbackAuthorized PayloadKind = "contract_rollback_authorized"
	PayloadContractRollbackCommitted  PayloadKind = "contract_rollback_committed"
	PayloadContractDemoted            PayloadKind = "contract_demoted"
	PayloadContractExpired            PayloadKind = "contract_expired"
	PayloadContractDrift              PayloadKind = "contract_drift"
	PayloadShadowDelta                PayloadKind = "shadow_delta"
	PayloadOpportunityMissing         PayloadKind = "opportunity_missing"
	PayloadKeyRotation                PayloadKind = "key_rotation"
	PayloadContractRedactionRequest   PayloadKind = "contract_redaction_request"
)

// SignatureProof is the detached Ed25519 signature proof attached to an EvidenceReceipt.
// The Signature field is excluded from the signable preimage.
type SignatureProof struct {
	SignerKeyID string `json:"signer_key_id"`
	KeyPurpose  string `json:"key_purpose"`
	// Algorithm must be "ed25519".
	Algorithm string `json:"algorithm"`
	// Signature is "ed25519:<hex>" over jcs(receipt_without_signature).
	Signature string `json:"signature"`
}

// EvidenceReceipt is the v2 evidence receipt envelope.
// Payload holds a typed struct serialized as JSON; its structure is determined
// by PayloadKind and validated by the registry in registry.go.
type EvidenceReceipt struct {
	RecordType     RecordType  `json:"record_type"`
	ReceiptVersion int         `json:"receipt_version"`
	PayloadKind    PayloadKind `json:"payload_kind"`
	// EventID is a UUIDv7 uniquely identifying this receipt event.
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`

	Principal       string   `json:"principal,omitempty"`
	Actor           string   `json:"actor,omitempty"`
	DelegationChain []string `json:"delegation_chain,omitempty"`

	// Signature is the detached proof. It is excluded from SignablePreimage.
	Signature SignatureProof `json:"signature"`

	ChainSeq      uint64 `json:"chain_seq"`
	ChainPrevHash string `json:"chain_prev_hash"`

	ActiveManifestHash string `json:"active_manifest_hash,omitempty"`
	ContractHash       string `json:"contract_hash,omitempty"`
	SelectorID         string `json:"selector_id,omitempty"`
	ContractGeneration uint64 `json:"contract_generation,omitempty"`

	// Payload is the typed struct for this PayloadKind, serialized as JSON.
	// Dispatch to the appropriate typed validator happens in Validate().
	Payload json.RawMessage `json:"payload"`
}

// Validate performs structural validation of the envelope and dispatches to the
// registered payload validator for r.PayloadKind.
func (r EvidenceReceipt) Validate() error {
	if r.RecordType != RecordTypeEvidenceV2 {
		return fmt.Errorf("%w: got %q", ErrUnsupportedRecordType, r.RecordType)
	}
	if r.ReceiptVersion != 2 {
		return fmt.Errorf("%w: got %d", ErrWrongReceiptVersion, r.ReceiptVersion)
	}
	if r.EventID == "" {
		return fmt.Errorf("%w: event_id", ErrPayloadMissingField)
	}
	v, ok := payloadValidators[r.PayloadKind]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownPayloadKind, r.PayloadKind)
	}
	if err := v(r.Payload); err != nil {
		return err
	}
	return r.validateSignatureProof()
}

func (r EvidenceReceipt) validateSignatureProof() error {
	if r.Signature.SignerKeyID == "" {
		return fmt.Errorf("%w: signature.signer_key_id", ErrPayloadMissingField)
	}
	if r.Signature.KeyPurpose == "" {
		return fmt.Errorf("%w: signature.key_purpose", ErrPayloadMissingField)
	}
	if err := contract.AuthorizeKeyPurpose(string(r.PayloadKind), r.Signature.KeyPurpose); err != nil {
		return err
	}
	if r.Signature.Algorithm != signatureAlgorithmEd25519 {
		return fmt.Errorf("%w: signature.algorithm=%q", ErrPayloadInvalidEnum, r.Signature.Algorithm)
	}
	if !strings.HasPrefix(r.Signature.Signature, signaturePrefixEd25519) {
		return fmt.Errorf("%w: signature.signature prefix", ErrPayloadInvalidEnum)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(r.Signature.Signature, signaturePrefixEd25519))
	if err != nil {
		return fmt.Errorf("%w: signature.signature hex: %w", ErrPayloadInvalidEnum, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature.signature length=%d", ErrPayloadInvalidEnum, len(sig))
	}
	return nil
}

// SignablePreimage returns the JCS-canonical bytes of the receipt with the
// Signature field zeroed out. Callers sign these bytes with Ed25519 PureEdDSA.
//
// Recipe: clone receipt → zero Signature → json.Marshal → ParseJSONStrict →
// Canonicalize.
func (r EvidenceReceipt) SignablePreimage() ([]byte, error) {
	clone := r
	clone.Signature = SignatureProof{}
	raw, err := json.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse receipt for canonicalization: %w", err)
	}
	return contract.Canonicalize(tree)
}
