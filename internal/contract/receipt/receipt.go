// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package receipt defines the EvidenceReceipt v2 envelope, the typed payload
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
	"crypto/sha256"
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

const (
	canonicalizationJCSProfile         = "pipelock-jcs-rfc8785-nfc-v1"
	canonicalizationJCSVersion         = "rfc8785"
	canonicalizationHashAlg            = "sha256"
	canonicalizationSigAlg             = "ed25519"
	canonicalizationRedactionRulesetID = "pipelock-transform-v1"
	canonicalizationRedactionVersion   = "1"
	canonicalizationRedactionHash      = "sha256:541896788b42651a202448894583a847db9d1aa081c33a7e1f0512303d72527e"

	CritCanonicalization = "canonicalization"
	CritSourceSpans      = "source_spans"
)

// PayloadKind identifies the payload structure carried inside an EvidenceReceipt.
type PayloadKind string

const (
	PayloadProxyDecision          PayloadKind = "proxy_decision"
	PayloadProxyDecisionWithSpans PayloadKind = "proxy_decision_with_spans"

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

// CanonicalizationProfile names the exact signed interpretation of this receipt:
// JSON canonicalization, digest/signature algorithms, and the redaction/transform
// ruleset that source-span views are based on.
type CanonicalizationProfile struct {
	JCSProfile              string `json:"jcs_profile"`
	JCSVersion              string `json:"jcs_version"`
	HashAlg                 string `json:"hash_alg"`
	SigAlg                  string `json:"sig_alg"`
	RedactionRulesetID      string `json:"redaction_ruleset_id"`
	RedactionRulesetVersion string `json:"redaction_ruleset_version"`
	RedactionRulesetHash    string `json:"redaction_ruleset_hash"`
}

// DefaultCanonicalizationProfile returns the only EvidenceReceipt v2 profile
// understood by this verifier.
func DefaultCanonicalizationProfile() CanonicalizationProfile {
	return CanonicalizationProfile{
		JCSProfile:              canonicalizationJCSProfile,
		JCSVersion:              canonicalizationJCSVersion,
		HashAlg:                 canonicalizationHashAlg,
		SigAlg:                  canonicalizationSigAlg,
		RedactionRulesetID:      canonicalizationRedactionRulesetID,
		RedactionRulesetVersion: canonicalizationRedactionVersion,
		RedactionRulesetHash:    canonicalizationRedactionHash,
	}
}

// CritForPayloadKind returns the critical receipt features that a verifier must
// understand before accepting this payload kind.
func CritForPayloadKind(kind PayloadKind) []string {
	crit := []string{CritCanonicalization}
	if kind == PayloadProxyDecisionWithSpans {
		crit = append(crit, CritSourceSpans)
	}
	return crit
}

// EvidenceReceipt is the v2 evidence receipt envelope.
// Payload holds a typed struct serialized as JSON; its structure is determined
// by PayloadKind and validated by the registry in registry.go.
type EvidenceReceipt struct {
	RecordType       RecordType              `json:"record_type"`
	ReceiptVersion   int                     `json:"receipt_version"`
	PayloadKind      PayloadKind             `json:"payload_kind"`
	Canonicalization CanonicalizationProfile `json:"canonicalization"`
	Crit             []string                `json:"crit"`
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
	if err := r.validateCanonicalization(); err != nil {
		return err
	}
	if err := r.validateCrit(); err != nil {
		return err
	}
	if r.EventID == "" {
		return fmt.Errorf("%w: event_id", ErrPayloadMissingField)
	}
	if r.Timestamp.IsZero() {
		return fmt.Errorf("%w: timestamp", ErrPayloadMissingField)
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

func (r EvidenceReceipt) validateCanonicalization() error {
	want := DefaultCanonicalizationProfile()
	if r.Canonicalization.JCSProfile != want.JCSProfile {
		return fmt.Errorf("%w: canonicalization.jcs_profile=%q", ErrPayloadInvalidEnum, r.Canonicalization.JCSProfile)
	}
	if r.Canonicalization.JCSVersion != want.JCSVersion {
		return fmt.Errorf("%w: canonicalization.jcs_version=%q", ErrPayloadInvalidEnum, r.Canonicalization.JCSVersion)
	}
	if r.Canonicalization.HashAlg != want.HashAlg {
		return fmt.Errorf("%w: canonicalization.hash_alg=%q", ErrPayloadInvalidEnum, r.Canonicalization.HashAlg)
	}
	if r.Canonicalization.SigAlg != want.SigAlg {
		return fmt.Errorf("%w: canonicalization.sig_alg=%q", ErrPayloadInvalidEnum, r.Canonicalization.SigAlg)
	}
	if r.Canonicalization.RedactionRulesetID != want.RedactionRulesetID {
		return fmt.Errorf("%w: canonicalization.redaction_ruleset_id=%q", ErrPayloadInvalidEnum, r.Canonicalization.RedactionRulesetID)
	}
	if r.Canonicalization.RedactionRulesetVersion != want.RedactionRulesetVersion {
		return fmt.Errorf("%w: canonicalization.redaction_ruleset_version=%q", ErrPayloadInvalidEnum, r.Canonicalization.RedactionRulesetVersion)
	}
	if r.Canonicalization.RedactionRulesetHash != want.RedactionRulesetHash {
		return fmt.Errorf("%w: canonicalization.redaction_ruleset_hash=%q", ErrPayloadInvalidEnum, r.Canonicalization.RedactionRulesetHash)
	}
	return nil
}

func (r EvidenceReceipt) validateCrit() error {
	if len(r.Crit) == 0 {
		return fmt.Errorf("%w: crit", ErrPayloadMissingField)
	}
	seen := make(map[string]struct{}, len(r.Crit))
	hasCanonicalization := false
	hasSourceSpans := false
	for _, name := range r.Crit {
		if name == "" {
			return fmt.Errorf("%w: crit empty name", ErrPayloadInvalidEnum)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("%w: crit duplicate %q", ErrPayloadInvalidEnum, name)
		}
		seen[name] = struct{}{}
		switch name {
		case CritCanonicalization:
			hasCanonicalization = true
		case CritSourceSpans:
			hasSourceSpans = true
		default:
			return fmt.Errorf("%w: crit %q", ErrPayloadInvalidEnum, name)
		}
	}
	if !hasCanonicalization {
		return fmt.Errorf("%w: crit canonicalization", ErrPayloadMissingField)
	}
	if r.PayloadKind == PayloadProxyDecisionWithSpans && !hasSourceSpans {
		return fmt.Errorf("%w: crit source_spans", ErrPayloadMissingField)
	}
	if r.PayloadKind != PayloadProxyDecisionWithSpans && hasSourceSpans {
		return fmt.Errorf("%w: crit source_spans for payload_kind=%q", ErrPayloadInvalidEnum, r.PayloadKind)
	}
	return nil
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

// ReceiptHash computes the SHA-256 hex digest of the canonical full receipt.
func ReceiptHash(r EvidenceReceipt) (string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("marshal receipt: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return "", fmt.Errorf("parse receipt for hashing: %w", err)
	}
	canonical, err := contract.Canonicalize(tree)
	if err != nil {
		return "", fmt.Errorf("canonicalize receipt for hashing: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyWithKey verifies the detached Ed25519 signature against pubKey and
// confirms that the receipt declares the expected signer key id.
func VerifyWithKey(r EvidenceReceipt, pubKey ed25519.PublicKey, expectedSignerKeyID string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if expectedSignerKeyID == "" {
		return fmt.Errorf("%w: expected signer_key_id", ErrPayloadMissingField)
	}
	if r.Signature.SignerKeyID != expectedSignerKeyID {
		return fmt.Errorf("%w: signer_key_id", ErrPayloadInvalidEnum)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signature public key length=%d", ErrPayloadInvalidEnum, len(pubKey))
	}
	sigHex := strings.TrimPrefix(r.Signature.Signature, signaturePrefixEd25519)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("%w: signature.signature hex: %w", ErrPayloadInvalidEnum, err)
	}
	preimage, err := r.SignablePreimage()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, preimage, sig) {
		return ErrSignatureVerification
	}
	return nil
}
