// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// Domain-separation contexts. Every signing input is the JCS canonicalization of
// an object that carries one of these as a signed field, so a signature made for
// one purpose can never be replayed as evidence for another.
const (
	// ContextAssertion is the domain separator for the assurance-assertion
	// signature (the parallel multi-signatures in Envelope.Signatures).
	ContextAssertion = "pipelock-aarp-v0.1/assurance-assertion"
)

// Envelope errors. Compare with errors.Is.
var (
	// ErrSchema means the envelope is structurally invalid: a missing required
	// field, a profile mismatch, an empty signature set, or a typed-string
	// grammar violation.
	ErrSchema = errors.New("aarp: envelope schema violation")

	// ErrUnknownField means an AARP-controlled object carried a field outside
	// the registered schema. Unlike legacy v1 receipts (where unknown fields are
	// ignored for backward compatibility), AARP objects reject unknown fields so
	// a producer cannot smuggle unsigned-but-meaningful content past appraisal.
	ErrUnknownField = errors.New("aarp: unknown field in AARP-controlled object")
)

// Subject names the immutable receipt this assurance envelope appraises, by
// digest. Every field is a typed string (number-safety): digests are lowercase
// hex, the signer key is the receipt's Ed25519 public key in hex.
type Subject struct {
	// ActionRecordSHA256 is the SHA-256 of the v1 canonical ActionRecord, or of
	// the v2 EvidenceReceipt SignablePreimage, depending on ReceiptType.
	ActionRecordSHA256 string `json:"action_record_sha256"`
	// ReceiptEnvelopeSHA256 is the SHA-256 of the canonical, unchanged receipt
	// envelope this assurance appraises.
	ReceiptEnvelopeSHA256 string `json:"receipt_envelope_sha256"`
	// ReceiptSignerKey is the hex Ed25519 public key that signed the receipt. An
	// Ed25519 public key is 32 bytes = 64 lowercase hex chars, which is why the
	// 64-hex grammar (ValidateHex256) applies; a future receipt type using a
	// different key size would need a key-length-aware validator.
	ReceiptSignerKey string `json:"receipt_signer_key"`
	// ReceiptType names which frozen receipt format the digests target. This is
	// the exact "hash-of-what" disambiguation.
	ReceiptType string `json:"receipt_type"`
}

// Receipt type constants for Subject.ReceiptType.
const (
	// ReceiptTypeActionV1 targets the legacy ActionReceipt v1 (json.Marshal +
	// SHA-256 of canonical bytes).
	ReceiptTypeActionV1 = "action_receipt_v1"
	// ReceiptTypeEvidenceV2 targets the EvidenceReceipt v2 (JCS SignablePreimage).
	ReceiptTypeEvidenceV2 = "evidence_receipt_v2"
)

var knownReceiptTypes = map[string]bool{
	ReceiptTypeActionV1:   true,
	ReceiptTypeEvidenceV2: true,
}

func (s Subject) validate() error {
	if err := ValidateHex256(s.ActionRecordSHA256); err != nil {
		return fmt.Errorf("%w: subject.action_record_sha256: %w", ErrSchema, err)
	}
	if err := ValidateHex256(s.ReceiptEnvelopeSHA256); err != nil {
		return fmt.Errorf("%w: subject.receipt_envelope_sha256: %w", ErrSchema, err)
	}
	if err := ValidateHex256(s.ReceiptSignerKey); err != nil {
		return fmt.Errorf("%w: subject.receipt_signer_key: %w", ErrSchema, err)
	}
	if !knownReceiptTypes[s.ReceiptType] {
		return fmt.Errorf("%w: unknown subject.receipt_type %q", ErrSchema, s.ReceiptType)
	}
	return nil
}

// Assertion is the producer's claim set about the subject. It is the shared
// payload bound (by digest) by every parallel signature.
type Assertion struct {
	// Claimed lists the claim names the producer asserts. They are producer
	// claims, not verified facts; the verifier confirms each one independently.
	Claimed []string `json:"claimed"`
	// MediatorID is the producer's self-declared mediator identity. It is only
	// trusted insofar as it matches a verifier-side trust entry.
	MediatorID string `json:"mediator_id"`
	// TrustDomain is the producer's SPIFFE trust domain (optional in core;
	// required when an SVID binding is present in the attestation layer).
	TrustDomain string `json:"trust_domain,omitempty"`
	// CompleteMediation is a claim-only field. v0.1 never verifies it: there is
	// no local evidence that proves the absence of an out-of-band path.
	CompleteMediation bool `json:"complete_mediation"`
	// EvidenceRefs names evidence objects (e.g. "spiffe_svid") that an upper
	// layer attaches and verifies.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	// IssuedAt is the assertion issuance time as an RFC3339Nano typed string.
	IssuedAt string `json:"issued_at"`
}

func (a Assertion) validate() error {
	if a.MediatorID == "" {
		return fmt.Errorf("%w: assertion.mediator_id is required", ErrSchema)
	}
	if err := ValidateTimestamp(a.IssuedAt); err != nil {
		return fmt.Errorf("%w: assertion.issued_at: %w", ErrSchema, err)
	}
	if a.TrustDomain != "" {
		if err := validateTrustDomainName(a.TrustDomain); err != nil {
			return fmt.Errorf("%w: assertion.trust_domain: %w", ErrSchema, err)
		}
	}
	return nil
}

// Signature is one parallel protected signature over the shared canonical
// payload digest. Signatures are parallel (each independently binds the same
// payload digest under its own suite), never chained over one another.
type Signature struct {
	Protected ProtectedHeader `json:"protected"`
	// Sig is "<alg>:<base64-std>" over the canonical signing input.
	Sig string `json:"sig"`
}

// Envelope is the top-level AARP assurance artifact. It sits alongside a frozen
// receipt and carries its own parallel signatures; it never mutates the receipt.
type Envelope struct {
	Profile   string    `json:"profile"`
	Subject   Subject   `json:"subject"`
	Assertion Assertion `json:"assertion"`
	// Chain optionally places this envelope in an issuer's append-only,
	// hash-chained stream (Rung-1 timestamp trust). When present it is part of
	// the signed payload, so backdating within a stream is signature-detectable.
	Chain *ChainLink `json:"chain,omitempty"`
	// Signatures holds N parallel protected signatures over the payload digest.
	Signatures []Signature `json:"signatures"`
	// CritExt lists envelope-level critical extension names. Any name not in the
	// known registry rejects the whole envelope (fail closed).
	CritExt []string `json:"crit_ext"`
	// Ext carries non-critical extensions. Unknown non-critical extensions are
	// ignored safely; they are not part of the signed payload.
	Ext map[string]json.RawMessage `json:"ext,omitempty"`
}

// payload is the exact set of fields covered by every signature: the profile,
// subject, assertion, the envelope-level critical-extension list, and (when
// present) the chain link. CritExt is signed so a man-in-the-middle cannot
// strip a critical extension a producer flagged. It deliberately excludes
// Signatures (signatures never sign each other) and Ext (non-critical
// extensions are advisory and ignored safely).
type payload struct {
	Profile   string    `json:"profile"`
	Subject   Subject   `json:"subject"`
	Assertion Assertion `json:"assertion"`
	// CritExt is NOT omitempty: an empty critical-extension list must serialize
	// as "crit_ext": [] so the signed canonical bytes match an external
	// implementation that faithfully emits []. With omitempty, a nil and an
	// explicit [] would canonicalize differently across languages and break
	// cross-implementation signature agreement.
	CritExt []string   `json:"crit_ext"`
	Chain   *ChainLink `json:"chain,omitempty"`
}

func (e Envelope) payload() payload {
	// Normalize a nil critical-extension list to an empty slice so it always
	// serializes as [] (never null) in the signed payload.
	critExt := e.CritExt
	if critExt == nil {
		critExt = []string{}
	}
	return payload{
		Profile:   e.Profile,
		Subject:   e.Subject,
		Assertion: e.Assertion,
		CritExt:   critExt,
		Chain:     e.Chain,
	}
}

// CanonicalPayload returns the JCS-canonical bytes of the signed payload (the
// "identical canonical payload bytes" all parallel signatures bind). Recipe:
// marshal → ParseJSONStrict → EnforceSafeNumbers → Canonicalize.
func (e Envelope) CanonicalPayload() ([]byte, error) {
	raw, err := json.Marshal(e.payload())
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse payload: %w", ErrSchema, err)
	}
	if err := EnforceSafeNumbers(tree); err != nil {
		return nil, err
	}
	return contract.Canonicalize(tree)
}

// PayloadDigest returns the lowercase-hex SHA-256 of the canonical payload. It
// is the value every signature binds and the value an SVID binding references
// as assurance_assertion_sha256.
func (e Envelope) PayloadDigest() (string, error) {
	canonical, err := e.CanonicalPayload()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// signingInput builds the canonical bytes one signature signs: the domain
// context, the shared payload digest, and that signature's protected header.
// Embedding the protected header means each signature commits to its own suite
// (alg, key, canon, profile, critical extensions), defeating algorithm
// substitution; binding the payload digest means all signatures cover identical
// payload bytes.
func signingInput(payloadDigest string, h ProtectedHeader) ([]byte, error) {
	obj := signingInputObject{
		Context:       ContextAssertion,
		PayloadSHA256: payloadDigest,
		Protected:     h,
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal signing input: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse signing input: %w", err)
	}
	return contract.Canonicalize(tree)
}

type signingInputObject struct {
	Context       string          `json:"context"`
	PayloadSHA256 string          `json:"payload_sha256"`
	Protected     ProtectedHeader `json:"protected"`
}

// validatePayloadParts validates the signed payload-bearing fields (profile,
// subject, assertion, chain) plus envelope-level critical extensions. It does
// NOT require signatures, so it is the structural gate the signer runs before
// producing them.
func (e Envelope) validatePayloadParts() error {
	if e.Profile != Profile {
		return fmt.Errorf("%w: profile %q, want %q", ErrSchema, e.Profile, Profile)
	}
	if err := e.Subject.validate(); err != nil {
		return err
	}
	if err := e.Assertion.validate(); err != nil {
		return err
	}
	if e.Chain != nil {
		if err := e.Chain.validate(); err != nil {
			return err
		}
	}
	return checkCriticalExtensions(e.CritExt)
}

// validateStructure runs the envelope-fatal schema checks that must hold before
// any per-signature appraisal: the payload parts (which include the top-level
// profile and the envelope-level critical-extension list) and a non-empty
// signature set.
//
// Only fields inside the SIGNED payload are envelope-fatal here. Per-signature
// suite fields (a signature's protected profile, canon, alg, key trust, and its
// own critical-extension list) are deliberately NOT checked here: they are
// per-signature outcomes appraised in appraiseSignature. The signatures array
// is not itself signed, so a man-in-the-middle can append a junk signature; if a
// bad protected header were envelope-fatal, that append would deny a
// legitimately-signed envelope. Per-signature handling makes one unverifiable
// signature inert instead of fatal, while the signed top-level profile and
// crit_ext (which an append cannot forge) stay fatal.
func (e Envelope) validateStructure() error {
	if err := e.validatePayloadParts(); err != nil {
		return err
	}
	if len(e.Signatures) == 0 {
		return fmt.Errorf("%w: envelope has no signatures", ErrSchema)
	}
	return nil
}

// Marshal returns the JSON encoding of an envelope. An empty critical-extension
// list is emitted as "crit_ext": [] (never omitted), matching the signed payload
// and the spec wire form so strict external implementations and golden vectors
// agree byte-for-byte.
func Marshal(e Envelope) ([]byte, error) {
	if e.CritExt == nil {
		e.CritExt = []string{}
	}
	return json.Marshal(e)
}

// Unmarshal parses a JSON-encoded envelope, rejecting duplicate keys at any
// nesting depth (parser-differential smuggling guard) and unknown fields in
// AARP-controlled objects. The receipt subject digests, not the receipt bytes,
// are what AARP signs, so strict decoding here cannot affect frozen receipts.
func Unmarshal(data []byte) (Envelope, error) {
	tree, err := contract.ParseJSONStrict(data)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	// Reject any raw JSON number outside the I-JSON safe range anywhere in the
	// envelope before decoding. Identity, digest, counter, timestamp, and amount
	// fields must arrive as typed strings; a raw number in any position is a
	// cross-language canonicalization hazard and is refused here.
	if err := EnforceSafeNumbers(tree); err != nil {
		return Envelope{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber() // future-proof: preserve integers if a numeric field is ever added
	var e Envelope
	if err := dec.Decode(&e); err != nil {
		// Distinguish an unknown AARP field (a smuggling attempt) from an
		// ordinary type/shape decode error, so errors.Is(err, ErrUnknownField)
		// is not a false positive on, e.g., a type mismatch.
		if strings.Contains(err.Error(), "unknown field") {
			return Envelope{}, fmt.Errorf("%w: %w", ErrUnknownField, err)
		}
		return Envelope{}, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	return e, nil
}
