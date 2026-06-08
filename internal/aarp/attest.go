// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/svid"
)

// ContextSVIDBinding is the domain separator for the SVID proof-of-possession
// binding. It is a signed field of the binding payload, never a sibling label,
// so an SVID signature made to bind one receipt can never be replayed as
// evidence for another.
const ContextSVIDBinding = "pipelock-aarp-v0.1/svid-receipt-binding"

// minNonceBytes is the minimum SVID-binding nonce size: 128 bits.
const minNonceBytes = 16

// SVID binding algorithm identifiers. The binding signature is made by the SVID
// leaf's private key, so the algorithm follows the leaf key type.
const (
	// BindingAlgECDSAP256SHA256 signs SHA-256(canonical binding payload) with
	// ECDSA P-256 (ASN.1 signature). This is the common SPIFFE leaf key type.
	BindingAlgECDSAP256SHA256 = "ecdsa-p256-sha256"
	// BindingAlgEd25519 signs the canonical binding payload with Ed25519
	// PureEdDSA.
	BindingAlgEd25519 = "ed25519"
)

// Attestation failure classes. Compare with errors.Is.
var (
	// ErrSVIDEvidence means the evidence object is structurally invalid (bad
	// base64/DER, missing fields, malformed binding).
	ErrSVIDEvidence = errors.New("aarp: malformed SVID evidence")

	// ErrSVIDBinding means the proof-of-possession binding does not tie the SVID
	// to this receipt and assertion: a context mismatch, a digest mismatch, a
	// signer-key mismatch, a spiffe-id mismatch, or a binding signature that does
	// not verify under the SVID leaf key.
	ErrSVIDBinding = errors.New("aarp: SVID binding does not verify against this receipt")

	// ErrSVIDNotPermitted means the SVID validated cryptographically but its
	// SPIFFE ID is not permitted by the verifier's allowed set/prefixes.
	ErrSVIDNotPermitted = errors.New("aarp: SVID spiffe_id not permitted by trust policy")
)

// SVIDBinding is the proof-of-possession signature tying an SVID to a receipt.
type SVIDBinding struct {
	Alg string `json:"alg"`
	// Context must equal ContextSVIDBinding.
	Context string `json:"context"`
	// PayloadSHA256 is the lowercase-hex SHA-256 of the canonical binding
	// payload (display/reference; the verifier recomputes it).
	PayloadSHA256 string `json:"payload_sha256"`
	// SignatureB64 is the standard-base64 leaf-key signature over the binding.
	SignatureB64 string `json:"signature_b64"`
}

// SVIDEvidence is the X.509-SVID workload-identity evidence attached to an AARP
// envelope. Only X.509-SVID counts toward verified workload identity; JWT-SVID
// is a bearer token and is claim-only in v0.1.
type SVIDEvidence struct {
	Type string `json:"type"` // must be "x509"
	// SPIFFEID is the claimed SPIFFE ID; it must match the SVID's URI SAN.
	SPIFFEID string `json:"spiffe_id"`
	// LeafDERB64 is the standard-base64 DER of the leaf SVID certificate.
	LeafDERB64 string `json:"leaf_der_b64"`
	// ChainDERB64 holds any intermediate certificates, leaf-to-root order.
	ChainDERB64 []string `json:"chain_der_b64,omitempty"`
	// Nonce is a >=128-bit random value (base64url, no padding) defeating
	// cross-action replay; it is part of the signed binding payload.
	Nonce string `json:"nonce"`
	// IssuedAt is the binding issuance time (RFC3339Nano typed string).
	IssuedAt string `json:"issued_at"`
	// Binding is the proof-of-possession signature.
	Binding SVIDBinding `json:"binding"`
}

// bindingPayload is the exact object the SVID leaf key signs. It carries a
// signed domain-separation context field (JCS sorts keys, so "context" is part
// of the signed bytes but not necessarily first in canonical order); every
// numeric-like field is a typed string.
type bindingPayload struct {
	Context                  string `json:"context"`
	Profile                  string `json:"profile"`
	ActionRecordSHA256       string `json:"action_record_sha256"`
	ReceiptEnvelopeSHA256    string `json:"receipt_envelope_sha256"`
	AssuranceAssertionSHA256 string `json:"assurance_assertion_sha256"`
	ReceiptSignerKey         string `json:"receipt_signer_key"`
	MediatorID               string `json:"mediator_id"`
	SPIFFEID                 string `json:"spiffe_id"`
	IssuedAt                 string `json:"issued_at"`
	Nonce                    string `json:"nonce"`
}

// SVIDVerifyOptions carries the verifier's pinned trust for an SVID binding.
type SVIDVerifyOptions struct {
	// TrustDomain is the SPIFFE trust domain the SVID must belong to.
	TrustDomain string
	// History is the pinned trust-bundle history for TrustDomain.
	History *svid.TrustBundleHistory
	// ActionTime is the time the appraised action occurred. The SVID is
	// validated at this time (offline, point-in-time), not at "now", so a
	// historical short-lived credential still validates for its action.
	ActionTime time.Time
	// AllowedSPIFFEIDs, when non-empty, is the exact set of SPIFFE IDs permitted.
	AllowedSPIFFEIDs []string
}

// bindingCanonical returns the JCS-canonical bytes of the binding payload built
// from the envelope and evidence. It is the message the SVID leaf key signs.
func bindingCanonical(e Envelope, ev SVIDEvidence) ([]byte, error) {
	assertionDigest, err := e.PayloadDigest()
	if err != nil {
		return nil, err
	}
	bp := bindingPayload{
		Context:                  ContextSVIDBinding,
		Profile:                  Profile,
		ActionRecordSHA256:       e.Subject.ActionRecordSHA256,
		ReceiptEnvelopeSHA256:    e.Subject.ReceiptEnvelopeSHA256,
		AssuranceAssertionSHA256: assertionDigest,
		ReceiptSignerKey:         e.Subject.ReceiptSignerKey,
		MediatorID:               e.Assertion.MediatorID,
		SPIFFEID:                 ev.SPIFFEID,
		IssuedAt:                 ev.IssuedAt,
		Nonce:                    ev.Nonce,
	}
	raw, err := json.Marshal(bp)
	if err != nil {
		return nil, fmt.Errorf("marshal binding payload: %w", err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse binding payload: %w", err)
	}
	return contract.Canonicalize(tree)
}

// VerifySVIDBinding verifies that the SVID evidence is a genuine, receipt-bound
// X.509-SVID workload-identity proof. It fails closed: any structural problem,
// chain-validation failure, digest/signer/spiffe mismatch, or bad
// proof-of-possession signature returns an error and confirms nothing.
//
// On success it returns the validated SPIFFE ID. The caller maps that to the
// signing_workload_svid_chain_validated / signing_workload_svid_bound /
// signing_workload_svid_valid_at_action_time claims via AppraiseWithSVID.
func VerifySVIDBinding(e Envelope, ev SVIDEvidence, opts SVIDVerifyOptions) (string, error) {
	if ev.Type != "x509" {
		return "", fmt.Errorf("%w: evidence type %q (only x509 counts as verified attestation)", ErrSVIDEvidence, ev.Type)
	}
	if err := ValidateTimestamp(ev.IssuedAt); err != nil {
		return "", fmt.Errorf("%w: issued_at: %w", ErrSVIDEvidence, err)
	}
	// The nonce defeats cross-action replay; require at least 128 bits of
	// base64url so a producer can't weaken replay resistance with a tiny nonce.
	nonceBytes, err := base64.RawURLEncoding.DecodeString(ev.Nonce)
	if err != nil {
		return "", fmt.Errorf("%w: nonce not base64url: %w", ErrSVIDEvidence, err)
	}
	if len(nonceBytes) < minNonceBytes {
		return "", fmt.Errorf("%w: nonce %d bytes, want >= %d", ErrSVIDEvidence, len(nonceBytes), minNonceBytes)
	}
	if ev.Binding.Context != ContextSVIDBinding {
		return "", fmt.Errorf("%w: binding context %q", ErrSVIDBinding, ev.Binding.Context)
	}

	leafPEM, err := svidPEM(ev)
	if err != nil {
		return "", err
	}

	// Validate the SVID offline, at ACTION time, against the pinned bundle.
	validated, err := svid.ValidateSVID(leafPEM, svid.Options{
		TrustDomain: opts.TrustDomain,
		History:     opts.History,
		At:          opts.ActionTime,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSVIDBinding, err)
	}

	// The claimed spiffe_id and the binding spiffe_id must match the validated
	// URI SAN — no substitution.
	if ev.SPIFFEID != validated.SPIFFEID {
		return "", fmt.Errorf("%w: evidence spiffe_id %q != validated %q", ErrSVIDBinding, ev.SPIFFEID, validated.SPIFFEID)
	}
	if !spiffeIDPermitted(validated.SPIFFEID, opts.AllowedSPIFFEIDs) {
		return "", fmt.Errorf("%w: %q", ErrSVIDNotPermitted, validated.SPIFFEID)
	}

	// The signed assertion must declare the same trust domain the SVID validated
	// against (ValidateSVID already pins the SVID to opts.TrustDomain). Without
	// this, a valid SVID from one trust domain could back an assertion claiming
	// another — trust-domain confusion. trust_domain is required when an SVID
	// binding is present.
	if e.Assertion.TrustDomain == "" {
		return "", fmt.Errorf("%w: assertion.trust_domain is required with an SVID binding", ErrSVIDBinding)
	}
	if e.Assertion.TrustDomain != opts.TrustDomain {
		return "", fmt.Errorf("%w: assertion trust_domain %q != validated SVID trust domain %q", ErrSVIDBinding, e.Assertion.TrustDomain, opts.TrustDomain)
	}

	// The proof-of-possession must have been issued while the SVID was valid: a
	// binding stamped after the leaf expired (or before it was issued) signals
	// post-expiry key use, not a fresh possession proof. issued_at is producer-
	// asserted (there is no trusted timestamp without a TSA, Rung-2), so this is
	// a fail-closed sanity bound on top of the action-time chain validation, not
	// a substitute for it.
	issuedAt, perr := time.Parse(time.RFC3339Nano, ev.IssuedAt)
	if perr != nil {
		return "", fmt.Errorf("%w: issued_at: %w", ErrSVIDEvidence, perr)
	}
	if issuedAt.Before(validated.Leaf.NotBefore) || issuedAt.After(validated.Leaf.NotAfter) {
		return "", fmt.Errorf("%w: binding issued_at %s outside the SVID leaf validity window", ErrSVIDBinding, ev.IssuedAt)
	}

	// Recompute the canonical binding payload and verify the proof-of-possession
	// signature under the SVID leaf public key.
	canonical, err := bindingCanonical(e, ev)
	if err != nil {
		return "", err
	}
	if want := hexSHA256(canonical); ev.Binding.PayloadSHA256 != "" && ev.Binding.PayloadSHA256 != want {
		return "", fmt.Errorf("%w: binding payload_sha256 mismatch", ErrSVIDBinding)
	}
	sig, err := base64.StdEncoding.DecodeString(ev.Binding.SignatureB64)
	if err != nil {
		return "", fmt.Errorf("%w: binding signature base64: %w", ErrSVIDEvidence, err)
	}
	if err := verifyLeafSignature(validated.Leaf, ev.Binding.Alg, canonical, sig); err != nil {
		return "", err
	}
	return validated.SPIFFEID, nil
}

// verifyLeafSignature verifies a proof-of-possession signature under the SVID
// leaf public key, dispatching on the declared algorithm and the actual key
// type. A declared algorithm that does not match the key type fails closed.
func verifyLeafSignature(leaf *x509.Certificate, alg string, msg, sig []byte) error {
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if alg != BindingAlgECDSAP256SHA256 {
			return fmt.Errorf("%w: binding alg %q does not match ECDSA leaf key", ErrSVIDBinding, alg)
		}
		// The alg id names P-256; ecdsa.VerifyASN1 is curve-agnostic, so without
		// this check a P-384/P-521 leaf would verify under a name that promises
		// P-256 — a display-vs-reality divergence for curve-scoped policy.
		if pub.Curve != elliptic.P256() {
			return fmt.Errorf("%w: ECDSA leaf curve %s, binding alg requires P-256", ErrSVIDBinding, pub.Curve.Params().Name)
		}
		sum := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return fmt.Errorf("%w: ECDSA proof-of-possession does not verify", ErrSVIDBinding)
		}
		return nil
	case ed25519.PublicKey:
		if alg != BindingAlgEd25519 {
			return fmt.Errorf("%w: binding alg %q does not match Ed25519 leaf key", ErrSVIDBinding, alg)
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
			return fmt.Errorf("%w: Ed25519 proof-of-possession does not verify", ErrSVIDBinding)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported SVID leaf key type %T", ErrSVIDBinding, leaf.PublicKey)
	}
}

// svidPEM assembles the leaf-first certificate chain PEM from the evidence DER
// fields, the form internal/svid.ValidateSVID expects.
func svidPEM(ev SVIDEvidence) ([]byte, error) {
	leafDER, err := base64.StdEncoding.DecodeString(ev.LeafDERB64)
	if err != nil {
		return nil, fmt.Errorf("%w: leaf_der_b64: %w", ErrSVIDEvidence, err)
	}
	if len(leafDER) == 0 {
		return nil, fmt.Errorf("%w: empty leaf certificate DER", ErrSVIDEvidence)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	for i, c := range ev.ChainDERB64 {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("%w: chain_der_b64[%d]: %w", ErrSVIDEvidence, i, err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out, nil
}

// spiffeIDPermitted reports whether id is in the allowed set. An empty allowed
// set permits any validated SPIFFE ID in the (already verified) trust domain.
func spiffeIDPermitted(id string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == id {
			return true
		}
	}
	return false
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AppraiseWithSVID runs the core appraisal and, when SVID evidence is present
// AND verifies against the pinned trust, adds the workload-identity claims. An
// SVID that fails to verify never removes a core claim and never adds an
// attestation one: the producer's workload-identity claim is simply reported
// claimed-but-unverified, with a warning. Attestation is only considered on a
// signed assertion, since the binding ties to the signed assertion digest.
func AppraiseWithSVID(e Envelope, ev *SVIDEvidence, opts VerifyOptions, svidOpts SVIDVerifyOptions) (*Appraisal, error) {
	ap, err := appraiseCore(e, opts)
	if err != nil {
		return nil, err
	}
	if ev != nil {
		addSVIDClaims(ap, e, *ev, svidOpts)
	}
	classifyClaims(ap)
	ap.finalize()
	return ap, nil
}

func addSVIDClaims(ap *Appraisal, e Envelope, ev SVIDEvidence, svidOpts SVIDVerifyOptions) {
	if !ap.AssertionSigned {
		ap.Warnings = append(ap.Warnings, "SVID evidence present but assertion not signed; workload identity reported claim-only")
		return
	}
	if _, err := VerifySVIDBinding(e, ev, svidOpts); err != nil {
		ap.Warnings = append(ap.Warnings, "SVID attestation did not verify: "+err.Error())
		return
	}
	ap.addVerified(ClaimSigningWorkloadSVIDChainValidated, AxisIdentity)
	ap.addVerified(ClaimSigningWorkloadSVIDBound, AxisIdentity)
	ap.addVerified(ClaimSigningWorkloadSVIDValidAtActionTime, AxisFreshness)
	// A verified signing-workload identity is NOT a deployment or non-bypass
	// proof: it says who signed, never that the deployment forces the workload's
	// traffic through the mediator. State both negatives explicitly so the SVID
	// binding can never be over-read as containment.
	ap.addDoesNotAssert(DNAssertNetworkNonBypassFromIdentity, DNAssertDeploymentEnforcementFromIdentity)
}
