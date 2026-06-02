// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

// Axis names group verified claims by the kind of proof they rest on.
// Transparency and attestation are orthogonal kinds of evidence; a linear trust
// score would lie by collapsing them, so AARP reports claims per axis instead.
const (
	AxisIdentity     = "identity"
	AxisAuthority    = "authority"
	AxisIntegrity    = "integrity"
	AxisFreshness    = "freshness"
	AxisTransparency = "transparency"
	AxisDeployment   = "deployment"
)

// Verified-claim names. A claim appears in Appraisal.VerifiedClaims only when
// the verifier independently confirmed it; otherwise the producer's claim is
// reported as claimed-but-unverified.
const (
	// ClaimAssertionSignatureValid: at least one parallel signature verified
	// under a trusted key over the canonical assertion payload.
	ClaimAssertionSignatureValid = "assertion_signature_valid"
	// ClaimMediatorKeyPinned: a verifying signature's key id is bound by a
	// verifier-side trust entry to the asserted mediator identity (and role).
	ClaimMediatorKeyPinned = "mediator_key_pinned"
	// ClaimChainLinked: the envelope carries a well-formed Rung-1 chain link.
	// Full stream linkage is confirmed by VerifyChain over the stream.
	ClaimChainLinked = "chain_linked"
)

// docsNotAsserted is the fixed set of properties an AARP appraisal never
// asserts, regardless of which claims verified. It is reported verbatim so a
// relying party can never read more into a receipt than it proves.
var docsNotAsserted = []string{
	"efficacy",
	"absence_of_bypass",
	"complete_mediation",
	"policy_correctness",
	"action_safety",
}

// SignatureStatus is the per-signature appraisal outcome. Only SigVerified
// counts toward a confirmed claim; every other status leaves the signature
// unverified, never "trusted by fallback".
type SignatureStatus string

const (
	// SigVerified: the signature is valid under a trusted, implemented suite.
	SigVerified SignatureStatus = "verified"
	// SigFailed: the suite is implemented and the key trusted, but the signature
	// does not verify over the canonical bytes.
	SigFailed SignatureStatus = "failed"
	// SigUnknownKey: the key id is not in the verifier's trusted set.
	SigUnknownKey SignatureStatus = "unknown_key"
	// SigUnimplemented: a recognized suite (the PQ slot) with no built verifier.
	SigUnimplemented SignatureStatus = "unimplemented"
	// SigUnknownSuite: an unrecognized algorithm; no fallback verification.
	SigUnknownSuite SignatureStatus = "unknown_suite"
	// SigMalformed: a structurally invalid signature (key-type mismatch, empty
	// role, bad wire encoding).
	SigMalformed SignatureStatus = "malformed"
)

// SignatureResult is the appraisal of one parallel signature.
type SignatureResult struct {
	KeyID  string          `json:"key_id"`
	Alg    string          `json:"alg"`
	Role   string          `json:"signer_role"`
	Status SignatureStatus `json:"status"`
	Reason string          `json:"reason,omitempty"`
}

// Appraisal is the AARP verifier result. It reports verified claims grouped by
// axis plus an explicit does_not_assert list, and never carries a "trusted" or
// "safe" boolean. AssertionSigned is the single cryptographic gate: it is true
// only when at least one parallel signature verified under a trusted key.
type Appraisal struct {
	Profile           string              `json:"profile"`
	AssertionSigned   bool                `json:"assertion_signed"`
	Signatures        []SignatureResult   `json:"signatures"`
	AssuranceClaimed  []string            `json:"assurance_claimed"`
	VerifiedClaims    []string            `json:"verified_claims"`
	ClaimedUnverified []string            `json:"claimed_unverified"`
	Axes              map[string][]string `json:"axes"`
	DoesNotAssert     []string            `json:"does_not_assert"`
	Warnings          []string            `json:"warnings"`
}

// newAppraisal returns an Appraisal with the fixed does_not_assert list and
// empty axis buckets, ready for the verifier to populate.
func newAppraisal() *Appraisal {
	return &Appraisal{
		Profile:       Profile,
		Axes:          map[string][]string{},
		DoesNotAssert: append([]string(nil), docsNotAsserted...),
		Warnings:      []string{},
	}
}

// addVerified records a confirmed claim under an axis (and in VerifiedClaims).
func (a *Appraisal) addVerified(claim, axis string) {
	a.VerifiedClaims = append(a.VerifiedClaims, claim)
	a.Axes[axis] = append(a.Axes[axis], claim)
}
