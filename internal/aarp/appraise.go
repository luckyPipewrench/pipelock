// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import "sort"

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
//
// These names are deliberately literal: each names the exact mechanical fact the
// verifier confirmed, never a property a relying party might over-read. They are
// the stable public claim dictionary; renaming one is a breaking change to every
// reference verifier and the conformance corpus, so they are chosen to say only
// what the evidence proves.
const (
	// ClaimReceiptSignatureValid: at least one parallel signature verified under
	// a trusted key over the canonical assertion payload. It is integrity over the
	// assertion bytes — NOT transparency-log inclusion, authorization, or action
	// safety.
	ClaimReceiptSignatureValid = "receipt_signature_valid"
	// ClaimMediatorKeyPinned: a verifying signature's key id is bound by a
	// verifier-side trust entry to the asserted mediator identity (and role).
	ClaimMediatorKeyPinned = "mediator_key_pinned"
	// ClaimReceiptTimestampMonotonicChainPresent: the envelope carries a signed,
	// well-formed Rung-1 chain link (sequence number + prior hash) — a position in
	// an issuer's monotonic stream. It is deliberately NOT "freshness" and NOT
	// "chain linked": a single envelope cannot prove the stream is contiguous or
	// untampered (VerifyChain over the stream is the authority for that), and a
	// monotonic position is not a wall-clock freshness proof.
	ClaimReceiptTimestampMonotonicChainPresent = "receipt_timestamp_monotonic_chain_present"
	// ClaimSigningWorkloadSVIDChainValidated: a receipt-bound X.509-SVID leaf
	// chain validated offline against a pinned trust bundle and its SPIFFE ID is
	// permitted. It attests the signing workload's identity, NOT that the
	// workload's network egress was mediated or non-bypassable.
	ClaimSigningWorkloadSVIDChainValidated = "signing_workload_svid_chain_validated"
	// ClaimSigningWorkloadSVIDBound: the SVID leaf key signed a binding tying it
	// to this receipt and assurance-assertion digest (proof of possession). It is
	// an identity binding, NOT a deployment attestation — it does not prove the
	// deployment forces the workload's traffic through the mediator.
	ClaimSigningWorkloadSVIDBound = "signing_workload_svid_bound"
	// ClaimSigningWorkloadSVIDValidAtActionTime: the SVID validated at the action
	// time (offline, point-in-time), not merely at "now".
	ClaimSigningWorkloadSVIDValidAtActionTime = "signing_workload_svid_valid_at_action_time"

	// ClaimPolicyHashBound is RESERVED, not yet emitted. It names a verified claim
	// that the decision's policy_hash (the hash of the policy inputs the evaluator
	// used) is bound into the signed assertion. It lands when the envelope-level
	// policy_hash field ships (v2.7 PR1); the name is reserved here so the public
	// claim dictionary is stable when PR1 wires it.
	ClaimPolicyHashBound = "policy_hash_bound"
)

// Paired does_not_assert negatives. A verified claim a relying party could
// over-read carries an explicit negative stating what it does NOT prove. These
// are added to DoesNotAssert when their paired claim is present, alongside the
// fixed general list below.
const (
	// DNAssertNetworkNonBypassFromIdentity pairs with the SVID claims: a verified
	// signing-workload identity does not prove the workload's network egress was
	// mediated or that direct (proxy-bypassing) egress was impossible.
	DNAssertNetworkNonBypassFromIdentity = "does_not_assert_network_non_bypass_from_identity"
	// DNAssertDeploymentEnforcementFromIdentity pairs with the SVID claims: a
	// verified identity does not prove the deployment (network policy, admission
	// control, process owner) forces traffic through the mediator.
	DNAssertDeploymentEnforcementFromIdentity = "does_not_assert_deployment_enforcement_from_identity"
)

// Overclaim-risk codes. Each names a property a reader might infer from a present
// verified claim that the evidence does NOT mechanically support, because the
// stronger sibling (a different axis, or a stream-level proof) is absent. They
// are stable strings: the active "you might be about to over-read X" warnings,
// distinct from the static does_not_assert surface.
const (
	// RiskSignatureValidNotTransparency: a valid signature is integrity over the
	// assertion bytes, not proof the receipt was submitted to or witnessed by an
	// external transparency log. Emitted when the signature is valid but no
	// transparency-axis claim is present.
	RiskSignatureValidNotTransparency = "signature_valid_is_not_transparency_inclusion"
	// RiskSVIDIdentityNotDeploymentNonBypass: a verified signing-workload identity
	// is not a deployment/non-bypass proof. Emitted when the SVID is bound but no
	// deployment-axis claim is present.
	RiskSVIDIdentityNotDeploymentNonBypass = "svid_identity_is_not_deployment_non_bypass"
	// RiskChainLinkNotContiguousChain: a present chain link is a single position,
	// not a verified contiguous stream. Emitted when the chain link is present in
	// single-envelope appraisal, which never proves stream continuity.
	RiskChainLinkNotContiguousChain = "chain_link_present_is_not_verified_contiguous_chain"
)

// docsNotAsserted is the fixed set of properties an AARP appraisal never asserts,
// regardless of which claims verified. It is reported verbatim so a relying party
// can never read more into a receipt than it proves.
var docsNotAsserted = []string{
	"efficacy",
	"absence_of_bypass",
	"complete_mediation",
	"policy_correctness",
	"intent_correctness",
	"action_safety",
	"all_tools_discovered",
	"delegated_actions_mediated",
	"hosted_saas_actions_mediated",
	"local_side_effects_mediated",
	"key_non_compromise",
	"semantic_equivalence_after_modify",
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

// AssuranceSummary is a computed, never-asserted descriptor of evidence breadth:
// the set of axes that hold at least one verified claim. It is derived from the
// evidence, not a grade, score, or ladder — it describes coverage and carries no
// "trusted"/"safe" connotation. The redundant axis count is intentionally NOT in
// this struct (and not in the comparable JSON surface): it is the array length,
// derived where displayed, so the cross-language comparison surface stays free of
// raw JSON numbers.
type AssuranceSummary struct {
	AxesWithVerifiedClaims []string `json:"axes_with_verified_claims"`
}

// Appraisal is the AARP verifier result. It reports verified claims grouped by
// axis plus an explicit does_not_assert list and an overclaim_risks list, and
// never carries a "trusted" or "safe" boolean. AssertionSigned is the single
// cryptographic gate: it is true only when at least one parallel signature
// verified under a trusted key.
type Appraisal struct {
	Profile           string              `json:"profile"`
	AssertionSigned   bool                `json:"assertion_signed"`
	Signatures        []SignatureResult   `json:"signatures"`
	AssuranceClaimed  []string            `json:"assurance_claimed"`
	VerifiedClaims    []string            `json:"verified_claims"`
	ClaimedUnverified []string            `json:"claimed_unverified"`
	Axes              map[string][]string `json:"axes"`
	DoesNotAssert     []string            `json:"does_not_assert"`
	OverclaimRisks    []string            `json:"overclaim_risks"`
	Assurance         AssuranceSummary    `json:"assurance"`
	Warnings          []string            `json:"warnings"`
}

// newAppraisal returns an Appraisal with the fixed does_not_assert list and
// empty axis buckets, ready for the verifier to populate.
func newAppraisal() *Appraisal {
	return &Appraisal{
		Profile:        Profile,
		Axes:           map[string][]string{},
		DoesNotAssert:  append([]string(nil), docsNotAsserted...),
		OverclaimRisks: []string{},
		Warnings:       []string{},
	}
}

// addVerified records a confirmed claim under an axis (and in VerifiedClaims).
func (a *Appraisal) addVerified(claim, axis string) {
	a.VerifiedClaims = append(a.VerifiedClaims, claim)
	a.Axes[axis] = append(a.Axes[axis], claim)
}

// addDoesNotAssert appends one or more paired negatives, skipping any already
// present so the list never carries a duplicate a relying party might count.
func (a *Appraisal) addDoesNotAssert(items ...string) {
	for _, it := range items {
		if !containsString(a.DoesNotAssert, it) {
			a.DoesNotAssert = append(a.DoesNotAssert, it)
		}
	}
}

// finalize computes the derived honesty outputs — the overclaim risks and the
// assurance axis-set descriptor — from the populated claim set and axes. It must
// run AFTER classifyClaims and after any attestation claims are added, so it sees
// the final verified set (Verify and AppraiseWithSVID both call it last).
func (a *Appraisal) finalize() {
	a.OverclaimRisks = a.computeOverclaimRisks()
	a.Assurance = AssuranceSummary{AxesWithVerifiedClaims: a.axesWithVerifiedClaims()}
}

// computeOverclaimRisks returns the sorted, de-duplicated overclaim-risk codes
// for the present verified claims. A risk fires when a claim that could be
// over-read is present AND the stronger sibling it might be mistaken for is
// absent, so the warning auto-suppresses once that stronger axis is populated
// (e.g. a future external-witness transparency claim or stream-authority proof).
func (a *Appraisal) computeOverclaimRisks() []string {
	verified := make(map[string]struct{}, len(a.VerifiedClaims))
	for _, c := range a.VerifiedClaims {
		verified[c] = struct{}{}
	}
	var risks []string
	add := func(code string) {
		if !containsString(risks, code) {
			risks = append(risks, code)
		}
	}
	if _, ok := verified[ClaimReceiptSignatureValid]; ok && len(a.Axes[AxisTransparency]) == 0 {
		add(RiskSignatureValidNotTransparency)
	}
	if _, ok := verified[ClaimSigningWorkloadSVIDBound]; ok && len(a.Axes[AxisDeployment]) == 0 {
		add(RiskSVIDIdentityNotDeploymentNonBypass)
	}
	if _, ok := verified[ClaimReceiptTimestampMonotonicChainPresent]; ok && len(a.Axes[AxisAuthority]) == 0 {
		add(RiskChainLinkNotContiguousChain)
	}
	sort.Strings(risks)
	return risks
}

// axesWithVerifiedClaims returns the sorted axis names that hold at least one
// verified claim.
func (a *Appraisal) axesWithVerifiedClaims() []string {
	out := make([]string, 0, len(a.Axes))
	for axis, claims := range a.Axes {
		if len(claims) > 0 {
			out = append(out, axis)
		}
	}
	sort.Strings(out)
	return out
}

// containsString reports whether s is in xs.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
