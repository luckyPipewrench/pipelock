// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/svidsidecar"
)

// This file builds the Evidence Theater Kill Suite arm of the AARP hostile
// corpus: evidence packets that look valid and sound strong but overclaim, each
// paired with the EXACT appraiser downgrade. The suite exists to publicly prove a
// single, hard-to-copy property — Pipelock's verifier refuses to call an
// assertion "proven" beyond what the evidence mechanically supports, and it
// applies that refusal to Pipelock's OWN strongest-sounding evidence.
//
// Every kill-suite fixture is verdictAppraise (an overclaim withholds claims, it
// never makes the envelope fatal). Beyond the standard appraisal byte-match, each
// fixture carries hand-authored gate annotations (mustNotVerify / expectRisks /
// expectNegatives) asserted live by TestKillSuiteOverclaimGate. Those
// annotations are written by a human, NOT generated from the verifier, so
// regenerating the .appraisal.json golden can never launder an over-broad
// verified claim past the gate.
//
// Framing is uniform and vendor-neutral: the corpus describes how agent-control
// evidence can lie, and applies the test to Pipelock-shaped evidence the same way
// it applies it to anything else. No competitor names, no "fake/noncompliant"
// language — the point is that strong-sounding evidence is not the same as proof.

// Producer-claim vocabulary the kill suite asserts the verifier never promotes to
// a verified claim. These are the broad properties an overclaiming producer wants
// a relying party to read in. They are deliberately the spec's literal deployment
// vocabulary and general non-assertions so the suite documents exactly which
// over-reads are refused.
const (
	// claimCompleteMediation is the producer's snake_case complete-mediation claim;
	// it is a fixed does_not_assert entry and is never verifiable in v0.1.
	claimCompleteMediation = "complete_mediation"
	// claimAbsenceOfBypass: the producer asserts no traffic bypassed the mediator.
	// A receipt cannot prove a negative about traffic it never saw.
	claimAbsenceOfBypass = "absence_of_bypass"
	// claimK8sEgressPolicy is a deployment-vocabulary claim (v2.8 reserved): it
	// asserts a namespace egress policy forces the workload through the mediator.
	// A producer reading its own identity cannot prove a cluster-side control.
	claimK8sEgressPolicy = "k8s_namespace_egress_policy_restricts_workload_to_mediator_observed"
	// claimTransparencyInclusion: the producer asserts the receipt was witnessed by
	// an external transparency log. Never verifiable in v0.1 (no witness root).
	claimTransparencyInclusion = "transparency_inclusion"
	// claimWitnessCheckpoint is the deployment/transparency witness vocabulary
	// (v2.8 reserved): an external-witness checkpoint signature. Never verifiable
	// in v0.1; the witness root is held for v2.8.
	claimWitnessCheckpoint = "external_witness_checkpoint_signature_valid"
	// claimK8sPodInjection is a deployment-vocabulary claim (v2.8 reserved): the
	// pod spec was observed to inject the proxy. A self-read cannot prove it.
	claimK8sPodInjection = "k8s_pod_spec_proxy_injection_observed"
	// The producer-claim synonyms below are broad-mediation aliases an overclaiming
	// producer scatters across the claim list hoping one is promoted. None is in the
	// producer-claim map, so each lands in claimed_unverified — the verifier never
	// multiplies a confirmed narrow claim into these.
	claimFullyMediated      = "fully_mediated"
	claimAllTrafficMediated = "all_traffic_mediated"
	claimOrgWideEgress      = "all_agent_egress_mediated_org_wide"
	claimBundledReceipts    = "bundled_receipts_all_valid"
	claimDownstreamAttested = "downstream_actions_attested"
	claimModifyEquivalent   = "modification_semantically_equivalent"
	claimSessionComplete    = "session_complete_from_genesis"
	claimDualSigned         = "dual_signed_high_assurance"
	claimHighAssurance      = "high_assurance_certified"
)

// does_not_assert codes the kill suite asserts are present. These mirror the
// fixed appraisal does_not_assert list (which is unexported in internal/aarp);
// re-declaring them here lets a fixture assert the specific negative it relies on
// without coupling to the internal slice.
const (
	dnaSemanticEquivalence = "semantic_equivalence_after_modify"
	dnaDelegatedActions    = "delegated_actions_mediated"
	dnaLocalSideEffects    = "local_side_effects_mediated"
)

// signEdMulti signs e with every provided ed25519 (keyID, role, priv) signer,
// producing parallel signatures over the SAME payload. It is the parallel-
// signature builder the confusion fixtures need (aarp.Sign replaces the
// signature set, so two signatures must come from one Sign call).
type edSignerSpec struct {
	keyID string
	role  string
	priv  ed25519.PrivateKey
}

func (g *aarpGen) signEdMulti(e aarp.Envelope, specs ...edSignerSpec) aarp.Envelope {
	signers := make([]aarp.Signer, 0, len(specs))
	for _, sp := range specs {
		s, err := aarp.NewEd25519Signer(sp.keyID, sp.role, sp.priv)
		if err != nil {
			g.t.Fatalf("new signer %s: %v", sp.keyID, err)
		}
		signers = append(signers, s)
	}
	signed, err := aarp.Sign(e, signers...)
	if err != nil {
		g.t.Fatalf("multi-sign: %v", err)
	}
	return signed
}

// Shared must_verify sets: the genuine narrow claims a fixture's evidence DOES
// prove. Pairing these with must_not_verify states both halves of a downgrade —
// valid evidence present, broad reading refused — so the gate independently
// guards against a regression that simply stops verifying anything.
var (
	// ksVerifyNarrow: a pinned-mediator signature — signature valid + mediator
	// pinned. The common case for a genuine Pipelock receipt signed by k-signer.
	ksVerifyNarrow = []string{aarp.ClaimReceiptSignatureValid, aarp.ClaimMediatorKeyPinned}
	// ksVerifySigOnly: the signature verifies but the mediator is NOT pinned
	// (wrong role, or a confusable identity that fails the trust-entry compare).
	ksVerifySigOnly = []string{aarp.ClaimReceiptSignatureValid}
	// ksVerifyChain: a pinned signature plus a present (not contiguous) chain link.
	ksVerifyChain = []string{aarp.ClaimReceiptSignatureValid, aarp.ClaimMediatorKeyPinned, aarp.ClaimReceiptTimestampMonotonicChainPresent}
	// ksVerifySVID: a pinned signature plus a fully verified workload-identity SVID.
	ksVerifySVID = []string{
		aarp.ClaimReceiptSignatureValid, aarp.ClaimMediatorKeyPinned,
		aarp.ClaimSigningWorkloadSVIDChainValidated, aarp.ClaimSigningWorkloadSVIDBound,
		aarp.ClaimSigningWorkloadSVIDValidAtActionTime,
	}
)

// killsuiteFixtures returns the Evidence Theater Kill Suite. The spike (first
// three) de-risks the vocabulary before the full matrix: one genuine Pipelock
// receipt (the honest control), one hostile non-Pipelock-shaped packet, and one
// Pipelock-shaped packet whose own strongest evidence is downgraded.
func (g *aarpGen) killsuiteFixtures() []aarpFixture {
	ca := g.newEd25519CA("killsuite", "AARP Kill Suite Test CA", svidCANotBefore, time.Time{})
	var out []aarpFixture

	// k01: the honest control. A genuine Pipelock receipt: the pinned-mediator
	// signature verifies and the appraiser confirms exactly the narrow integrity +
	// identity claims. It is Pipelock-shaped and fully valid, yet the appraiser
	// STILL names the transparency limit and asserts nothing about mediation
	// completeness or bypass. This anchors the suite: the downgrades below are not
	// the verifier being broken, they are the verifier being honest.
	{
		e := aarp.Envelope{Subject: g.baseSubject("k01"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k01-valid-pipelock-baseline", category: catKillSuite, attackClass: "baseline",
			description: "a genuine Pipelock receipt verifies its signature and mediator pinning; the appraiser confirms exactly those narrow claims and still names what it cannot prove",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "control: a real Pipelock receipt proves its signature and mediator identity and asserts nothing broader",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimCompleteMediation, claimAbsenceOfBypass, claimK8sEgressPolicy},
			expectRisks:        []string{aarp.RiskSignatureValidNotTransparency},
			expectNegatives:    []string{claimCompleteMediation, claimAbsenceOfBypass},
		})
	}

	// k02: hostile non-Pipelock-shaped packet. It presents a real cryptographic
	// signature and a maximal claim list (mediation, complete mediation,
	// transparency inclusion) — but the signing key is not in the verifier's trust
	// set. Every signature is unknown_key, the assertion is unsigned, and not one
	// claim verifies. This is the trust-substitution shape: an authoritative-LOOKING
	// receipt from an untrusted issuer proves nothing.
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k02"),
			Assertion: baseAssertion("mediated", claimCompleteMediation, claimTransparencyInclusion),
		}
		e = g.signEd(e, keyIDOther, roleMediator, g.otherPriv)
		out = append(out, aarpFixture{
			name: "k02-untrusted-issuer-overclaim", category: catKillSuite, attackClass: "trust-file-substitution",
			description: "a maximal claim list under a real signature whose key is untrusted: every signature is unknown_key, the assertion is unsigned, and no claim verifies",
			verdict:     verdictAppraise, body: g.marshal(e),
			overclaimNarrative: "this receipt is signed by the mediator and proves mediation, transparency-log inclusion, and complete mediation",
			mustNotVerify:      []string{aarp.ClaimReceiptSignatureValid, aarp.ClaimMediatorKeyPinned, claimCompleteMediation, claimTransparencyInclusion},
		})
	}

	// k03: Pipelock-shaped but downgraded — the moat fixture. A genuine Pipelock
	// receipt with a valid pinned-mediator signature AND a valid workload-identity
	// X.509-SVID binding, whose producer claims broad deployment non-bypass and
	// complete mediation. The appraiser confirms the identity and freshness claims
	// the SVID actually proves, and then explicitly refuses the deployment reading:
	// it raises svid_identity_is_not_deployment_non_bypass and asserts it does NOT
	// prove the workload's egress was mediated or non-bypassable. This is axis
	// laundering — an identity proof dressed as a deployment proof — and the
	// verifier downgrades Pipelock's own strongest evidence.
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k03"),
			Assertion: baseAssertion("mediated", producerClaimWorkloadIdentityVerified, claimCompleteMediation, claimK8sEgressPolicy),
		}
		e.Assertion.TrustDomain = svidTrustDomain
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		lf := g.issueLeaf(ca, "k03", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: e, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("k03"), seed: "k03",
		})
		out = append(out, aarpFixture{
			name: "k03-svid-identity-as-deployment", category: catKillSuite, attackClass: "axis-laundering",
			description: "a genuine Pipelock receipt with a valid signature and a valid workload-identity SVID, whose producer claims deployment non-bypass and complete mediation: the appraiser confirms identity and freshness but downgrades the deployment reading, naming svid_identity_is_not_deployment_non_bypass",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			svid:               &svidsidecar.Sidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))},
			overclaimNarrative: "the agent runs under a verified workload identity, so its egress is forced through Pipelock and cannot be bypassed",
			mustVerify:         ksVerifySVID,
			mustNotVerify:      []string{claimK8sEgressPolicy, claimCompleteMediation, claimAbsenceOfBypass},
			expectRisks:        []string{aarp.RiskSVIDIdentityNotDeploymentNonBypass},
			expectNegatives:    []string{aarp.DNAssertNetworkNonBypassFromIdentity, aarp.DNAssertDeploymentEnforcementFromIdentity},
		})
	}

	// ---- the full matrix (k04..k23) ----

	// k04: valid signature + omitted action. A genuine receipt that proves it
	// mediated ONE action, claiming complete mediation. The signature verifies, but
	// a single action receipt cannot prove the agent's other / delegated / local
	// actions were mediated, so those stay in does_not_assert and complete-mediation
	// is unverified. (omitted-action / partial-coverage)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k04"), Assertion: baseAssertion("mediated", claimCompleteMediation)}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k04-valid-sig-omitted-action", category: catKillSuite, attackClass: "omitted-action",
			description: "a genuine receipt for one mediated action, claiming complete mediation: the signature verifies but delegated/local/other actions are not covered, so complete mediation is not confirmed",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "this receipt proves every action the agent took was mediated",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimCompleteMediation},
			expectNegatives:    []string{claimCompleteMediation, dnaDelegatedActions, dnaLocalSideEffects},
		})
	}

	// k05: self-attested complete-mediation. The producer flips its OWN
	// CompleteMediation boolean to true and claims it. A self-set flag is not
	// evidence; the appraiser never promotes complete_mediation and keeps it in
	// does_not_assert. (self-attestation)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k05"), Assertion: baseAssertion("mediated", claimCompleteMediation)}
		e.Assertion.CompleteMediation = true // producer self-attests; must not be trusted
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k05-self-attested-complete-mediation", category: catKillSuite, attackClass: "self-attestation",
			description: "the producer sets its own complete-mediation flag to true and claims it: a self-asserted boolean is not evidence and is never promoted to a verified claim",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "the receipt's complete_mediation flag is set, so mediation was complete",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimCompleteMediation},
			expectNegatives:    []string{claimCompleteMediation},
		})
	}

	// k06: claim-alias sprawl. The producer scatters many synonyms for broad
	// mediation across the claim list; only the literal "mediated" maps to a
	// verifiable claim. The aliases do not multiply into verified claims — they all
	// land in claimed_unverified. (claim-alias-sprawl)
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k06"),
			Assertion: baseAssertion("mediated", claimFullyMediated, claimAllTrafficMediated, claimCompleteMediation),
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k06-claim-alias-sprawl", category: catKillSuite, attackClass: "claim-alias-sprawl",
			description: "many broad-mediation synonyms in the claim list: only the mapped 'mediated' claim pins; the aliases are not promoted and stay claimed_unverified",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "the receipt is fully mediated, all traffic mediated, completely mediated",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimFullyMediated, claimAllTrafficMediated, claimCompleteMediation},
		})
	}

	// k07: scope smuggling. A receipt that genuinely mediated one action claims
	// org-wide egress coverage. The narrow claim pins; the org-wide claim is
	// unverified — a single action's mediation says nothing about org-wide scope.
	// (scope-smuggling)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k07"), Assertion: baseAssertion("mediated", claimOrgWideEgress)}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k07-scope-smuggling", category: catKillSuite, attackClass: "scope-smuggling",
			description: "a single-action receipt claiming org-wide egress coverage: the narrow mediated claim pins, the broad-scope claim is not confirmed",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "every agent's egress across the whole organization is mediated",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimOrgWideEgress, claimCompleteMediation},
		})
	}

	// k08: evidence-bundling. A valid signed assertion travels next to producer
	// claims about OTHER, unverifiable receipts ("all bundled receipts valid",
	// "downstream actions attested"). The valid narrow claim must not lend its
	// credibility to the unverifiable bundle. (evidence-bundling)
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k08"),
			Assertion: baseAssertion("mediated", claimBundledReceipts, claimDownstreamAttested),
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k08-evidence-bundling", category: catKillSuite, attackClass: "evidence-bundling",
			description: "a valid signed assertion bundled with claims about other unverifiable receipts: the verified narrow claim does not transfer credibility to the bundle",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "this signed receipt proves the whole bundle of attached receipts is valid",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimBundledReceipts, claimDownstreamAttested},
		})
	}

	// k09: wrong-purpose signing key. A key pinned to the mediator role signs under
	// the countersig role. The signature still verifies (trusted key), but the role
	// scope does not match, so mediator_key_pinned is withheld and 'mediated' is
	// unverified. (wrong-purpose-key)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k09"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleCountsig, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k09-wrong-purpose-signing-key", category: catKillSuite, attackClass: "wrong-purpose-key",
			description: "the mediator key signs under the countersig role: the signature verifies but the role scope does not match, so mediator pinning is withheld",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "the mediator signed this, so the mediator identity is pinned",
			mustVerify:         ksVerifySigOnly,
			mustNotVerify:      []string{aarp.ClaimMediatorKeyPinned},
		})
	}

	// k10: role confusion. The receipt-signing key (pinned only to the mediator
	// role) is used to assert deployment and witness properties. The signature and
	// mediator pinning verify, but a receipt-signing key cannot speak for a
	// deployment or transparency-witness claim — those stay unverified.
	// (role-confusion)
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k10"),
			Assertion: baseAssertion("mediated", claimK8sEgressPolicy, claimWitnessCheckpoint),
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k10-role-confusion-deployment-witness", category: catKillSuite, attackClass: "role-confusion",
			description: "a receipt-signing key asserting deployment and witness claims: the signature and mediator pinning verify, but the key cannot speak for deployment or transparency-witness properties",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "because the mediator signed it, the deployment egress policy and external witness checkpoint are proven",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimK8sEgressPolicy, claimWitnessCheckpoint},
		})
	}

	// k11: deployment claim without scope. The producer asserts deployment controls
	// (egress policy, pod-spec injection) with no SVID and no attestor. There is no
	// deployment-axis evidence at all, so both claims are unverified. (deployment-
	// without-scope)
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k11"),
			Assertion: baseAssertion("mediated", claimK8sEgressPolicy, claimK8sPodInjection),
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k11-deployment-claim-without-scope", category: catKillSuite, attackClass: "deployment-without-scope",
			description: "deployment-control claims with no attestor or SVID: there is no deployment-axis evidence, so the deployment claims are not confirmed",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "the workload's egress policy and proxy injection are enforced at deployment",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimK8sEgressPolicy, claimK8sPodInjection},
		})
	}

	// k12: policy_hash absent on a default-allow. The producer claims the decision
	// was bound to a policy hash, but no policy_hash is present and policy_hash_bound
	// is not yet an emitted verified claim. It stays unverified — an allow decision
	// with no bound policy proves no policy was applied. (policy-hash-absent)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k12"), Assertion: baseAssertion("mediated", aarp.ClaimPolicyHashBound)}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k12-policy-hash-absent-default-allow", category: catKillSuite, attackClass: "policy-hash-absent",
			description: "a decision claiming policy_hash binding with no policy_hash present: the claim is not confirmed, so a default-allow is not shown to be policy-bound",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "this allow decision was evaluated against a bound, hashed policy",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{aarp.ClaimPolicyHashBound},
		})
	}

	// k13: modify receipt without semantic equivalence. The producer claims a
	// content modification preserved meaning. The appraiser never asserts semantic
	// equivalence after a modify — it is a fixed non-assertion — so the claim is
	// unverified and the negative is present. (modify-without-equivalence)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k13"), Assertion: baseAssertion("mediated", claimModifyEquivalent)}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k13-modify-without-semantic-equivalence", category: catKillSuite, attackClass: "modify-without-equivalence",
			description: "a claim that a modification preserved meaning: semantic equivalence after modify is a fixed non-assertion, so the claim is not confirmed",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "the proxy modified the payload but the modification is semantically equivalent",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimModifyEquivalent},
			expectNegatives:    []string{dnaSemanticEquivalence},
		})
	}

	// k14: hash chain + missing session start. A single, signed, well-formed chain
	// link from the MIDDLE of a stream (seq 5). The link's position is present, but
	// a single envelope can never prove the stream is contiguous back to genesis, so
	// the appraiser raises the contiguous-chain overclaim risk. (chain-missing-start)
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k14"),
			Assertion: baseAssertion("mediated", claimSessionComplete),
			Chain:     &aarp.ChainLink{IssuerID: issuerStream, Seq: "5", PriorHash: fixedDigest("k14-prior")},
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k14-chain-link-missing-session-start", category: catKillSuite, attackClass: "chain-missing-start",
			description: "a single mid-stream chain link claiming a complete session from genesis: the link position is present, but single-envelope appraisal cannot prove a contiguous chain, so the contiguous-chain risk is raised",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "this chain link proves the full session is recorded contiguously from its start",
			mustVerify:         ksVerifyChain,
			mustNotVerify:      []string{claimSessionComplete},
			expectRisks:        []string{aarp.RiskChainLinkNotContiguousChain},
		})
	}

	// k15: witnessed checkpoint + pre-witness omission. The producer claims external
	// transparency-witness inclusion. v0.1 has no witness root, so the transparency
	// claims are unverified and the signature-is-not-transparency risk is raised: a
	// valid signature is integrity, not witnessed inclusion. (transparency-omission)
	{
		e := aarp.Envelope{
			Subject:   g.baseSubject("k15"),
			Assertion: baseAssertion("mediated", claimTransparencyInclusion, claimWitnessCheckpoint),
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k15-witnessed-checkpoint-pre-witness-omission", category: catKillSuite, attackClass: "transparency-omission",
			description: "claims of external-witness transparency inclusion with no witness root: the transparency claims are not confirmed and the signature-is-not-transparency risk is raised",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "the receipt was submitted to and witnessed by an external transparency log, so no pre-witness receipts were omitted",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimTransparencyInclusion, claimWitnessCheckpoint},
			expectRisks:        []string{aarp.RiskSignatureValidNotTransparency},
		})
	}

	// k16: parallel-signature confusion. Two parallel signatures: a valid pinned
	// mediator signature and a second, cryptographically valid signature under an
	// untrusted key claiming "dual signed, high assurance". The untrusted signature
	// is unknown_key and adds nothing; a second signature does not stack assurance.
	// (parallel-signature-confusion)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k16"), Assertion: baseAssertion("mediated", claimDualSigned)}
		e = g.signEdMulti(e,
			edSignerSpec{keyIDSigner, roleMediator, g.signerPriv},
			edSignerSpec{keyIDOther, roleMediator, g.otherPriv},
		)
		out = append(out, aarpFixture{
			name: "k16-parallel-signature-confusion", category: catKillSuite, attackClass: "parallel-signature-confusion",
			description: "a valid pinned signature beside a valid-but-untrusted second signature: the untrusted signature is unknown_key and stacks no assurance; only the pinned claims hold",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "two signatures cover this receipt, so it is dual-signed and higher assurance",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimDualSigned},
		})
	}

	// k17: critical-extension downgrade. The single signature carries an unknown
	// per-signature critical extension. An honest verifier cannot process the
	// flagged-critical extension, so the signature is unknown_suite and never
	// verifies; assertion_signed is false and nothing pins. A verifier that ignored
	// the critical flag would wrongly verify it. (critical-extension-downgrade)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k17"), Assertion: baseAssertion("mediated")}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		e.Signatures[0].Protected.Crit = []string{"x-unknown-critical"}
		out = append(out, aarpFixture{
			name: "k17-critical-extension-downgrade", category: catKillSuite, attackClass: "critical-extension-downgrade",
			description: "a signature with an unknown critical extension: an honest verifier cannot process it, reports unknown_suite, and never verifies; a verifier that ignored the critical flag would inflate the claim",
			verdict:     verdictAppraise, body: g.marshal(e),
			overclaimNarrative: "the signature is valid, so the assertion is signed and the mediator is pinned",
			mustNotVerify:      []string{aarp.ClaimReceiptSignatureValid, aarp.ClaimMediatorKeyPinned},
		})
	}

	// k18: cross-language confusable drift. The mediator_id carries a Cyrillic 'а'
	// (U+0430) that looks like Latin 'a' but is a different code point; the trust
	// entry pins the Latin "mediator.example". The signature verifies over the
	// confusable bytes, but the identity does NOT match the pinned Latin id, so
	// mediator pinning is withheld. NFKC does not fold cross-script homoglyphs, so a
	// verifier that "looks at" the id must compare code points, not glyphs; every
	// reference verifier must reach the same verdict. (cross-language-confusable)
	{
		const confusableMediator = "mediаtor.example" // Cyrillic а, not Latin a
		e := aarp.Envelope{
			Subject:   g.baseSubject("k18"),
			Assertion: aarp.Assertion{Claimed: []string{"mediated"}, MediatorID: confusableMediator, IssuedAt: tsIssued},
		}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k18-confusable-mediator-id", category: catKillSuite, attackClass: "cross-language-confusable",
			description: "a mediator_id with a Cyrillic homoglyph that pins the Latin mediator identity: the signature verifies but the id does not equal the pinned Latin id, so mediator pinning is withheld across all four verifiers",
			verdict:     verdictAppraise, body: g.marshal(e),
			overclaimNarrative: "the mediator_id reads as mediator.example, so the trusted mediator is pinned",
			mustVerify:         ksVerifySigOnly,
			mustNotVerify:      []string{aarp.ClaimMediatorKeyPinned},
		})
	}

	// k19: forged SVID binding. A Pipelock receipt with an SVID sidecar whose
	// proof-of-possession signature is tampered (one base64 char flipped). The
	// envelope signature still verifies, but the SVID binding does not, so the three
	// workload-identity claims are withheld — a forged identity proof does not fail
	// the envelope, it simply does not attach. (forged-svid-binding)
	{
		e := g.svidEnvelope("k19", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "k19", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: e, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("k19"), seed: "k19",
		})
		ev.Binding.SignatureB64 = flipB64Char(ev.Binding.SignatureB64) // forge the PoP
		out = append(out, aarpFixture{
			name: "k19-forged-svid-binding", category: catKillSuite, attackClass: "forged-svid-binding",
			description: "a Pipelock receipt with a tampered SVID proof-of-possession: the envelope signature verifies but the workload-identity binding does not, so the three identity claims are withheld",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			svid:               &svidsidecar.Sidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))},
			overclaimNarrative: "the receipt carries an SVID, so the signing workload's identity is verified",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{aarp.ClaimSigningWorkloadSVIDChainValidated, aarp.ClaimSigningWorkloadSVIDBound, aarp.ClaimSigningWorkloadSVIDValidAtActionTime},
		})
	}

	// k20: SVID trust-domain confusion. A valid SVID from trust domain example.org
	// backs an assertion that declares a DIFFERENT trust domain. The binding's
	// domain must equal the assertion's, so the identity claims are withheld: an
	// identity from one domain cannot back an assertion claiming another.
	// (svid-trust-domain-confusion)
	{
		e := g.svidEnvelope("k20", svidWrongTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "k20", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: e, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("k20"), seed: "k20",
		})
		out = append(out, aarpFixture{
			name: "k20-svid-trust-domain-confusion", category: catKillSuite, attackClass: "svid-trust-domain-confusion",
			description: "a valid SVID from one trust domain backing an assertion that declares another: the binding's domain must equal the assertion's, so the workload-identity claims are withheld",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			svid:               &svidsidecar.Sidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))},
			overclaimNarrative: "a valid workload-identity SVID is attached, so this assertion's domain identity is verified",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{aarp.ClaimSigningWorkloadSVIDChainValidated},
		})
	}

	// k21: SVID replayed across actions. An SVID binding minted for one receipt is
	// attached to a DIFFERENT receipt. The recomputed binding payload digest differs,
	// the proof-of-possession does not verify, and the identity claims are withheld.
	// The nonce + receipt digests are what defeat this replay. (svid-replay)
	{
		bound := g.svidEnvelope("k21-bound", svidTrustDomain, keyIDSigner, g.signerPriv)
		target := g.svidEnvelope("k21-target", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "k21", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: bound, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("k21"), seed: "k21",
		})
		out = append(out, aarpFixture{
			name: "k21-svid-replay-across-actions", category: catKillSuite, attackClass: "svid-replay",
			description: "an SVID binding minted for one receipt replayed onto another: the recomputed binding digest differs, the proof-of-possession fails, and the identity claims are withheld",
			verdict:     verdictAppraise, body: g.marshal(target), pipelockShaped: true,
			svid:               &svidsidecar.Sidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))},
			overclaimNarrative: "a valid SVID proof-of-possession is attached, so this action's signing workload is identity-verified",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{aarp.ClaimSigningWorkloadSVIDChainValidated, aarp.ClaimSigningWorkloadSVIDBound},
		})
	}

	// k22: assurance-as-grade. The producer claims a marketing-style "high assurance
	// certified" grade, hoping the appraiser's assurance descriptor reads as a score.
	// The assurance output is only the set of axes that hold verified claims, never a
	// grade; the producer's grade claim is unverified. (assurance-as-grade)
	{
		e := aarp.Envelope{Subject: g.baseSubject("k22"), Assertion: baseAssertion("mediated", claimHighAssurance)}
		e = g.signEd(e, keyIDSigner, roleMediator, g.signerPriv)
		out = append(out, aarpFixture{
			name: "k22-assurance-as-grade", category: catKillSuite, attackClass: "assurance-as-grade",
			description: "a 'high assurance certified' grade claim: the assurance output is an axis-set descriptor, never a grade, so the grade claim is not confirmed",
			verdict:     verdictAppraise, body: g.marshal(e), pipelockShaped: true,
			overclaimNarrative: "this receipt is certified high-assurance",
			mustVerify:         ksVerifyNarrow,
			mustNotVerify:      []string{claimHighAssurance},
		})
	}

	// k23: untrusted issuer claiming workload identity (non-Pipelock-shaped). A
	// full-looking SVID attestation whose ENVELOPE signature is under an untrusted
	// key. SVID claims attach only to a signed assertion, so with no verified
	// signature the assertion is unsigned and NONE of the identity claims attach —
	// the attestation rides on a receipt nobody trusts. (unsigned-svid-host)
	{
		e := g.svidEnvelope("k23", svidTrustDomain, keyIDOther, g.otherPriv)
		lf := g.issueLeaf(ca, "k23", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: e, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("k23"), seed: "k23",
		})
		out = append(out, aarpFixture{
			name: "k23-untrusted-issuer-svid", category: catKillSuite, attackClass: "unsigned-svid-host",
			description: "a complete SVID attestation on a receipt signed by an untrusted key: the assertion is unsigned, so the workload-identity claims never attach",
			verdict:     verdictAppraise, body: g.marshal(e),
			svid:               &svidsidecar.Sidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))},
			overclaimNarrative: "a valid SVID is attached, so the signing workload identity is verified regardless of the receipt signer",
			mustNotVerify:      []string{aarp.ClaimReceiptSignatureValid, aarp.ClaimSigningWorkloadSVIDChainValidated, aarp.ClaimSigningWorkloadSVIDBound},
		})
	}

	return out
}
