// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
)

// SVID corpus certificate/action windows. All fixed; no wall clock. The action
// time sits inside [leafValidFrom, leafValidTo] for the valid baselines; the
// hostile fixtures move one boundary at a time.
var (
	svidCANotBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	leafValidFrom   = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leafValidTo     = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	leafExpiredTo   = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)   // < action time
	leafFutureFrom  = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)   // > action time
	leafExpiryEarly = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)   // for issued-at-after-expiry
	staleGenClose   = time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC) // generation closes before action

	// svidActionInWindow is the point-in-time the SVID is validated at; it equals
	// the fixed assertion issued_at (tsIssued) and falls inside the valid window.
	svidActionInWindow = tsIssued
	// issuedAtAfterExpiry stamps the binding after the (early-expiry) leaf window.
	issuedAtAfterExpiry = "2026-06-01T00:00:00.000000000Z"
)

// svidEnvelope builds and signs a base SVID receipt envelope: claims mediated +
// workload_identity_verified, carries the trust domain (required with a binding),
// signed by the given key/role.
func (g *aarpGen) svidEnvelope(label, trustDomain, keyID string, priv ed25519.PrivateKey) aarp.Envelope {
	e := aarp.Envelope{
		Subject:   g.baseSubject(label),
		Assertion: baseAssertion("mediated", aarp.ClaimWorkloadIdentityVerified),
	}
	e.Assertion.TrustDomain = trustDomain
	return g.signEd(e, keyID, roleMediator, priv)
}

// openBundle is a single open-ended pinned generation holding the corpus CA.
func openBundle(ca *testCA) []svidBundleGen {
	return []svidBundleGen{{
		NotBefore:         rfc(svidCANotBefore),
		AuthoritiesDERB64: []string{b64std(ca.der)},
	}}
}

// verifyBlock builds the verifier-pinned block for a fixture validated at the
// given action time against the given bundle. The trust domain is always the
// corpus domain — trust-domain confusion is exercised on the ENVELOPE assertion
// domain (via svidEnvelope), not by mis-pinning the verifier.
func verifyBlock(actionTime string, bundle []svidBundleGen) svidVerifyBlock {
	return svidVerifyBlock{TrustDomain: svidTrustDomain, ActionTime: actionTime, Bundle: bundle}
}

// svidFixtures returns the SVID X.509 attestation arm of the corpus: two valid
// baselines (ECDSA-P256 and Ed25519) plus the full hostile matrix. Every fixture
// is verdictAppraise; the malicious ones must appraise WITHOUT the three
// workload-identity claims (no inflation), the valid ones WITH them. The three
// Codex-finding fixtures are s01 (valid baseline), s09 (trust-domain confusion),
// and s15 (issued-at-after-leaf-expiry).
func (g *aarpGen) svidFixtures() []aarpFixture {
	ca := g.newEd25519CA("primary", "AARP Corpus Test CA", svidCANotBefore, time.Time{})
	var out []aarpFixture

	add := func(name, attackClass, description string, body []byte, sc *svidSidecar) {
		out = append(out, aarpFixture{
			name: name, category: catSVID, attackClass: attackClass,
			description: description, verdict: verdictAppraise, body: body, svid: sc,
		})
	}

	// s01: valid ECDSA-P256 SVID, binding verifies — the three workload-identity
	// claims attach. (Codex baseline: a genuine attestation MUST still verify.)
	{
		env := g.svidEnvelope("s01", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s01", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s01"), seed: "s01",
		})
		add("s01-valid-ecdsa-p256-baseline", "baseline-attestation",
			"a genuine ECDSA-P256 X.509-SVID binding verifies and confirms the workload-identity claims",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s02: valid Ed25519 SVID baseline.
	{
		env := g.svidEnvelope("s02", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s02", leafKindEd25519, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgEd25519,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s02"), seed: "s02",
		})
		add("s02-valid-ed25519-baseline", "baseline-attestation",
			"a genuine Ed25519 X.509-SVID binding verifies and confirms the workload-identity claims",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s03: replay across actions. Evidence bound to one receipt is attached to a
	// different one; the recomputed binding payload digest differs and the
	// proof-of-possession signature does not verify.
	{
		bound := g.svidEnvelope("s03-bound", svidTrustDomain, keyIDSigner, g.signerPriv)
		target := g.svidEnvelope("s03-target", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s03", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: bound, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s03"), seed: "s03",
		})
		add("s03-replay-across-actions", "replay",
			"a binding minted for one receipt does not verify when replayed onto a different action",
			g.marshal(target), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s04: SVID expired at action time (leaf NotAfter precedes the action).
	{
		env := g.svidEnvelope("s04", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s04", leafKindECDSAP256, leafValidFrom, leafExpiredTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: "2026-02-15T00:00:00.000000000Z", nonce: nonceFor("s04"), seed: "s04",
		})
		add("s04-expired-at-action-time", "expiry",
			"an SVID whose leaf expired before the action time does not validate point-in-time",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s05: SVID not yet valid at action time (leaf NotBefore follows the action).
	{
		env := g.svidEnvelope("s05", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s05", leafKindECDSAP256, leafFutureFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: "2026-07-01T00:00:00.000000000Z", nonce: nonceFor("s05"), seed: "s05",
		})
		add("s05-not-yet-valid-at-action-time", "expiry",
			"an SVID whose leaf is not yet valid at the action time does not validate point-in-time",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s06: wrong leaf key. The binding is signed by a different ECDSA key than the
	// leaf's; verification under the leaf public key fails.
	{
		env := g.svidEnvelope("s06", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s06", leafKindECDSAP256, leafValidFrom, leafValidTo)
		impostorKey := g.detECDSAKey(elliptic.P256(), "s06-impostor-key")
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: impostorKey, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s06"), seed: "s06",
		})
		add("s06-wrong-leaf-key", "forged-binding",
			"a binding signed by a key other than the SVID leaf does not verify",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s07: stale bundle. The pinned generation closed before the action time, so
	// no pinned bundle is authoritative at the action.
	{
		env := g.svidEnvelope("s07", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s07", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s07"), seed: "s07",
		})
		stale := []svidBundleGen{{NotBefore: rfc(svidCANotBefore), NotAfter: rfc(staleGenClose), AuthoritiesDERB64: []string{b64std(ca.der)}}}
		add("s07-stale-bundle", "stale-bundle",
			"no pinned bundle generation is authoritative at the action time; the SVID does not validate",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, stale)})
	}

	// s08: forked bundle root. The pinned bundle holds a different CA than the one
	// that issued the leaf, so the chain does not validate to pinned trust.
	{
		env := g.svidEnvelope("s08", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s08", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s08"), seed: "s08",
		})
		forkedCA := g.newEd25519CA("forked", "AARP Corpus Forked CA", svidCANotBefore, time.Time{})
		add("s08-forked-bundle-root", "forked-bundle",
			"the SVID chains to an issuer not present in the pinned bundle (a forked/foreign root)",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(forkedCA))})
	}

	// s09: trust-domain confusion. The SVID validates in example.org, but the
	// signed assertion declares a different trust domain. (Codex fixture.)
	{
		env := g.svidEnvelope("s09", svidWrongTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s09", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s09"), seed: "s09",
		})
		add("s09-trust-domain-confusion", "trust-domain-confusion",
			"a valid SVID from one trust domain cannot back an assertion declaring another trust domain",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s10: SPIFFE-ID substitution. The claimed spiffe_id differs from the leaf's
	// actual URI SAN.
	{
		env := g.svidEnvelope("s10", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s10", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDImposter, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s10"), seed: "s10",
		})
		add("s10-spiffe-id-substitution", "identity-substitution",
			"the claimed spiffe_id does not match the SVID leaf URI SAN; identity cannot be substituted",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s11: curve confusion. A P-384 leaf is presented under the ecdsa-p256-sha256
	// binding alg; the curve check rejects it (VerifyASN1 is curve-agnostic).
	{
		env := g.svidEnvelope("s11", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s11", leafKindECDSAP384, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s11"), seed: "s11",
		})
		add("s11-curve-confusion-p384", "curve-confusion",
			"a P-384 leaf under the P-256 binding alg is rejected: the alg id names a curve the key is not",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s12: short nonce. An under-128-bit nonce weakens replay resistance and is
	// rejected as malformed evidence.
	{
		env := g.svidEnvelope("s12", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s12", leafKindECDSAP256, leafValidFrom, leafValidTo)
		shortNonce := base64RawURL(detBytes("nonce/s12-short", 8)) // 64 bits < 128
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: shortNonce, seed: "s12",
		})
		add("s12-short-nonce", "weak-nonce",
			"a nonce below 128 bits is rejected; a producer cannot weaken cross-action replay resistance",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s13: unsigned assertion. The envelope is signed by an untrusted key, so the
	// assertion is not signed under trust; the binding never attaches a claim.
	{
		env := g.svidEnvelope("s13", svidTrustDomain, keyIDOther, g.otherPriv)
		lf := g.issueLeaf(ca, "s13", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s13"), seed: "s13",
		})
		add("s13-unsigned-assertion", "unsigned-assertion",
			"SVID evidence on an assertion not signed under trust attaches no workload-identity claim",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s14: JWT treated as verified. Only X.509-SVID counts; a jwt-typed evidence
	// object is rejected before any chain work.
	{
		env := g.svidEnvelope("s14", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s14", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "jwt", issuedAt: tsIssued, nonce: nonceFor("s14"), seed: "s14",
		})
		add("s14-jwt-treated-as-verified", "jwt-as-verified",
			"a JWT-SVID is bearer-only in v0.1; a jwt-typed evidence object never counts as verified workload identity",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s15: issued-at after leaf expiry. The leaf validates at the action time, but
	// the binding's issued_at falls after the leaf expired — post-expiry key use.
	// (Codex fixture.)
	{
		env := g.svidEnvelope("s15", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s15", leafKindECDSAP256, leafValidFrom, leafExpiryEarly)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: issuedAtAfterExpiry, nonce: nonceFor("s15"), seed: "s15",
		})
		add("s15-issued-at-after-leaf-expiry", "post-expiry-key-use",
			"the chain validates at the action time but the binding issued_at is after the leaf expired: post-expiry key use is rejected",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	// s16: forged binding signature. A valid binding's signature byte is flipped;
	// it no longer verifies under the leaf key.
	{
		env := g.svidEnvelope("s16", svidTrustDomain, keyIDSigner, g.signerPriv)
		lf := g.issueLeaf(ca, "s16", leafKindECDSAP256, leafValidFrom, leafValidTo)
		ev := g.buildEvidence(svidEvidenceParams{
			env: env, leafDER: lf.der, signer: lf.signer, alg: bindingAlgP256,
			spiffeID: svidIDAgentA, evidenceType: "x509", issuedAt: tsIssued, nonce: nonceFor("s16"), seed: "s16",
		})
		ev.Binding.SignatureB64 = flipB64Char(ev.Binding.SignatureB64)
		add("s16-forged-binding-signature", "forged-binding",
			"a tampered binding signature does not verify under the leaf key; no workload-identity claim attaches",
			g.marshal(env), &svidSidecar{Evidence: ev, Verify: verifyBlock(svidActionInWindow, openBundle(ca))})
	}

	return out
}
