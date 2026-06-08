// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// TrustEntry binds a signing key id to an authority namespace, never to a bare
// key. A verified mediated claim requires the verifying signature's key id to
// match a TrustEntry whose mediator id (and, when set, signer role and trust
// domain) agree with the assertion. An attacker self-signing with
// signer_role=mediator and no matching entry gets mediated reported claim-only.
type TrustEntry struct {
	// MediatorID is the mediator identity this key is authorized to assert.
	MediatorID string
	// Role, when non-empty, is the signer_role the key is authorized to use.
	Role string
	// TrustDomain, when non-empty, is the trust domain the assertion must carry.
	TrustDomain string
}

// VerifyOptions configures appraisal. It carries the verifier's pinned trust,
// never anything fetched live.
type VerifyOptions struct {
	// TrustedKeys maps a key id to its Ed25519 public key. A signature whose key
	// id is absent is reported unknown_key and never counts as verified.
	TrustedKeys map[string]ed25519.PublicKey
	// Trust maps a key id to its authority-namespace binding. A key id present
	// in TrustedKeys but absent from Trust can still verify a signature, but
	// cannot confirm the mediator_key_pinned claim.
	Trust map[string]TrustEntry
}

// claimVerifiedBy maps each producer claim name to the set of verified-claim
// names that must all be present for the producer claim to count as confirmed.
// A nil value means the claim is structurally claim-only in v0.1 (never
// verifiable), so it is always reported unverified.
//
// The KEYS are the producer's input claim vocabulary (what a producer writes in
// assertion.claimed); they are part of the receipt input and stay stable. The
// VALUES are the verifier's literal output claim names, which this PR renamed —
// so a producer that still claims the legacy "workload_identity_verified" string
// is confirmed by the renamed verified claim it now maps to.
var claimVerifiedBy = map[string][]string{
	"mediated":                   {ClaimMediatorKeyPinned},
	"complete-mediation":         nil,
	"complete_mediation":         nil,
	"workload_identity_verified": {ClaimSigningWorkloadSVIDChainValidated},
	"x509_svid_bound":            {ClaimSigningWorkloadSVIDBound},
	"svid_valid_at_action_time":  {ClaimSigningWorkloadSVIDValidAtActionTime},
	"transparency_inclusion":     nil,
}

// Verify appraises an AARP envelope and returns a structured result. It rejects
// the envelope (returns a nil appraisal and an error) only for envelope-fatal
// conditions: a schema violation, a profile/canon mismatch, or an unknown
// critical extension. Per-signature problems (unknown or unimplemented suite,
// untrusted key, invalid signature) are reported in the appraisal, never as a
// hard rejection, so one bad parallel signature cannot mask a good one.
//
// The appraisal never reports "trusted" or "safe". A relying party applies its
// own claim policy to the verified_claims and axes.
func Verify(e Envelope, opts VerifyOptions) (*Appraisal, error) {
	ap, err := appraiseCore(e, opts)
	if err != nil {
		return nil, err
	}
	classifyClaims(ap)
	ap.finalize()
	return ap, nil
}

// appraiseCore runs the full envelope appraisal EXCEPT the final claim
// classification, returning an appraisal whose verified claims are populated.
// Verify finishes it with classifyClaims; AppraiseWithSVID adds the
// workload-identity claims first, then classifies, so an attestation claim moves
// from claimed-unverified to verified in one consistent pass.
func appraiseCore(e Envelope, opts VerifyOptions) (*Appraisal, error) {
	if err := e.validateStructure(); err != nil {
		return nil, err
	}
	digest, err := e.PayloadDigest()
	if err != nil {
		return nil, err
	}

	ap := newAppraisal()
	ap.AssuranceClaimed = append([]string(nil), e.Assertion.Claimed...)

	var verified []verifiedSigner
	for _, s := range e.Signatures {
		res, ok := appraiseSignature(s, digest, opts)
		ap.Signatures = append(ap.Signatures, res)
		if ok {
			verified = append(verified, verifiedSigner{keyID: s.Protected.KeyID, role: s.Protected.SignerRole})
		}
	}

	if len(verified) > 0 {
		ap.AssertionSigned = true
		ap.addVerified(ClaimReceiptSignatureValid, AxisIntegrity)
		if mediatorKeyPinned(e.Assertion, verified, opts.Trust) {
			ap.addVerified(ClaimMediatorKeyPinned, AxisIdentity)
		}
		if e.Chain != nil {
			// A signed chain link is present (its position is authenticated by
			// the verified signature). Stream continuity is NOT asserted here;
			// VerifyChain over the stream is the authority for that.
			ap.addVerified(ClaimReceiptTimestampMonotonicChainPresent, AxisIntegrity)
		}
	} else {
		// Without any verified signature, every producer claim is untrusted
		// input, not a producer-authored claim.
		ap.Warnings = append(ap.Warnings, "no signature verified under a trusted key; all assurance claims are untrusted input")
	}
	return ap, nil
}

// appraiseSignature verifies one parallel signature and returns its result plus
// whether it verified. It never falls back: an unknown or unimplemented suite,
// an untrusted key, or an invalid signature all yield verified=false.
func appraiseSignature(s Signature, digest string, opts VerifyOptions) (SignatureResult, bool) {
	res := SignatureResult{KeyID: s.Protected.KeyID, Alg: s.Protected.Alg, Role: s.Protected.SignerRole}

	// Per-signature suite identity. A wrong profile/canon or an unknown critical
	// extension in THIS signature's protected header makes only this signature
	// unverifiable — it never rejects the envelope, so an appended junk signature
	// cannot deny a verifiable sibling. (The signed top-level profile and
	// crit_ext are checked envelope-fatal in validateStructure.)
	if s.Protected.Profile != Profile {
		res.Status, res.Reason = SigUnknownSuite, fmt.Sprintf("profile %q != %q", s.Protected.Profile, Profile)
		return res, false
	}
	if s.Protected.Canon != CanonID {
		res.Status, res.Reason = SigUnknownSuite, fmt.Sprintf("canon %q != %q", s.Protected.Canon, CanonID)
		return res, false
	}
	if err := checkCriticalExtensions(s.Protected.Crit); err != nil {
		if errors.Is(err, ErrUnknownCriticalExtension) {
			res.Status, res.Reason = SigUnknownSuite, err.Error()
		} else {
			res.Status, res.Reason = SigMalformed, err.Error()
		}
		return res, false
	}

	if s.Protected.KeyID == "" {
		res.Status, res.Reason = SigMalformed, "empty key_id"
		return res, false
	}
	if !knownSignerRoles[s.Protected.SignerRole] {
		res.Status, res.Reason = SigMalformed, "unknown signer_role"
		return res, false
	}
	wantKeyType, known := keyTypeForAlg[AlgID(s.Protected.Alg)]
	if !known {
		res.Status, res.Reason = SigUnknownSuite, "unrecognized algorithm; no fallback"
		return res, false
	}
	if s.Protected.KeyType != wantKeyType {
		res.Status, res.Reason = SigMalformed, fmt.Sprintf("key_type %q != %q required by alg", s.Protected.KeyType, wantKeyType)
		return res, false
	}
	if !implementedAlgs[AlgID(s.Protected.Alg)] {
		res.Status, res.Reason = SigUnimplemented, "recognized suite, verifier not yet built"
		return res, false
	}

	// Implemented suite: Ed25519.
	pub, ok := opts.TrustedKeys[s.Protected.KeyID]
	if !ok {
		res.Status, res.Reason = SigUnknownKey, "key_id not in trusted set"
		return res, false
	}
	if len(pub) != ed25519.PublicKeySize {
		res.Status, res.Reason = SigMalformed, "trusted key has wrong size"
		return res, false
	}
	input, err := signingInput(digest, s.Protected)
	if err != nil {
		res.Status, res.Reason = SigMalformed, "signing input: "+err.Error()
		return res, false
	}
	raw, err := decodeSigWire(s.Protected.Alg, s.Sig)
	if err != nil {
		res.Status, res.Reason = SigMalformed, err.Error()
		return res, false
	}
	if len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, input, raw) {
		res.Status, res.Reason = SigFailed, "signature does not verify over canonical bytes"
		return res, false
	}
	res.Status = SigVerified
	return res, true
}

// verifiedSigner is a signature that verified under a trusted key, carrying the
// key id and the signer role from its protected header so the trust-entry check
// can enforce role scoping.
type verifiedSigner struct {
	keyID string
	role  string
}

// mediatorKeyPinned reports whether any verifying signature is bound by a trust
// entry to the asserted mediator identity, and (when the entry sets them) the
// signer role and trust domain. The role is checked against the role carried by
// the verifying signature, so a key scoped to e.g. "countersig" cannot satisfy
// a mediated claim made under "mediator".
func mediatorKeyPinned(a Assertion, verified []verifiedSigner, trust map[string]TrustEntry) bool {
	for _, vs := range verified {
		entry, ok := trust[vs.keyID]
		if !ok {
			continue
		}
		if entry.MediatorID != a.MediatorID {
			continue
		}
		if entry.TrustDomain != "" && entry.TrustDomain != a.TrustDomain {
			continue
		}
		if entry.Role != "" && entry.Role != vs.role {
			continue
		}
		return true
	}
	return false
}

// classifyClaims fills ClaimedUnverified from the producer claims that the
// verifier did not confirm. A claim whose required verified-claims are all
// present is satisfied; everything else (claim-only, unknown, or unmet) is
// reported unverified.
func classifyClaims(ap *Appraisal) {
	verified := make(map[string]struct{}, len(ap.VerifiedClaims))
	for _, c := range ap.VerifiedClaims {
		verified[c] = struct{}{}
	}
	// Deduplicate producer claims so a repeated claim name does not inflate the
	// claimed-unverified list a relying party might count.
	seenClaim := make(map[string]struct{}, len(ap.AssuranceClaimed))
	for _, claimed := range ap.AssuranceClaimed {
		if _, dup := seenClaim[claimed]; dup {
			continue
		}
		seenClaim[claimed] = struct{}{}
		required, known := claimVerifiedBy[claimed]
		if !known {
			ap.ClaimedUnverified = append(ap.ClaimedUnverified, claimed)
			ap.Warnings = append(ap.Warnings, "unknown assurance claim reported claim-only: "+claimed)
			continue
		}
		if len(required) == 0 {
			ap.ClaimedUnverified = append(ap.ClaimedUnverified, claimed)
			continue
		}
		if allPresent(required, verified) {
			continue
		}
		ap.ClaimedUnverified = append(ap.ClaimedUnverified, claimed)
	}
}

func allPresent(required []string, have map[string]struct{}) bool {
	for _, r := range required {
		if _, ok := have[r]; !ok {
			return false
		}
	}
	return true
}
