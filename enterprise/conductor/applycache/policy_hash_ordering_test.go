//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// foreignPolicyHash is a well-formed hash belonging to neither scheme this build
// can compute, standing in for a value produced by a prior release's config
// canonicaliser.
const foreignPolicyHash = "abababababababababababababababababababababababababababababababab"

// TestVerifyBundleSignatureGateRunsBeforePolicyHashTolerance pins the ordering
// invariant that makes the policy_hash tolerance safe on the follower.
//
// verifyBundle tolerates a policy_hash this build cannot reproduce, because a
// bundle published before a release moved the canonical policy hash is in
// exactly that position, and refusing it stops policy applying for the whole of
// a rolling upgrade. That tolerance is only defensible because
// VerifySignaturesAt runs FIRST. Were the tolerance ever moved above the
// signature check, a bundle of unknown provenance would be applied.
//
// Mutating PolicyHash after signing invalidates the signature, because the field
// sits inside the signable preimage. So a bundle in the tolerated policy-hash
// state with a broken signature must still be refused.
func TestVerifyBundleSignatureGateRunsBeforePolicyHashTolerance(t *testing.T) {
	key := newTestKey(t)
	bundle := signedTestBundle(t, key, "ordering-1", 1, "")

	// Sanity: as signed, this bundle verifies. Otherwise the negative case below
	// could pass for an unrelated reason.
	if err := verifyBundle(testNow, bundle, verifyOptions{
		Resolver: testResolver(key),
		Identity: Identity{OrgID: "org-1", FleetID: "fleet-1", InstanceID: "instance-1"},
	}); err != nil {
		t.Fatalf("verifyBundle(as signed) = %v, want nil", err)
	}

	bundle.PolicyHash = foreignPolicyHash
	if status := bundle.PolicyHashStatus(); status != conductor.PolicyHashUnknownUnverified {
		t.Fatalf("PolicyHashStatus() = %q, want %q", status, conductor.PolicyHashUnknownUnverified)
	}

	// The policy_hash is now tolerated, but provenance is broken, so the
	// signature gate must refuse it.
	if err := verifyBundle(testNow, bundle, verifyOptions{
		Resolver: testResolver(key),
		Identity: Identity{OrgID: "org-1", FleetID: "fleet-1", InstanceID: "instance-1"},
	}); err == nil {
		t.Fatal("verifyBundle(tolerated policy_hash, broken signature) = nil, want error")
	}
}

// TestVerifyBundleAcceptsForeignPolicyHashWhenProperlySigned is the positive half:
// a bundle signed OVER the unreproducible policy_hash, which is what an older
// leader actually publishes, must apply. This is the case that was refused and
// that stopped a rolling upgrade.
func TestVerifyBundleAcceptsForeignPolicyHashWhenProperlySigned(t *testing.T) {
	key := newTestKey(t)
	bundle := signedTestBundle(t, key, "ordering-2", 1, "")

	// Re-sign over the foreign hash so provenance is intact, exactly as a prior
	// release's publisher would have produced it.
	bundle.PolicyHash = foreignPolicyHash
	bundle.Signatures = []conductor.SignatureProof{signProof(t, key, bundle.SignablePreimage)}

	if status := bundle.PolicyHashStatus(); status != conductor.PolicyHashUnknownUnverified {
		t.Fatalf("PolicyHashStatus() = %q, want %q", status, conductor.PolicyHashUnknownUnverified)
	}
	if err := verifyBundle(testNow, bundle, verifyOptions{
		Resolver: testResolver(key),
		Identity: Identity{OrgID: "org-1", FleetID: "fleet-1", InstanceID: "instance-1"},
	}); err != nil {
		t.Fatalf("verifyBundle(properly signed, unreproducible policy_hash) = %v, want nil", err)
	}
}
