//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"errors"
	"testing"
)

// TestPolicyHashForeignSchemeIsRejected pins the upgrade break that a release
// changing the canonical policy hash produces.
//
// A bundle published by an earlier release carries a policy_hash computed by
// THAT release's config canonicaliser. When the canonical policy hash moves, the
// value recomputed here no longer matches, and LegacyPolicyHash is a different
// and much older scheme (raw YAML, pre-LoadPolicyBundleBytes) rather than "the
// previous release's scheme", so it does not match either. Both validation
// entry points therefore reject a bundle that is otherwise entirely well formed.
//
// Reproduced live against the real thing: a bundle published by a v3.2.0
// conductor is reported by v3.3.0 as
//
//	conductor hash mismatch: policy_hash
//
// which stops the leader before it can serve, with no operator path out
// (`conductor store repair` classifies such records as unreadable and refuses to
// remove them).
//
// This test documents the CURRENT behaviour so the fix has something to flip. A
// foreign-scheme hash stands in for a prior release's canonicalisation: what
// matters is that it is a well-formed hash produced by neither scheme this build
// knows, which is exactly the position every already-published bundle is in.
func TestPolicyHashForeignSchemeIsRejected(t *testing.T) {
	bundle := testPolicyBundle()

	currentHash, err := bundle.Payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash() error = %v", err)
	}
	legacyHash, err := bundle.Payload.LegacyPolicyHash()
	if err != nil {
		t.Fatalf("LegacyPolicyHash() error = %v", err)
	}

	// A well-formed hash belonging to neither known scheme.
	foreignHash := testHash("ab")
	if foreignHash == currentHash || foreignHash == legacyHash {
		t.Fatalf("fixture is not foreign to both schemes: foreign=%s current=%s legacy=%s",
			foreignHash, currentHash, legacyHash)
	}
	bundle.PolicyHash = foreignHash

	// Publish stays strict: a publisher must always produce a hash its own build
	// can reproduce, and that is the only place the check means anything.
	if err := bundle.Validate(); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("Validate(foreign scheme policy_hash) = %v, want ErrHashMismatch", err)
	}

	// Reading an already-stored bundle tolerates it, because refusing here is
	// what stopped the leader booting after upgrade and stopped followers
	// applying mid-rollout, while protecting nothing: see validateHashes.
	if err := bundle.ValidateAllowLegacyPolicyHash(); err != nil {
		t.Fatalf("ValidateAllowLegacyPolicyHash(foreign scheme policy_hash) = %v, want nil", err)
	}

	// Tolerated is not the same as verified, and the status must say so.
	status := bundle.PolicyHashStatus()
	if status != PolicyHashUnknownUnverified {
		t.Fatalf("PolicyHashStatus() = %q, want %q", status, PolicyHashUnknownUnverified)
	}
	if status.Reproducible() {
		t.Fatal("PolicyHashStatus().Reproducible() = true for a hash this build cannot compute, want false")
	}

	// Everything else about the bundle is sound, which is what makes the refusal
	// an upgrade break rather than corruption detection: the payload digest still
	// agrees with the payload.
	if err := bundle.VerifyPayloadHash(); err != nil {
		t.Fatalf("VerifyPayloadHash() error = %v, want nil (only policy_hash differs)", err)
	}

	// A bundle whose hash IS reproducible must still report so, otherwise the
	// tolerance would be hiding real drift rather than describing it.
	bundle.PolicyHash = currentHash
	if status := bundle.PolicyHashStatus(); status != PolicyHashCurrent {
		t.Fatalf("PolicyHashStatus(current hash) = %q, want %q", status, PolicyHashCurrent)
	}
	bundle.PolicyHash = legacyHash
	if status := bundle.PolicyHashStatus(); status != PolicyHashKnownLegacy {
		t.Fatalf("PolicyHashStatus(legacy hash) = %q, want %q", status, PolicyHashKnownLegacy)
	}
}
