//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"errors"
	"testing"
	"time"
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

// TestValidateAtTimeAllowLegacyPolicyHashStillChecksValidity pins that tolerating
// an unreproducible policy hash relaxed only the hash decision. The freshness
// window is a separate guard and a tolerated bundle must still be refused outside
// it, otherwise the tolerance would quietly hand callers an expired or not-yet
// valid bundle that the strict path would have rejected.
func TestValidateAtTimeAllowLegacyPolicyHashStillChecksValidity(t *testing.T) {
	bundle := testPolicyBundle()
	bundle.PolicyHash = testHash("ab")
	if status := bundle.PolicyHashStatus(); status != PolicyHashUnknownUnverified {
		t.Fatalf("fixture PolicyHashStatus() = %q, want %q", status, PolicyHashUnknownUnverified)
	}

	// In window: the hash is tolerated and the bundle is accepted.
	inWindow := bundle.NotBefore.Add(time.Minute)
	if err := bundle.ValidateAtTimeAllowLegacyPolicyHash(inWindow); err != nil {
		t.Fatalf("ValidateAtTimeAllowLegacyPolicyHash(in window) = %v, want nil", err)
	}

	// Before NotBefore: refused despite the tolerated hash. The window start
	// deliberately tolerates bounded clock skew (MessageNotBeforeSkew), so the
	// probe has to sit clearly outside that allowance to be testing the guard
	// rather than the skew.
	tooEarly := bundle.NotBefore.Add(-(MessageNotBeforeSkew + time.Minute))
	if err := bundle.ValidateAtTimeAllowLegacyPolicyHash(tooEarly); err == nil {
		t.Fatal("ValidateAtTimeAllowLegacyPolicyHash(before not_before beyond skew) = nil, want refusal")
	}

	// And just inside the skew allowance is still accepted, so the test above is
	// pinning the guard rather than accidentally pinning the skew window.
	if err := bundle.ValidateAtTimeAllowLegacyPolicyHash(bundle.NotBefore.Add(-time.Second)); err != nil {
		t.Fatalf("ValidateAtTimeAllowLegacyPolicyHash(within not_before skew) = %v, want nil", err)
	}

	// After ExpiresAt: likewise refused.
	if err := bundle.ValidateAtTimeAllowLegacyPolicyHash(bundle.ExpiresAt.Add(time.Minute)); err == nil {
		t.Fatal("ValidateAtTimeAllowLegacyPolicyHash(after expires_at) = nil, want refusal")
	}
}

// TestPolicyHashUnparseableConfigIsToleratedWhenReadingStoredState covers the
// second door into the same upgrade failure, which the first version of this fix
// left open.
//
// Computing policy_hash parses the bundle's config through the CURRENT schema, so
// a stored bundle whose config sets a field this release removed does not merely
// produce a DIFFERENT hash, it makes the computation ERROR. Returning that error
// before consulting the tolerance put the leader straight back to not starting.
//
// This is not hypothetical for this release: it removes three denial-of-wallet
// budget fields, and a bundle published before that removal can carry them.
func TestPolicyHashUnparseableConfigIsToleratedWhenReadingStoredState(t *testing.T) {
	bundle := testPolicyBundle()
	// A field the current schema rejects, standing in for anything a later release
	// removes. The point is that PolicyHash cannot be computed at all.
	bundle.Payload = PolicyBundlePayload{
		ConfigYAML: "mode: strict\ndlp:\n  removed_knob_from_a_later_release: true\n",
	}
	bundle.PayloadSHA256 = mustPayloadHash(bundle.Payload)

	if _, err := bundle.Payload.PolicyHash(); err == nil {
		t.Fatal("fixture PolicyHash() = nil error, want a parse failure so this test exercises the error path")
	}

	// Publish stays strict: the build computing the hash is the build that made the
	// bundle, so a config it cannot parse is a real error and must surface.
	if err := bundle.Validate(); err == nil {
		t.Fatal("Validate(unparseable config) = nil, want the parse error to surface on the strict path")
	}

	// Reading stored state tolerates it. Refusing here is the crashloop this
	// change exists to prevent, and the payload digest above still binds the
	// payload.
	if err := bundle.ValidateAllowLegacyPolicyHash(); err != nil {
		t.Fatalf("ValidateAllowLegacyPolicyHash(unparseable config) = %v, want nil", err)
	}

	// And it reports itself as unreproducible rather than current, so nothing
	// downstream can present the stored hash as a verified digest.
	status := bundle.PolicyHashStatus()
	if status != PolicyHashUnknownUnverified {
		t.Fatalf("PolicyHashStatus() = %q, want %q", status, PolicyHashUnknownUnverified)
	}
	if status.Reproducible() {
		t.Fatal("PolicyHashStatus().Reproducible() = true for an unparseable config, want false")
	}
}
