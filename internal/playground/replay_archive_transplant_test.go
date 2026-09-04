// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"encoding/json"
	"strings"
	"testing"
)

// Editing any field of an authorization also breaks its signature, so the
// signature check masks the artifact-binding check for every tampering case.
// The binding check earns its place against the one attack the signature cannot
// catch: lifting a GENUINELY signed authorization off one published run and
// presenting it alongside a different run's evidence. Without this test,
// removing the binding check entirely breaks nothing in the suite.
func TestVerifyReplayArchiveAuthorization_RefusesATransplantedAuthorization(t *testing.T) {
	pub, _, raw, authorized := archiveAuthorizationFixture(t)

	// A second run under the same root: its own nonce, digest and delegation.
	other := validDelegation(pub)
	other.RunNonce = "a-different-published-run"
	otherManifest := LaunchManifest{
		RunNonce:     other.RunNonce,
		DelegationID: other.DelegationID,
		ImageDigest:  other.ImageDigest,
	}
	otherRaw, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}

	// The authorization is untouched and its signature still verifies; only the
	// evidence beside it has been swapped.
	err = VerifyReplayArchiveAuthorization(pub, authorized, otherManifest, otherRaw)
	if err == nil {
		t.Fatal("a validly signed authorization from another run must not authorize this one")
	}
	if !strings.Contains(err.Error(), "does not bind these run artifacts") {
		t.Fatalf("error = %v, want the artifact-binding refusal rather than a signature failure", err)
	}

	// Control: the same authorization still accepts the run it was issued for,
	// so the refusal above comes from the binding and not from a broken fixture.
	_, lm, ownRaw, own := archiveAuthorizationFixture(t)
	if err := VerifyReplayArchiveAuthorization(pub, own, lm, ownRaw); err != nil {
		t.Fatalf("the authorization was rejected for its own run: %v", err)
	}
	_ = raw
}
