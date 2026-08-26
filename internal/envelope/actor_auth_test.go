// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import "testing"

// TestTrustedForIdentity pins which provenance grades may present a label as an
// identity to an external consumer.
//
// ActorAuthMatched is excluded ON PURPOSE and is the case most likely to be
// "fixed" by someone reading the name and assuming a match is a verification.
// It means a caller supplied a name that happens to match a configured profile,
// which proves the name exists and nothing about who sent it.
func TestTrustedForIdentity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		auth ActorAuth
		want bool
	}{
		{"infrastructure bound", ActorAuthBound, true},
		{"operator configured", ActorAuthConfigDefault, true},
		{"caller named a known profile", ActorAuthMatched, false},
		{"caller self declared", ActorAuthSelfDeclared, false},
		{"grade never recorded", ActorAuthUnknown, false},
		{"empty grade", ActorAuth(""), false},
		{"unrecognized grade", ActorAuth("totally-made-up"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.auth.TrustedForIdentity(); got != tc.want {
				t.Fatalf("ActorAuth(%q).TrustedForIdentity() = %v, want %v", tc.auth, got, tc.want)
			}
		})
	}
}

// TestNormalizeActorAuth pins the fail-closed default: anything the code does
// not recognize becomes ActorAuthUnknown, so a consumer can tell "we did not
// grade this" apart from "no actor present" and never reads an empty string as
// benign.
func TestNormalizeActorAuth(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want ActorAuth
	}{
		{"bound survives", string(ActorAuthBound), ActorAuthBound},
		{"config default survives", string(ActorAuthConfigDefault), ActorAuthConfigDefault},
		{"matched survives", string(ActorAuthMatched), ActorAuthMatched},
		{"self declared survives", string(ActorAuthSelfDeclared), ActorAuthSelfDeclared},
		{"empty becomes unknown", "", ActorAuthUnknown},
		{"garbage becomes unknown", "not-a-grade", ActorAuthUnknown},
		{"unknown stays unknown", string(ActorAuthUnknown), ActorAuthUnknown},
		{"wrong case is not trusted", "BOUND", ActorAuthUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeActorAuth(tc.raw); got != tc.want {
				t.Fatalf("NormalizeActorAuth(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestNormalizeThenTrustFailsClosed composes the two: every grade that
// normalization rejects must also be untrusted for identity. A future grade
// added to one function and not the other would break this.
func TestNormalizeThenTrustFailsClosed(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "BOUND", "not-a-grade", "unknown", "matched", "self-declared"} {
		if NormalizeActorAuth(raw).TrustedForIdentity() {
			t.Fatalf("raw grade %q normalized to a trusted identity grade", raw)
		}
	}
	for _, raw := range []string{"bound", "config-default"} {
		if !NormalizeActorAuth(raw).TrustedForIdentity() {
			t.Fatalf("raw grade %q should normalize to a trusted identity grade", raw)
		}
	}
}
