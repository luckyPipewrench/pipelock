// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// The rich golden fixtures do NOT configure path_entropy_exclusions, so they
// prove nothing about how this field canonicalizes. An earlier claim that they
// did was wrong. These exercise the field directly.
//
// The contract: scheme, host and path prefix decide whether the path gate runs
// and therefore belong in the policy hash a receipt carries. Reason, owner and
// expiry are for the operator reading the config later and must NOT move the
// hash, or editing a comment would look like a policy change in signed
// evidence.

func hashWithPathExclusions(t *testing.T, entries ...PathEntropyExclusion) string {
	t.Helper()
	cfg := Defaults()
	cfg.FetchProxy.Monitoring.PathEntropyExclusions = entries
	return cfg.CanonicalPolicyHash()
}

// POSITIVE CONTROL, and it comes first because every invariance test below is
// vacuous without it: a canonicalization that discarded the whole field would
// satisfy all of them. Changing the route must move the hash.
func TestPathEntropyExclusionsChangeTheCanonicalHash(t *testing.T) {
	t.Parallel()

	none := hashWithPathExclusions(t)
	one := hashWithPathExclusions(t, PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/d/"})
	if none == one {
		t.Fatal("adding a path exclusion did not change the policy hash; the field is not reaching the canonical view")
	}

	otherHost := hashWithPathExclusions(t, PathEntropyExclusion{Host: "drive.vendor.example", PathPrefix: "/document/d/"})
	if one == otherHost {
		t.Error("changing the host did not change the policy hash")
	}
	otherPrefix := hashWithPathExclusions(t, PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/file/d/"})
	if one == otherPrefix {
		t.Error("changing the path prefix did not change the policy hash")
	}
}

// Entry order is an authoring detail, not policy. Two configs listing the same
// routes in different orders describe the same policy and must hash the same,
// or a reordering would look like a policy change in a receipt.
func TestPathEntropyExclusionsHashIsOrderInvariant(t *testing.T) {
	t.Parallel()

	a := PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/d/"}
	b := PathEntropyExclusion{Host: "drive.vendor.example", PathPrefix: "/file/d/"}
	c := PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/spreadsheets/d/"}

	forward := hashWithPathExclusions(t, a, b, c)
	reversed := hashWithPathExclusions(t, c, b, a)
	if forward != reversed {
		t.Fatalf("entry order changed the policy hash:\n  forward  %s\n  reversed %s", forward, reversed)
	}
}

// Host case and a trailing dot are the same host. Scheme defaults to https.
// None of these are policy differences.
func TestPathEntropyExclusionsHashIsNormalizationInvariant(t *testing.T) {
	t.Parallel()

	plain := hashWithPathExclusions(t, PathEntropyExclusion{
		Scheme: "https", Host: "docs.vendor.example", PathPrefix: "/document/d/",
	})

	for name, entry := range map[string]PathEntropyExclusion{
		"uppercase host":   {Scheme: "https", Host: "DOCS.Vendor.Example", PathPrefix: "/document/d/"},
		"trailing dot":     {Scheme: "https", Host: "docs.vendor.example.", PathPrefix: "/document/d/"},
		"scheme omitted":   {Host: "docs.vendor.example", PathPrefix: "/document/d/"},
		"scheme uppercase": {Scheme: "HTTPS", Host: "docs.vendor.example", PathPrefix: "/document/d/"},
	} {
		if got := hashWithPathExclusions(t, entry); got != plain {
			t.Errorf("%s changed the policy hash:\n  want %s\n  got  %s", name, plain, got)
		}
	}
}

// Governance metadata must not move the hash. This is the property that lets an
// operator correct a reason, hand over ownership, or extend an expiry without
// it reading as a policy change in signed evidence.
func TestPathEntropyExclusionsHashIgnoresGovernanceMetadata(t *testing.T) {
	t.Parallel()

	bare := hashWithPathExclusions(t, PathEntropyExclusion{
		Host: "docs.vendor.example", PathPrefix: "/document/d/",
	})
	annotated := hashWithPathExclusions(t, PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
		Reason:     "service-issued document identifier",
		Owner:      "platform",
		Expires:    "2027-01-01",
	})
	if bare != annotated {
		t.Fatalf("reason/owner/expires moved the policy hash:\n  bare      %s\n  annotated %s", bare, annotated)
	}

	changed := hashWithPathExclusions(t, PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
		Reason:     "a different reason entirely",
		Owner:      "someone else",
		Expires:    "2030-12-31",
	})
	if changed != bare {
		t.Fatalf("editing governance metadata moved the policy hash; an operator correcting a comment would look like a policy change")
	}
}
