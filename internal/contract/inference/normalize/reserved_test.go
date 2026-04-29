// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"sort"
	"testing"
)

func TestCanonicalReservedSegments_NoDuplicatesNoEmpty(t *testing.T) {
	t.Parallel()

	got := CanonicalReservedSegments()
	if len(got) == 0 {
		t.Fatalf("CanonicalReservedSegments() returned empty list")
	}

	seen := make(map[string]bool, len(got))
	for i, s := range got {
		if s == "" {
			t.Errorf("entry %d is empty", i)
		}
		if seen[s] {
			t.Errorf("duplicate entry %q at index %d", s, i)
		}
		seen[s] = true
	}
}

func TestCanonicalReservedSegments_MatchesDesign(t *testing.T) {
	t.Parallel()

	// Design-drift guard. The reserved-segment list in the contract
	// inference engine design is the source of truth. If it bumps,
	// this test fails and forces an update with audit trail rather
	// than a silent change.
	want := []string{
		"admin", "auth", "auth0", "billing", "ca",
		"cert", "key", "kms", "login", "me",
		"mfa", "oauth", "orgs", "password", "payment",
		"refund", "saml", "secret", "settings", "ssh",
		"ssl", "sso", "token", "transfer", "users",
		"vault", "withdraw",
	}

	got := CanonicalReservedSegments()
	if len(got) != len(want) {
		t.Fatalf("CanonicalReservedSegments() returned %d entries, want %d", len(got), len(want))
	}

	gotSorted := append([]string(nil), got...)
	sort.Strings(gotSorted)

	for i, w := range want {
		if gotSorted[i] != w {
			t.Errorf("sorted entry %d = %q, want %q", i, gotSorted[i], w)
		}
	}
}

func TestCanonicalReservedSegments_ReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	first := CanonicalReservedSegments()
	if len(first) == 0 {
		t.Fatalf("CanonicalReservedSegments() returned empty list")
	}
	original := first[0]
	first[0] = "MUTATED"

	second := CanonicalReservedSegments()
	if second[0] != original {
		t.Fatalf("second call returned %q at index 0, want %q — package-level slice was mutated through returned reference (security regression)", second[0], original)
	}
}

func TestIsReserved_HappyPath(t *testing.T) {
	t.Parallel()

	canonical := CanonicalReservedSegments()
	for _, c := range canonical {
		t.Run("canonical/"+c, func(t *testing.T) {
			t.Parallel()
			if !IsReserved(c, nil) {
				t.Fatalf("IsReserved(%q, nil) = false, want true", c)
			}
		})
	}

	notReserved := []string{"foo", "v1", "repos", "search", "items", "data"}
	for _, n := range notReserved {
		t.Run("non-canonical/"+n, func(t *testing.T) {
			t.Parallel()
			if IsReserved(n, nil) {
				t.Fatalf("IsReserved(%q, nil) = true, want false", n)
			}
		})
	}
}

func TestIsReserved_EmptyReturnsFalse(t *testing.T) {
	t.Parallel()

	if IsReserved("", nil) {
		t.Fatalf("IsReserved(\"\", nil) = true, want false (empty is not reserved)")
	}
	if IsReserved("", []string{"admin"}) {
		t.Fatalf("IsReserved(\"\", extras) = true, want false (empty is not reserved even with extras)")
	}
}

func TestIsReserved_ExtrasMatched(t *testing.T) {
	t.Parallel()

	extras := []string{"debug", "internal"}
	if !IsReserved("debug", extras) {
		t.Fatalf("IsReserved(\"debug\", %v) = false, want true (extras must be honored)", extras)
	}
	if !IsReserved("internal", extras) {
		t.Fatalf("IsReserved(\"internal\", %v) = false, want true (extras must be honored)", extras)
	}
	if IsReserved("staging", extras) {
		t.Fatalf("IsReserved(\"staging\", %v) = true, want false (not in extras or canonical)", extras)
	}
}

func TestIsReserved_ExtrasDoNotShadowCanonical(t *testing.T) {
	t.Parallel()

	// Empty/nil extras must not stop the canonical floor from
	// matching. Operators ADD to the floor; they cannot subtract.
	if !IsReserved("admin", nil) {
		t.Fatalf("IsReserved(\"admin\", nil) = false, want true")
	}
	if !IsReserved("admin", []string{}) {
		t.Fatalf("IsReserved(\"admin\", []) = false, want true")
	}
	if !IsReserved("admin", []string{"unrelated"}) {
		t.Fatalf("IsReserved(\"admin\", [\"unrelated\"]) = false, want true (canonical still applies)")
	}
}

func TestIsReserved_CaseSensitive(t *testing.T) {
	t.Parallel()

	// The function trusts the caller has normalized the input. Path.go
	// (next wave) lowercases before calling. Passing a non-normalized
	// form is the caller's bug, not the predicate's job to fix.
	if IsReserved("ADMIN", nil) {
		t.Fatalf("IsReserved(\"ADMIN\", nil) = true, want false (predicate is byte-exact, no folding)")
	}
	if IsReserved("Admin", nil) {
		t.Fatalf("IsReserved(\"Admin\", nil) = true, want false (predicate is byte-exact, no folding)")
	}
}

func TestIsReserved_ExactMatchOnly(t *testing.T) {
	t.Parallel()

	// Substring is not match: prefixes, suffixes, and embedded
	// occurrences must not match.
	notMatches := []string{"administrator", "admins", "myadmin", "auths", "uauth", "tokens"}
	for _, s := range notMatches {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			if IsReserved(s, nil) {
				t.Fatalf("IsReserved(%q, nil) = true, want false (substring is not match)", s)
			}
		})
	}
}
