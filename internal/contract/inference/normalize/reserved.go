// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

// reservedSegmentsCanonical is the security-floor list of path
// segments that cannot be collapsed to a wildcard at any entropy.
// Hardcoded by design — operators may extend via
// learn.inference.normalization.reserved_segments_extra but cannot
// remove. Order is the design's emission order; tests assert no
// duplicates and no empty entries.
var reservedSegmentsCanonical = []string{
	"admin", "auth", "login", "oauth", "token",
	"billing", "settings", "users", "me", "orgs",
	"sso", "saml", "mfa", "kms", "vault",
	"secret", "key", "password", "payment", "refund",
	"transfer", "withdraw", "ssh", "ssl", "cert",
	"ca", "auth0",
}

// CanonicalReservedSegments returns a defensive copy of the canonical
// reserved-segment list. Defense-in-depth: callers cannot mutate the
// package-level slice. Returned in deterministic order so callers can
// emit it as documentation or audit evidence.
func CanonicalReservedSegments() []string {
	out := make([]string, len(reservedSegmentsCanonical))
	copy(out, reservedSegmentsCanonical)
	return out
}

// IsReserved reports whether `segment` matches the canonical list or
// any operator-supplied extra. Comparison is byte-exact against the
// already-normalized form (NFC + lowercase + percent-decoded — the
// caller is responsible for normalizing first; this function does NOT
// re-normalize). Empty `segment` returns false.
//
// Performance: the canonical list is small (~27 entries) and the
// extras are bounded by config. Linear scan is fine; we do not bother
// with a map because the linear-scan constant factor is faster on
// slices this short and avoids pointer-chasing.
func IsReserved(segment string, extras []string) bool {
	if segment == "" {
		return false
	}
	for _, r := range reservedSegmentsCanonical {
		if segment == r {
			return true
		}
	}
	for _, e := range extras {
		if segment == e {
			return true
		}
	}
	return false
}
