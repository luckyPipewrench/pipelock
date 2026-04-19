// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

// TestDefaultMatcher_StructuredClasses exercises every built-in matcher class
// shipped in v1 with at least one positive example and asserts the class +
// span are correct.
func TestDefaultMatcher_StructuredClasses(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()

	cases := []struct {
		name  string
		input string
		want  Class
	}{
		{"ipv4", "connect to 192.0.2.104 now", ClassIPv4},
		{"ipv4-private", "192.168.1.5", ClassIPv4},
		{"cidr", "route 10.0.0.0/16 next", ClassCIDR},
		{"ipv6-compressed", "try 2001:db8::1 now", ClassIPv6},
		{"ipv6-full", "use 2001:0db8:85a3:0000:0000:8a2e:0370:7334 please", ClassIPv6},
		{"mac-colon", "mac aa:bb:cc:dd:ee:ff", ClassMAC},
		{"mac-dash", "mac aa-bb-cc-dd-ee-ff", ClassMAC},
		{"email", "contact jsmith@contoso.com for info", ClassEmail},
		{"fqdn", "visit dc01.corp.local for login", ClassFQDN},
		{"aws-access-key-akia", "key AKIA" + "IOSFODNN7EXAMPLE exposed", ClassAWSAccessKey},
		{"aws-access-key-asia", "temp " + "ASIA" + "Q5ZABCDEFG1234XY", ClassAWSAccessKey},
		{"google-api-key", "AIza" + "SyD4mHwK8NQ2J5B1v6xR3L9fP7aW0cZu8kE", ClassGoogleAPIKey},
		{"github-pat", "token ghp_" + strings.Repeat("A", 36) + " expires", ClassGitHubToken},
		{"github-new", "token github_pat_" + strings.Repeat("B", 40), ClassGitHubToken},
		{"slack-bot", "use " + "xox" + "b-12345-67890-abcdefghijklmnopqrstuvwx", ClassSlackToken},
		{"jwt", "bearer eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", ClassJWT},
		{"ssh-openssh", "-----BEGIN OPENSSH PRIVATE " + "KEY-----", ClassSSHPrivateKey},
		{"ssh-rsa", "-----BEGIN RSA PRIVATE " + "KEY-----", ClassSSHPrivateKey},
		{"ad-user", "CONTOSO\\jsmith logged in", ClassADUser},
		{"ssn", "SSN " + "123-45-" + "6789 on file", ClassSSN},
		{"credit-card-visa", "card " + "4111 1111 " + "1111 1111", ClassCreditCard},
		{"credit-card-amex-15digit", "card " + "3782 822463 " + "10005", ClassCreditCard},
		{"credit-card-amex-dashed", "card " + "3714-496353-" + "98431", ClassCreditCard},
		{"hash-md5", "etag " + strings.Repeat("a", 32), ClassHashMD5},
		{"hash-sha1", "sha1 " + strings.Repeat("b", 40), ClassHashSHA1},
		{"hash-sha256", "sha256 " + strings.Repeat("c", 64), ClassHashSHA256},
		{"hash-sha512", "sha512 " + strings.Repeat("d", 128), ClassHashSHA512},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matches := m.Scan(tc.input)
			if len(matches) == 0 {
				t.Fatalf("Scan(%q) returned no matches; expected class %s", tc.input, tc.want)
			}
			// At least one match must be of the expected class.
			found := false
			for _, got := range matches {
				if got.Class == tc.want {
					found = true
					// Verify span slices correctly back to the original.
					if got.Original != tc.input[got.Start:got.End] {
						t.Errorf("Match span mismatch: original=%q vs s[Start:End]=%q",
							got.Original, tc.input[got.Start:got.End])
					}
					break
				}
			}
			if !found {
				classesFound := make([]string, 0, len(matches))
				for _, got := range matches {
					classesFound = append(classesFound, string(got.Class))
				}
				t.Fatalf("no match of class %s in %q; got classes %v", tc.want, tc.input, classesFound)
			}
		})
	}
}

// TestDefaultMatcher_IPv6DoesNotMatchScopeOperator guards against the
// false-positive from review finding #4 (2026-04-19): the earlier IPv6
// regex accepted any `[A-Fa-f0-9:]*::[A-Fa-f0-9:]*` including `::` alone
// and C++ scope operators like `std::cout`.
func TestDefaultMatcher_IPv6DoesNotMatchScopeOperator(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	shouldNotMatch := []string{
		"std::cout is the output stream",
		"call foo::bar(x) to run",
		"the :: operator is C++",
	}
	for _, s := range shouldNotMatch {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			for _, mv := range m.Scan(s) {
				if mv.Class == ClassIPv6 {
					t.Fatalf("IPv6 falsely matched in %q: %+v", s, mv)
				}
			}
		})
	}

	// Real compressed IPv6 must still match.
	shouldMatch := []string{"::1", "fe80::1", "2001:db8::1"}
	for _, s := range shouldMatch {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			found := false
			for _, mv := range m.Scan(s) {
				if mv.Class == ClassIPv6 {
					found = true
				}
			}
			if !found {
				t.Fatalf("IPv6 failed to match legitimate address %q: scans=%+v", s, m.Scan(s))
			}
		})
	}
}

// TestDefaultMatcher_Negative verifies non-secret content does not match.
func TestDefaultMatcher_Negative(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()

	// Note: FQDN detection is class-level best-effort. Common file
	// extensions (foo.txt, config.yaml) will sometimes match. v1 accepts
	// this trade-off — operators who need finer control use dictionaries.
	cases := []string{
		"", // empty
		"just a normal sentence about http and https",   // no identifiers
		"version 1.2.3 shipped yesterday",               // not a FQDN
		"this is a plain english sentence with no dots", // nothing to match
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			if got := m.Scan(s); len(got) != 0 {
				t.Fatalf("Scan(%q) = %+v; wanted no matches", s, got)
			}
		})
	}
}

// TestDefaultMatcher_OverlapsResolvedByPriority confirms that when a span
// matches multiple classes, the highest-priority class wins.
func TestDefaultMatcher_OverlapsResolvedByPriority(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()

	// CIDR covers IPv4 + `/N`. Priority table puts CIDR above IPv4.
	s := "route 10.0.0.0/16 somewhere"
	matches := m.Scan(s)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (CIDR absorbs IPv4), got %d: %+v", len(matches), matches)
	}
	if matches[0].Class != ClassCIDR {
		t.Fatalf("expected ClassCIDR, got %s", matches[0].Class)
	}
}

// TestDefaultMatcher_SpansAreNonOverlapping sorted and non-overlapping.
func TestDefaultMatcher_SpansAreNonOverlapping(t *testing.T) {
	t.Parallel()
	m := NewDefaultMatcher()
	s := "a@b.com 10.0.0.1 dc01.corp.local 10.0.0.2 user@domain.org"
	matches := m.Scan(s)
	if len(matches) < 2 {
		t.Fatalf("expected multiple matches, got %d", len(matches))
	}
	for i := 1; i < len(matches); i++ {
		if matches[i-1].End > matches[i].Start {
			t.Errorf("matches[%d].End=%d overlaps matches[%d].Start=%d",
				i-1, matches[i-1].End, i, matches[i].Start)
		}
	}
}

// TestDefaultMatcher_NilSafe ensures a nil Matcher returns nil without
// panicking (defensive).
func TestDefaultMatcher_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Matcher
	if got := m.Scan("anything"); got != nil {
		t.Fatalf("nil Matcher Scan returned %+v, want nil", got)
	}
}

// TestDefaultRegistry_Cached ensures the compiled registry is stable across
// calls (same pointer-equal slice entries).
func TestDefaultRegistry_Cached(t *testing.T) {
	t.Parallel()
	a := defaultRegistry()
	b := defaultRegistry()
	if len(a) != len(b) {
		t.Fatalf("registry length changed: %d vs %d", len(a), len(b))
	}
	// Cached: first pattern's compiled regex pointer must match.
	if a[0].pattern != b[0].pattern {
		t.Fatalf("registry not cached: pointer identity broke")
	}
}
