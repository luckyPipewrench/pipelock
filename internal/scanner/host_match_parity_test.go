// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
)

// Validation approves a host pattern by NORMALIZING it; these lists then store
// the operator's string verbatim and hand it to MatchDomain, which normalizes
// LESS. Nothing proved the two agreed, and they did not: "example.com.."
// validated as "example.com", stayed stored as typed, and the blocklist did not
// block example.com. Validation now refuses a pattern the matcher would read
// differently, and this is the test that the two ends actually meet.
//
// It drives real YAML through config.LoadBytes and then a real scanner, because
// a unit test on either end alone is exactly what missed this.
func TestBlocklistPatternValidatedIsPatternMatched(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		host    string
	}{
		{"an exact host", "blocked.example", "blocked.example"},
		{"a trailing dot is DNS-equivalent", "blocked.example.", "blocked.example"},
		{"case is folded at match time", "BLOCKED.example", "blocked.example"},
		{"a wildcard covers a subdomain", "*.blocked.example", "api.blocked.example"},
		{"a wildcard also covers the apex", "*.blocked.example", "blocked.example"},
		{"a wildcard with a trailing dot still matches", "*.blocked.example.", "api.blocked.example"},
		{"an exact IPv4 literal", "8.8.8.8", "8.8.8.8"},
		{"an exact IPv6 literal", "2001:db8::1", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			yaml := "fetch_proxy:\n  monitoring:\n    blocklist: [\"" + tt.pattern + "\"]\n"
			cfg, err := config.LoadBytes([]byte(yaml))
			if err != nil {
				t.Fatalf("the pattern %q was refused at load, so the parity claim cannot be tested: %v", tt.pattern, err)
			}

			// Read the pattern back out of the loaded config rather than
			// trusting that load stored what was typed. If load ever starts
			// rewriting the value, this test must follow the stored one.
			stored := cfg.FetchProxy.Monitoring.Blocklist
			if len(stored) != 1 {
				t.Fatalf("expected exactly one stored pattern, got %v", stored)
			}
			if !destination.MatchDomain(tt.host, stored[0]) {
				t.Errorf("config accepted %q but the matcher does not match %q against the stored %q; a deny rule that never denies", tt.pattern, tt.host, stored[0])
			}

			cfg.Internal = nil // no DNS in a unit test; the literal-IP floor is unaffected
			s, err := New(cfg)
			if err != nil {
				t.Fatalf("scanner.New: %v", err)
			}
			defer s.Close()
			if res := s.checkBlocklist(tt.host); res.Allowed {
				t.Errorf("a loaded blocklist pattern %q did not block %q", tt.pattern, tt.host)
			}
		})
	}
}

// An EMPTY allowlist permits every domain, because the allowlist is opt-in.
// That makes "drop the malformed entries at construction time" the wrong repair
// for this list, however much it reads like hardening: dropping the last entry
// converts strict allowlist-only into allow-all. A round-seven review proposed
// exactly that; this pins the property that rejects it, so the next reader does
// not have to rediscover the reason.
func TestEmptyAllowlistPermitsEverything(t *testing.T) {
	t.Parallel()

	empty := &Scanner{allowlist: []string{}}
	if res := empty.checkAllowlist(destination.Destination{Host: "evil.example"}); !res.Allowed {
		t.Fatal("premise changed: an empty allowlist no longer permits everything, so the reasoning recorded above needs revisiting")
	}

	// The control that gives the assertion above its meaning: a NON-empty
	// allowlist does deny an unlisted host, so the permissiveness is about
	// emptiness and not about the check being inert.
	populated := &Scanner{allowlist: []string{"ok.example"}}
	if res := populated.checkAllowlist(destination.Destination{Host: "evil.example"}); res.Allowed {
		t.Error("control failed: a populated allowlist must deny an unlisted host")
	}
}

// Accepting an exact IP literal in config is not the same as honoring one, and
// on trusted_domains the difference is the whole SSRF story: that list bypasses
// the internal-IP check, so an IP entry there would be a bypass if it matched.
// It does not - IsTrustedDomain refuses an IP hostname before matching.
//
// This is pinned because moving the exact-IP acceptance ahead of the host:port
// rejection newly lets an IPv6 literal LOAD on this list, where previously the
// colons got it refused by accident. The entry is inert either way, but the
// safety now rests on this runtime check rather than on a validation quirk.
func TestTrustedDomainIPLiteralIsInertNotABypass(t *testing.T) {
	t.Parallel()

	s := &Scanner{trustedDomains: []string{"2001:db8::1", "::1", "127.0.0.1"}}
	for _, host := range []string{"2001:db8::1", "::1", "127.0.0.1", "[::1]"} {
		if s.IsTrustedDomain(host) {
			t.Errorf("IsTrustedDomain(%q) is true; an IP literal in trusted_domains would bypass the internal-IP check", host)
		}
	}

	// The control: the list is not simply inert. A hostname pattern in the same
	// list does match, so the rejections above are about IP literals.
	ctl := &Scanner{trustedDomains: []string{"internal.example"}}
	if !ctl.IsTrustedDomain("internal.example") {
		t.Error("control failed: a hostname entry in trusted_domains must match")
	}
}
