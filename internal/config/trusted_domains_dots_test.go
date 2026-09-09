// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// trusted_domains exempts hosts from the SSRF internal-IP check, so an
// over-broad entry here is heavier than an entropy exemption. This validator
// carried its own TrimSuffix, which removes ONE trailing dot, so "*.com.."
// passed the breadth check and was rewritten IN PLACE to "*.com."; MatchDomain
// then strips that last dot and matches every .com host. The raw two-dot form
// matches nothing on its own, so the half-normalization here is what made it
// dangerous.
//
// Reproduced before the fix: ValidateTrustedDomains([]string{"*.com.."})
// returned nil and left the slice holding "*.com.", while
// MatchDomain("evil.com", "*.com.") is true.
func TestValidateTrustedDomainsCollapsesEveryTrailingDot(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"*.com", "*.com.", "*.com..", "*.com...", "  *.COM..  "} {
		domains := []string{raw}
		if err := ValidateTrustedDomains(domains, "trusted_domains"); err == nil {
			t.Errorf("ValidateTrustedDomains(%q) = nil, want an over-broad rejection; slice now holds %q", raw, domains[0])
		}
	}

	// Control: a concrete wildcard stays accepted in every trailing-dot
	// spelling and normalizes to one canonical value, so the fix refuses
	// over-broad patterns rather than refusing legitimate config.
	for _, raw := range []string{"*.vendor.example", "*.vendor.example.", "*.vendor.example.."} {
		domains := []string{raw}
		if err := ValidateTrustedDomains(domains, "trusted_domains"); err != nil {
			t.Errorf("ValidateTrustedDomains(%q) = %v, want nil", raw, err)
			continue
		}
		if domains[0] != "*.vendor.example" {
			t.Errorf("ValidateTrustedDomains(%q) normalized to %q, want %q", raw, domains[0], "*.vendor.example")
		}
	}

	// A bare wildcard and a dots-only entry are still refused by their own
	// rules, which the shared normalizer must not have loosened.
	for _, raw := range []string{"*", ".", ".."} {
		if err := ValidateTrustedDomains([]string{raw}, "trusted_domains"); err == nil {
			t.Errorf("ValidateTrustedDomains(%q) = nil, want a rejection", raw)
		}
	}
}
