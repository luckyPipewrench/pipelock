// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// A wildcard host pattern decides how much of the internet a list covers, and
// several of those lists are security controls: trusted_domains exempts hosts
// from the SSRF internal-IP check, and the entropy-exclusion lists switch off
// detection gates.
//
// Counting dots cannot measure that, because a registry suffix can be several
// labels. "*.co.uk" has a dot and is every UK commercial domain. The rule now
// consults the published public-suffix list, and uses its ICANN flag to tell a
// registry suffix from a private registration a company added for its own
// subdomains.
func TestWildcardBreadthUsesThePublicSuffixList(t *testing.T) {
	t.Parallel()

	rejected := map[string]string{
		// Single-label bases: a whole top-level namespace. Rejected before
		// this change too, and these cases exist so the new rule cannot
		// regress them: the PSL reports "example" as a NON-ICANN suffix, so an
		// ICANN-only rule would have started accepting "*.example".
		"*.com":       "whole",
		"*.example":   "whole",
		"*.localhost": "whole",
		"*.internal":  "whole",

		// Multi-label ICANN registry suffixes. These are what counting dots
		// could not see, and they are the reason for this change.
		"*.co.uk":  "public suffix",
		"*.com.au": "public suffix",
		"*.org.uk": "public suffix",
		"*.ac.uk":  "public suffix",
		"*.co.jp":  "public suffix",
		"*.com.br": "public suffix",
	}
	for pattern, want := range rejected {
		err := HostPatternBreadthError(NormalizeHostPattern(pattern))
		if err == nil {
			t.Errorf("HostPatternBreadthError(%q) = nil, want a rejection; this pattern matches every domain under a registry", pattern)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("HostPatternBreadthError(%q) = %v, want a message mentioning %q so the operator can tell which rule refused it", pattern, err, want)
		}
	}

	// CONTROL, and it is the half that stops this becoming an over-strict
	// validator: every one of these is a pattern an operator legitimately
	// writes, and several are shipped in this repository's own presets. If the
	// rule refuses any of them it is worse than the weakness it replaces,
	// because a validator that rejects real config gets worked around.
	accepted := []string{
		// Shipped in configs/claude-code.yaml and internal/config/defaults.go.
		"*.anthropic.com", "*.openai.com", "*.github.com", "*.githubusercontent.com",
		"*.npmjs.com", "*.python.org", "*.pythonhosted.org", "*.crates.io",
		"*.docs.rs", "*.rubygems.org", "*.fireworks.ai", "*.openrouter.ai",
		// Documented examples.
		"*.example.com", "*.example.net", "*.corp.example.com",
		"*.apps.googleusercontent.com", "*.vendor.example",
		// PRIVATE public-suffix entries. These are THE reason the rule uses the
		// ICANN flag rather than refusing every registration boundary, and the
		// first five are shipped by this repository: rejecting the class was
		// tried and would refuse Pipelock's own presets and DLP exempt lists.
		"*.googleapis.com", "*.githubusercontent.com", "*.ngrok.io",
		"*.ngrok-free.app", "*.readthedocs.io",
		"*.s3.amazonaws.com", "*.github.io", "*.cloudfront.net",
		// Also shipped, and each is a case a hand-picked list misses: two are
		// private suffix entries and the rest are short registrable domains
		// whose base has exactly one dot, which is where a dot-counting rule
		// and a suffix rule are most likely to disagree.
		"*.ngrok.io", "*.readthedocs.io", "*.pinecone.io", "*.paste.ee",
		"*.huggingface.co", "*.cursor.sh", "*.docs.rs", "*.azure.com",
		"*.bitbucket.org", "*.beeceptor.com", "*.burpcollaborator.net",
		// Exact hosts are unaffected by the wildcard rule.
		"docs.vendor.example", "pypi.org",
	}
	for _, pattern := range accepted {
		if err := HostPatternBreadthError(NormalizeHostPattern(pattern)); err != nil {
			t.Errorf("HostPatternBreadthError(%q) = %v, want nil; this is legitimate operator config", pattern, err)
		}
	}
}

// The trailing-dot spellings must reach the same verdict, or "*.co.uk." would
// slip past a rule that "*.co.uk" fails.
func TestWildcardBreadthIgnoresTrailingDotSpelling(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{"*.co.uk", "*.co.uk.", "*.co.uk..", "  *.CO.UK.  "} {
		if err := HostPatternBreadthError(NormalizeHostPattern(pattern)); err == nil {
			t.Errorf("HostPatternBreadthError(%q) = nil, want a public-suffix rejection", pattern)
		}
	}
	for _, pattern := range []string{"*.vendor.example", "*.vendor.example.", "*.vendor.example.."} {
		if err := HostPatternBreadthError(NormalizeHostPattern(pattern)); err != nil {
			t.Errorf("HostPatternBreadthError(%q) = %v, want nil", pattern, err)
		}
	}
}

// The predicate governs every host-pattern list that shares it, so the effect
// has to be visible through a real validator rather than only the helper. This
// drives the SSRF trusted-domain list, where an over-broad wildcard exempts
// hosts from the internal-IP check.
func TestValidateTrustedDomainsRejectsRegistrySuffixWildcards(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"*.co.uk", "*.com.au", "*.com"} {
		if err := ValidateTrustedDomains([]string{raw}, "trusted_domains"); err == nil {
			t.Errorf("ValidateTrustedDomains(%q) = nil, want a rejection; this would exempt every domain under a registry from the SSRF internal-IP check", raw)
		}
	}
	// Control: the list still accepts what it is for, and normalizes it.
	domains := []string{"*.Vendor.Example."}
	if err := ValidateTrustedDomains(domains, "trusted_domains"); err != nil {
		t.Fatalf("ValidateTrustedDomains(*.Vendor.Example.) = %v, want nil", err)
	}
	if domains[0] != "*.vendor.example" {
		t.Errorf("normalized to %q, want %q", domains[0], "*.vendor.example")
	}
}

// A DENY or MATCH surface must NOT get the breadth rule. A request_policy route
// selects traffic and its action may be `block`, so a wildcard covering an
// entire registry is a policy an operator can legitimately write. An earlier
// revision of this change ran the breadth rule here and refused exactly that,
// which is the mirror image of the weakness the breadth rule fixes.
func TestRequestPolicyRouteHostsGetSyntaxOnlyValidation(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"*.co.uk", "*.com", "*.com.au", "*.github.io"} {
		route := &RequestPolicyRoute{Hosts: []string{host}}
		if err := validateRequestPolicyRoute(route, `request_policy rule "deny-broad"`); err != nil {
			t.Errorf("validateRequestPolicyRoute(hosts=[%q]) = %v, want nil; a broad match or block is a policy, not a misconfiguration", host, err)
		}
	}

	// The SAME pattern on a TRUST surface is still refused, which is the whole
	// point of splitting the two validators.
	if err := ValidateTrustedDomains([]string{"*.co.uk"}, "trusted_domains"); err == nil {
		t.Error("ValidateTrustedDomains(*.co.uk) = nil; the breadth rule must still govern trust surfaces")
	}

	// Shape rules survive on the deny surface: these are malformed either way.
	for _, host := range []string{"https://evil.example", "evil.example:443", "docs.*.example"} {
		route := &RequestPolicyRoute{Hosts: []string{host}}
		if err := validateRequestPolicyRoute(route, "control"); err == nil {
			t.Errorf("validateRequestPolicyRoute(hosts=[%q]) = nil, want a shape rejection", host)
		}
	}

	// Normalization still happens, so a trailing-dot spelling is stored once.
	route := &RequestPolicyRoute{Hosts: []string{"*.Vendor.Example."}}
	if err := validateRequestPolicyRoute(route, "control"); err != nil {
		t.Fatalf("validateRequestPolicyRoute(*.Vendor.Example.) = %v, want nil", err)
	}
	if route.Hosts[0] != "*.vendor.example" {
		t.Errorf("normalized to %q, want %q", route.Hosts[0], "*.vendor.example")
	}
}
