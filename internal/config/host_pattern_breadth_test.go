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

// An interior wildcard is a FAIL-OPEN on a deny surface, which is why the
// shape rule is shared rather than duplicated. "*.example*.com" passes a naive
// prefix check, and the request-policy runtime then compares hostnames against
// the literal suffix ".example*.com", which no legal DNS name contains. A
// `block` rule that matches nothing denies nothing, so a typo silently turns a
// blocking policy off. Both validators reject it now because breadth layers on
// top of shape instead of restating it.
func TestHostPatternRejectsInteriorWildcards(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{
		// Glob metacharacters: the originally reported class.
		"*.example*.com",  // the reported case
		"*.ex[a]mple.com", // character class
		"*.exa?ple.com",   // single-character glob
		"*.*.example.com", // a second wildcard label
		// Everything a character blacklist missed. A second round found all of
		// these admitted at once, which is why the rule validates DNS label
		// grammar instead of enumerating forbidden characters. Each makes a
		// suffix comparison match nothing, so each silently disables a block
		// rule that carries it.
		"*.vendor.example#disabled", // fragment character
		"*.vendor.example%20",       // percent escape
		"*.vendor_example.com",      // underscore is not a DNS label character
		"*.vendor..example",         // empty label
		"*.-vendor.example",         // leading hyphen
		"*.vendor-.example",         // trailing hyphen
		"*.vendör.example",          // non-ASCII label
	} {
		normalized := NormalizeHostPattern(pattern)

		if err := HostPatternSyntaxError(normalized); err == nil {
			t.Errorf("HostPatternSyntaxError(%q) = nil; an interior wildcard matches no legal hostname, so a block rule carrying it denies nothing", pattern)
		}
		// Breadth must inherit the shape rule rather than carry its own copy.
		if err := HostPatternBreadthError(normalized); err == nil {
			t.Errorf("HostPatternBreadthError(%q) = nil; the breadth validator must inherit the shape rule", pattern)
		}
		// And it must be refused on the real deny surface, end to end.
		route := &RequestPolicyRoute{Hosts: []string{pattern}}
		if err := validateRequestPolicyRoute(route, `request_policy rule "deny"`); err == nil {
			t.Errorf("validateRequestPolicyRoute(hosts=[%q]) = nil; this admits a block rule that cannot match", pattern)
		}
	}

	// Control: the ONE legal wildcard position still works on both surfaces.
	for _, pattern := range []string{"*.vendor.example", "*.googleapis.com"} {
		if err := HostPatternSyntaxError(NormalizeHostPattern(pattern)); err != nil {
			t.Errorf("HostPatternSyntaxError(%q) = %v, want nil", pattern, err)
		}
		route := &RequestPolicyRoute{Hosts: []string{pattern}}
		if err := validateRequestPolicyRoute(route, "control"); err != nil {
			t.Errorf("validateRequestPolicyRoute(hosts=[%q]) = %v, want nil", pattern, err)
		}
	}
}

// browser_shield.tracking_domains is a detection INCLUSION list whose entries
// the shield merges through regexp.QuoteMeta, so a wildcard compiles to a
// regex for the literal characters and can never match a URL. It was routed
// through the trust validator, which asked the wrong question: it judged
// breadth on a list where breadth is not a grant, and it accepted a wildcard
// that is inert. Refusing the wildcard is what stops the operator believing an
// entry works when it cannot.
func TestBrowserShieldTrackingDomainsRefuseInertWildcards(t *testing.T) {
	t.Parallel()

	base := func() *Config {
		c := Defaults()
		c.Internal = nil
		c.BrowserShield.Enabled = true
		return c
	}

	for _, entry := range []string{"*.tracker.example", "*.co.uk", "*"} {
		cfg := base()
		cfg.BrowserShield.TrackingDomains = []string{entry}
		err := cfg.Validate()
		if err == nil {
			t.Errorf("Validate() accepted tracking_domains=[%q]; the shield matches these literally, so the entry would never fire", entry)
			continue
		}
		if !strings.Contains(err.Error(), "wildcards are not supported here") {
			t.Errorf("tracking_domains=[%q] rejected for the wrong reason: %v", entry, err)
		}
	}

	// Control: exact hostnames are what this list is for, and they normalize.
	cfg := base()
	cfg.BrowserShield.TrackingDomains = []string{"Tracker.Example.", "pixel.vendor.example"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for exact hostnames", err)
	}
	if cfg.BrowserShield.TrackingDomains[0] != "tracker.example" {
		t.Errorf("normalized to %q, want %q", cfg.BrowserShield.TrackingDomains[0], "tracker.example")
	}
}

// HostPatternSyntaxError is EXPORTED, so it can be handed a value no in-package
// caller would produce. Every in-package caller normalizes first, and
// NormalizeHostPattern collapses "*." to "*", so the empty-base branch is
// unreachable from inside this package. It is still reachable across the
// package boundary, which is the difference between this and the unexported
// helper where the same branch WAS deleted as dead. Tested directly rather than
// removed, because a defensive branch on an exported predicate earns its place
// only if something proves it fires.
func TestHostPatternSyntaxErrorHandlesUnnormalizedInput(t *testing.T) {
	t.Parallel()

	if err := HostPatternSyntaxError("*."); err == nil {
		t.Error(`HostPatternSyntaxError("*.") = nil; a wildcard naming no domain must be refused`)
	}
	if err := HostPatternSyntaxError(""); err == nil {
		t.Error(`HostPatternSyntaxError("") = nil; an empty pattern must be refused`)
	}
	// Sanity: the in-package invariant this branch backs up still holds, so the
	// comment above stays true if NormalizeHostPattern ever changes.
	if got := NormalizeHostPattern("*."); got != "*" {
		t.Errorf(`NormalizeHostPattern("*.") = %q, want "*"; the empty-base branch reachability note needs revisiting`, got)
	}
}

// The tracking-domain loop rejects more than wildcards, and those paths are
// what an operator actually hits: a stray blank line in YAML, or a URL pasted
// where a hostname belongs.
func TestBrowserShieldTrackingDomainsRejectMalformedEntries(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":                        "is empty",
		"   ":                     "is empty",
		"https://tracker.example": "not a URL or host:port",
		"tracker.example:443":     "not a URL or host:port",
	}
	for entry, want := range cases {
		cfg := Defaults()
		cfg.Internal = nil
		cfg.BrowserShield.Enabled = true
		cfg.BrowserShield.TrackingDomains = []string{entry}
		err := cfg.Validate()
		if err == nil {
			t.Errorf("Validate() accepted tracking_domains=[%q], want a rejection", entry)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("tracking_domains=[%q] rejected for the wrong reason: %v (want %q)", entry, err, want)
		}
	}
}

// The raw value is checked for non-ASCII BEFORE case folding, and the ordering
// is the whole point. Some non-ASCII runes fold INTO ASCII: U+212A KELVIN SIGN
// lowercases to "k". So a pattern written with it folds to an ordinary ASCII
// hostname and would pass an ASCII check applied after folding, silently
// aiming the operator's rule at a different host than the one they typed.
func TestHostPatternRejectsRawNonASCIIBeforeFolding(t *testing.T) {
	t.Parallel()

	kelvin := "*.Kexample.com" // U+212A KELVIN SIGN, folds to ASCII 'k'

	// The trap: folding first makes this look like a plain ASCII pattern.
	if folded := NormalizeHostPattern(kelvin); folded != "*.kexample.com" {
		t.Fatalf("premise changed: NormalizeHostPattern folded to %q, expected the ASCII form that makes the ordering matter", folded)
	}

	if _, err := NormalizeAndCheckHostPattern(kelvin); err == nil {
		t.Error("NormalizeAndCheckHostPattern accepted a KELVIN SIGN pattern; it folds to a DIFFERENT host than the operator wrote")
	}
	for _, raw := range []string{"*.vendör.example", "vendör.example", "*.Kexample.com"} {
		if _, err := NormalizeAndCheckHostPattern(raw); err == nil {
			t.Errorf("NormalizeAndCheckHostPattern(%q) = nil, want a non-ASCII rejection", raw)
		}
	}

	// An ASCII A-label is the supported way to write an internationalized name
	// and must still pass, or the rule would refuse legitimate config.
	for _, raw := range []string{"*.xn--vendr-nsa.example", "xn--vendr-nsa.example"} {
		if _, err := NormalizeAndCheckHostPattern(raw); err != nil {
			t.Errorf("NormalizeAndCheckHostPattern(%q) = %v, want nil; an A-label is how an IDN is written here", raw, err)
		}
	}
}

// A malformed EXACT host fails open the same way a malformed wildcard base
// does: the matcher compares hostnames for equality, so no request can equal
// "vendor.example#disabled", and a block rule carrying it denies nothing.
// Scoping the grammar to wildcard bases only was the defect.
func TestExactRouteHostsGetTheSameGrammar(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"vendor.example#disabled",
		"vendor.example%20",
		"vendor_example.com",
		"vendor..example",
		"-vendor.example",
		"vendor-.example",
	} {
		route := &RequestPolicyRoute{Hosts: []string{host}}
		if err := validateRequestPolicyRoute(route, `request_policy rule "deny"`); err == nil {
			t.Errorf("validateRequestPolicyRoute(hosts=[%q]) = nil; no request can equal this, so a block rule carrying it denies nothing", host)
		}
	}

	// Controls. An exact IP literal is legitimate and this repository's own
	// route tests block by address, so the grammar must not reach it. And an
	// IP-literal wildcard base is accepted because the matcher compares
	// `host == base` as well as a suffix, so refusing it disagreed with the
	// runtime.
	for _, host := range []string{"8.8.8.8", "vendor.example", "*.vendor.example", "*.8.8.8.8"} {
		route := &RequestPolicyRoute{Hosts: []string{host}}
		if err := validateRequestPolicyRoute(route, "control"); err != nil {
			t.Errorf("validateRequestPolicyRoute(hosts=[%q]) = %v, want nil", host, err)
		}
	}
}

// A hyphen in the third and fourth positions of a label is legal DNS and was
// being refused, because idna.Lookup enables the UTS #46 CheckHyphens rule,
// which is a registration-era restriction rather than a DNS one. That made
// validation STRICTER THAN MATCHING: MatchDomain matches "my--host.example.com"
// without complaint, so a host list carrying one loaded before this branch and
// refused after it. An operator whose working config stops loading is the
// failure direction that gets a security check switched off, so this pins both
// halves: the legal shapes load, and IDNA is still doing its other job.
func TestDoubleHyphenLabelsAreLegalAndPunycodeIsStillChecked(t *testing.T) {
	t.Parallel()

	accepted := []string{
		"my--host.example.com",
		"ab--cd.example",
		// x/net's own CheckHyphens documentation names this shape as in common
		// use; it is a googlevideo CDN host, and *.googlevideo.com already
		// appears in this repository's shipped patterns.
		"r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com",
		"xn--bcher-kva.example",
		"*.my--host.example.com",
	}
	for _, host := range accepted {
		t.Run("accept "+host, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTrustedDomains([]string{host}, "trusted_domains"); err != nil {
				t.Errorf("%q is a legal hostname and the matcher matches it, but validation refused it: %v", host, err)
			}
		})
	}

	// The calibration, and the reason this test is not just an acceptance
	// list. Turning CheckHyphens off must not turn IDNA off: a malformed
	// punycode label has to stay refused, or the "fix" for the hyphen rule
	// would have quietly widened the grammar instead of correcting it.
	refused := []string{
		"xn--0.example",
		"xn--a.example",
	}
	for _, host := range refused {
		t.Run("refuse "+host, func(t *testing.T) {
			t.Parallel()
			err := ValidateTrustedDomains([]string{host}, "trusted_domains")
			if err == nil {
				t.Fatalf("%q is malformed punycode and must stay refused; IDNA validation was lost along with the hyphen rule", host)
			}
			if !strings.Contains(err.Error(), "IDNA") {
				t.Errorf("%q was refused for an unexpected reason, so this may not be the punycode check: %v", host, err)
			}
		})
	}
}
