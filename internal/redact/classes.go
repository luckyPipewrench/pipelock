// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"regexp"
	"sort"
	"sync"
)

// A classPattern associates a secret class with a compiled regex that
// matches instances of that class in arbitrary text. Patterns must not have
// anchors (^ / $) because they are applied inside larger string scalars.
type classPattern struct {
	class   Class
	pattern *regexp.Regexp
	// priority disambiguates overlapping classes: higher wins. Used when the
	// same substring matches multiple classes (e.g., a CIDR also contains an
	// IPv4). Kept small integer to make ordering obvious.
	priority int
}

// Shared regex fragments reused across category-specific registries.
const (
	hex32    = `[a-fA-F0-9]{32}`
	hex40    = `[a-fA-F0-9]{40}`
	hex64    = `[a-fA-F0-9]{64}`
	hex128   = `[a-fA-F0-9]{128}`
	octet    = `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`
	ipv4Str  = `\b` + octet + `\.` + octet + `\.` + octet + `\.` + octet
	cidrMask = `/(?:3[0-2]|[12]?\d)\b`
)

// classRegistry is the shipped set of structured secret classes.
// Split across category helpers so no single function trips funlen and the
// priority story stays scannable category by category.
func classRegistry() []classPattern {
	out := make([]classPattern, 0, 24)
	out = append(out, tokenClasses()...)
	out = append(out, hashClasses()...)
	out = append(out, networkClasses()...)
	out = append(out, identityClasses()...)
	out = append(out, personalClasses()...)
	return out
}

// tokenClasses is the API-key / bearer-credential category. High priority
// so specific token formats win over generic patterns sharing the span.
func tokenClasses() []classPattern {
	return []classPattern{
		{class: ClassAWSAccessKey, pattern: regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AGPA|AROA)[A-Z0-9]{16}\b`), priority: 100},
		{class: ClassGoogleAPIKey, pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), priority: 100},
		{class: ClassGitHubToken, pattern: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`), priority: 100},
		{class: ClassSlackToken, pattern: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), priority: 100},
		// JWT: three base64url segments separated by dots; first segment
		// starts with `eyJ` (decodes to '{"').
		{class: ClassJWT, pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), priority: 100},
		{class: ClassSSHPrivateKey, pattern: regexp.MustCompile(`-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY(?: BLOCK)?-----`), priority: 100},
	}
}

// hashClasses is the fixed-length hex digest category. Longer digests must
// win over shorter-hash prefixes, hence the descending priorities. NTLM
// and MD5 share hex32; disambiguation needs context we don't have at
// regex time, so we expose MD5 and leave NTLM as a reserved label.
func hashClasses() []classPattern {
	return []classPattern{
		{class: ClassHashSHA512, pattern: regexp.MustCompile(`\b` + hex128 + `\b`), priority: 90},
		{class: ClassHashSHA256, pattern: regexp.MustCompile(`\b` + hex64 + `\b`), priority: 85},
		{class: ClassHashSHA1, pattern: regexp.MustCompile(`\b` + hex40 + `\b`), priority: 80},
		{class: ClassHashMD5, pattern: regexp.MustCompile(`\b` + hex32 + `\b`), priority: 75},
	}
}

// networkClasses covers IP addresses (v4/v6), CIDR blocks, and MAC
// addresses. CIDR priority is above IPv4 so CIDR absorbs the embedded
// address; IPv6 priority is above MAC so the `::`-compressed form wins
// over the 6-group hex-with-colons shape.
func networkClasses() []classPattern {
	return []classPattern{
		{class: ClassIPv4, pattern: regexp.MustCompile(ipv4Str + `\b`), priority: 70},
		// CIDR = IPv4 followed by /N. Match before IPv4 so the /prefix is
		// included.
		{class: ClassCIDR, pattern: regexp.MustCompile(ipv4Str + cidrMask), priority: 72},
		// Pragmatic IPv6: either full 8-group form, OR a run with `::`
		// zero-compression that has at least one hex digit adjacent. The
		// hex-digit requirement keeps `std::cout` and bare `::` from
		// matching while still catching `::1`, `fe80::`, `2001:db8::1`.
		{class: ClassIPv6, pattern: regexp.MustCompile(`\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b[A-Fa-f0-9]+(?::[A-Fa-f0-9]*)*::(?:[A-Fa-f0-9]*:?)*[A-Fa-f0-9]*\b|::[A-Fa-f0-9]+(?::[A-Fa-f0-9]*)*\b`), priority: 68},
		{class: ClassMAC, pattern: regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`), priority: 65},
	}
}

// identityClasses covers email, FQDN, and AD user forms. FQDN is last
// (lowest priority among the three) so email wins on a shared span and a
// bare FQDN match only fires when no stricter class already claimed it.
func identityClasses() []classPattern {
	return []classPattern{
		{class: ClassEmail, pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), priority: 60},
		// Conservative FQDN: two-or-more labels, final TLD 2-24 letters.
		// Avoids version strings ("1.2.3") and most file paths.
		{class: ClassFQDN, pattern: regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,24}\b`), priority: 50},
		// AD user: CONTOSO\user shape. DOMAIN must be uppercase-ish to
		// avoid matching Windows paths with mixed case.
		{class: ClassADUser, pattern: regexp.MustCompile(`\b[A-Z][A-Z0-9_-]{1,20}\\[A-Za-z0-9._-]{2,}\b`), priority: 95},
	}
}

// personalClasses is the US-centric PII category. Operators in other
// locales supplement via dictionaries in v1.1. AmEx is 15 digits
// (4-6-5 split, 3[47] prefix); other supported brands are 16 digits
// (4-4-4-4). Folding both under the same template misses AmEx —
// regression reported in review (2026-04-19).
func personalClasses() []classPattern {
	return []classPattern{
		// SSN shape XXX-XX-XXXX. Matches on invalid area codes too; redacting
		// a non-SSN that happens to share the shape is safe. RE2 has no
		// negative lookahead so the area-code filter can't be encoded here.
		{class: ClassSSN, pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), priority: 95},
		{class: ClassCreditCard, pattern: regexp.MustCompile(`\b(?:3[47]\d{2}[ -]?\d{6}[ -]?\d{5}|(?:4\d{3}|5[1-5]\d{2}|6011|65\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})\b`), priority: 90},
	}
}

// compiledRegistry caches the compiled registry so each call to
// NewDefaultMatcher doesn't pay the regex compile cost.
var (
	compiledRegistryOnce sync.Once
	compiledRegistryVal  []classPattern
)

// defaultRegistry returns the shipped registry, compiled once.
func defaultRegistry() []classPattern {
	compiledRegistryOnce.Do(func() {
		compiledRegistryVal = classRegistry()
		// Sort highest-priority first so span overlap resolution picks the
		// most specific class first.
		sort.SliceStable(compiledRegistryVal, func(i, j int) bool {
			return compiledRegistryVal[i].priority > compiledRegistryVal[j].priority
		})
	})
	return compiledRegistryVal
}
