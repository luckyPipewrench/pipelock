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

// classRegistry is the shipped set of structured secret classes.
// Expressed as a function so compile errors surface at test time rather than
// process-startup time.
//
//nolint:funlen // registry is data; splitting hurts readability.
func classRegistry() []classPattern {
	// Shared fragments
	const (
		// Generic hex string (any length — refined per hash class below).
		hex32  = `[a-fA-F0-9]{32}`
		hex40  = `[a-fA-F0-9]{40}`
		hex64  = `[a-fA-F0-9]{64}`
		hex128 = `[a-fA-F0-9]{128}`
		// IPv4 octet (0-255).
		octet = `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`
	)

	return []classPattern{
		// Tokens / API keys — high priority so the most specific span wins.
		{
			class:    ClassAWSAccessKey,
			pattern:  regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AGPA|AROA)[A-Z0-9]{16}\b`),
			priority: 100,
		},
		{
			class:    ClassGoogleAPIKey,
			pattern:  regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
			priority: 100,
		},
		{
			class:    ClassGitHubToken,
			pattern:  regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`),
			priority: 100,
		},
		{
			class:    ClassSlackToken,
			pattern:  regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
			priority: 100,
		},
		{
			class: ClassJWT,
			// Three base64url segments separated by dots; first segment starts
			// with `eyJ` (decodes to '{"').
			pattern:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
			priority: 100,
		},
		{
			class:    ClassSSHPrivateKey,
			pattern:  regexp.MustCompile(`-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY(?: BLOCK)?-----`),
			priority: 100,
		},

		// Hashes — medium-high priority. Longer hashes first so they win over
		// shorter-hash prefixes.
		{class: ClassHashSHA512, pattern: regexp.MustCompile(`\b` + hex128 + `\b`), priority: 90},
		{class: ClassHashSHA256, pattern: regexp.MustCompile(`\b` + hex64 + `\b`), priority: 85},
		{class: ClassHashSHA1, pattern: regexp.MustCompile(`\b` + hex40 + `\b`), priority: 80},
		// NTLM is 32 hex chars — same length as MD5 but different context.
		// We keep a single hex32 class tagged as hash-sha256-like; NTLM-vs-MD5
		// disambiguation needs context we don't have at regex time. Document
		// this limitation and let the operator pick a dictionary entry if
		// they need to distinguish. See redaction-v1 §7 limitations.
		{class: ClassHashMD5, pattern: regexp.MustCompile(`\b` + hex32 + `\b`), priority: 75},

		// Network identifiers.
		{
			class:    ClassIPv4,
			pattern:  regexp.MustCompile(`\b` + octet + `\.` + octet + `\.` + octet + `\.` + octet + `\b`),
			priority: 70,
		},
		{
			class: ClassCIDR,
			// CIDR is an IPv4 followed by /N — match this BEFORE IPv4 so the
			// /prefix is included.
			pattern:  regexp.MustCompile(`\b` + octet + `\.` + octet + `\.` + octet + `\.` + octet + `/(?:3[0-2]|[12]?\d)\b`),
			priority: 72,
		},
		{
			class: ClassIPv6,
			// Pragmatic IPv6 pattern: either full 8-group form, OR a run
			// with `::` zero-compression that has at least one hex digit
			// adjacent to the `::`. The hex-digit requirement avoids bare
			// `::` and C++ scope operators like `std::cout` matching while
			// still catching `::1` (loopback), `fe80::`, `2001:db8::1`,
			// and full forms. Priority is below MAC so 6-group all-hex
			// strings ("aa:bb:cc:dd:ee:ff") belong to MAC.
			pattern:  regexp.MustCompile(`\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b[A-Fa-f0-9]+(?::[A-Fa-f0-9]*)*::(?:[A-Fa-f0-9]*:?)*[A-Fa-f0-9]*\b|::[A-Fa-f0-9]+(?::[A-Fa-f0-9]*)*\b`),
			priority: 68,
		},
		{
			class:    ClassMAC,
			pattern:  regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`),
			priority: 65,
		},

		// Identity / contact.
		{
			class:    ClassEmail,
			pattern:  regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
			priority: 60,
		},
		{
			class: ClassFQDN,
			// Conservative FQDN: two-or-more labels, final TLD of 2-24
			// letters. Avoids matching version strings ("1.2.3") and file
			// paths ("foo.txt"). Ordered AFTER email so email wins on same
			// span.
			pattern:  regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,24}\b`),
			priority: 50,
		},
		{
			class: ClassADUser,
			// CONTOSO\user or user@contoso.local style. Conservative: DOMAIN
			// must be uppercase-ish alphanumeric to avoid matching Windows
			// paths with mixed case.
			pattern:  regexp.MustCompile(`\b[A-Z][A-Z0-9_-]{1,20}\\[A-Za-z0-9._-]{2,}\b`),
			priority: 95,
		},

		// Personal identifiers (US-centric — operators in other locales
		// should supplement via dictionaries in v1.1).
		{
			class: ClassSSN,
			// RE2 doesn't support negative lookahead, so the area/group/
			// serial validity filter cannot be encoded in the regex alone.
			// We match the SSN shape XXX-XX-XXXX and accept some false
			// positives on invalid area codes. Redacting a non-SSN that
			// happens to match the shape is safe; leaking a real SSN is not.
			pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			priority: 95,
		},
		{
			class: ClassCreditCard,
			// Major brands with spaces or dashes tolerated. Luhn-verified
			// class narrowing is deferred; v1 accepts the regex-positive set
			// and trades some false positives for zero false negatives.
			pattern:  regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011|65\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`),
			priority: 90,
		},
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
