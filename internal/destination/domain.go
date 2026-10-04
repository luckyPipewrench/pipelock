// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// hostIDNAProfile keeps runtime matching aligned with host-pattern validation.
// CheckHyphens must remain after MapForLookup: it preserves legal DNS labels
// such as "my--host" while retaining the rest of lookup validation.
var hostIDNAProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.CheckHyphens(false),
)

// LookupASCII returns an IDNA lookup A-label using the profile shared by
// configured host patterns and runtime matching. Callers must discard the
// returned string when err is non-nil because x/net may return partial output.
func LookupASCII(host string) (string, error) {
	return hostIDNAProfile.ToASCII(host)
}

// canonicalDomainForMatch normalizes a hostname or leading-wildcard pattern
// for matching. It deliberately does no URL, port, zone, or IP parsing.
// Failed conversion preserves the original comparison, including wildcard
// matches, without using a partially converted hostname.
func canonicalDomainForMatch(value string) string {
	prefix := ""
	base := value
	if strings.HasPrefix(value, "*.") {
		prefix = "*."
		base = value[2:]
	}
	if base == "" || isDomainASCIIIdentity(base) {
		return value
	}
	ascii, err := LookupASCII(base)
	if err != nil || ascii == "" {
		return value
	}
	return prefix + ascii
}

// isDomainASCIIIdentity recognizes a conservative subset that lookup mapping
// leaves unchanged. ACE labels still need decoding and validation, even though
// their spelling is ASCII. All other inputs retain the full IDNA path and its
// original-input fallback on error. This is not hostname validation: invalid
// shapes in this subset also preserve their original spelling on that path.
func isDomainASCIIIdentity(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == 'x' && strings.HasPrefix(value[i:], "xn--") {
			return false
		}
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// MatchDomain reports whether a hostname matches a configured domain pattern.
//
// Patterns are either exact ("api.vendor.example") or a leading wildcard
// ("*.vendor.example"), where the wildcard matches the base domain itself and
// any subdomain of it. Comparison is case-insensitive and a trailing root dot
// is ignored on both sides.
//
// IP literals match exactly and never wildcard-expand. The dots in an address
// are not domain separators, so treating "192.168.1.1" as a subdomain of
// "168.1.1" would let a pattern authorize an unrelated address.
//
// This is the canonical implementation. internal/scanner re-exports it so the
// thirteen existing call sites across the scanner, proxy, CLI, session and
// content-entropy packages keep working unchanged.
//
// It also deliberately does NOT use NormalizeHost. Pattern matching needs IDNA
// conversion plus case folding and trailing-dot removal, but running the full
// normalizer would additionally strip an IPv6 zone index and silently turn one
// configured pattern into a broader one.
//
// NOTE: this deliberately uses net.ParseIP rather than this package's
// ParseIPLiteral. Recognizing the alternative IPv4 spellings here would change
// which patterns match an existing configuration, turning a token that is
// currently compared as a domain into one compared as an address. The literal
// parser is for the SSRF floor, where failing to recognize a spelling is a
// fail-open; here it would be a silent policy change, so the behavior is held
// exactly as it was.
func MatchDomain(hostname, pattern string) bool {
	// Equal inputs remain equal through normalization, including the original
	// spelling fallback. A wildcard also matches its own literal suffix.
	if hostname == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		host := strings.TrimSuffix(hostname, ".")
		suffix := strings.TrimSuffix(pattern[1:], ".")
		// A literal suffix of an identity-mapped hostname is itself
		// identity-mapped. IP literals still never wildcard-expand.
		if len(suffix) > 1 && strings.HasSuffix(host, suffix) && isDomainASCIIIdentity(hostname) && net.ParseIP(host) == nil {
			return true
		}
	}
	// IDNA also maps DNS separator characters. Remove the single root dot
	// after conversion so its equivalent spellings have identical semantics.
	hostname = strings.ToLower(strings.TrimSuffix(canonicalDomainForMatch(hostname), "."))
	pattern = strings.ToLower(strings.TrimSuffix(canonicalDomainForMatch(pattern), "."))
	if net.ParseIP(hostname) != nil {
		return hostname == pattern
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".vendor.example"
		base := pattern[2:]   // "vendor.example"
		return hostname == base || strings.HasSuffix(hostname, suffix)
	}
	return hostname == pattern
}

// MatchesDomainList reports whether a hostname matches any pattern in a list.
func MatchesDomainList(hostname string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchDomain(hostname, pattern) {
			return true
		}
	}
	return false
}
