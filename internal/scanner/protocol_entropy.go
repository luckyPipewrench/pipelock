// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"math"
	"net/url"
	"strings"
)

// Protocol-shaped values that trip the URL entropy gate without carrying
// anything the gate exists to stop. Each rule below narrows WHAT is measured;
// none of them skips a value by its parameter name alone.

const (
	// maxNestedURLEntropyDepth bounds how many URL-in-a-query-value layers are
	// scored part by part: an OAuth redirect_uri, plus one http(s) URL in that
	// URI's own query. A deeper value is scored as one string, never skipped,
	// so wrapping a payload in more URL layers cannot move it out of scope.
	maxNestedURLEntropyDepth = 2

	pkceChallengeParam = "code_challenge"
	pkceMethodParam    = "code_challenge_method"
	// pkceMethodS256 is compared case-sensitively. RFC 7636 section 4.3 spells
	// the method S256, and an omitted method means plain, which gets no relief.
	pkceMethodS256 = "S256"
	// pkceS256ChallengeLen is BASE64URL(SHA-256(verifier)) without padding:
	// 32 bytes encode to exactly 43 characters (RFC 7636 section 4.2).
	pkceS256ChallengeLen = 43

	// maxAssetHashSlotLen is the longest trailing build-hash token trimmed from
	// a static asset name before its path segment is scored.
	maxAssetHashSlotLen = 8
)

// assetExtensions are the static asset suffixes whose trailing build-hash
// token is not scored. The match is case-sensitive: build tools emit these in
// lower case, and a segment that does not match keeps the whole-segment score.
var assetExtensions = []string{".js", ".mjs", ".css", ".woff2"}

const sourceMapExtension = ".map"

// queryEntropyPair is one decoded query key and value.
type queryEntropyPair struct {
	key   string
	value string
}

// entropyFinding is a part of a query value whose entropy exceeded the gate.
// part is empty when the value was scored as one string.
type entropyFinding struct {
	part    string
	entropy float64
}

// splitQueryEntropyPairs splits a raw query on both '&' and ';', the way
// scanAmbiguousRawQuery reads it, and decodes each key and value once. A
// component that fails to decode is kept raw, so it is still measured.
func splitQueryEntropyPairs(rawQuery string) []queryEntropyPair {
	var pairs []queryEntropyPair
	for _, pair := range strings.FieldsFunc(rawQuery, func(r rune) bool {
		return r == '&' || r == ';'
	}) {
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, ok := strictQueryEntropyComponent(rawKey)
		if !ok {
			key = rawKey
		}
		value, ok := strictQueryEntropyComponent(rawValue)
		if !ok {
			value = rawValue
		}
		pairs = append(pairs, queryEntropyPair{key: key, value: value})
	}
	return pairs
}

// pkceS256Declared reports whether a query declares the S256 challenge method
// and nothing else: exactly one code_challenge_method value, and it is exactly
// S256, as RFC 7636 requests send. A second value (even another S256), plain,
// a lower-case s256, or an absent method all return false, so the challenge
// keeps its entropy score.
func pkceS256Declared(methods []string) bool {
	return len(methods) == 1 && methods[0] == pkceMethodS256
}

// pkceExemptionApplies reports whether a query may exempt its code_challenge
// from entropy scoring: it declares only S256, and it carries exactly one
// code_challenge value, as RFC 7636 requests do. A second challenge value,
// even one of the accepted shape, turns the exemption off so a query cannot
// carry several unscored hash-sized tokens.
func pkceExemptionApplies(methods, challenges []string) bool {
	return len(challenges) == 1 && pkceS256Declared(methods)
}

// isPKCES256Challenge reports whether one decoded value is an S256 PKCE code
// challenge. The decision is per value, never per key: a second
// code_challenge value that is not exactly 43 unpadded base64url characters
// is scored normally. The residual channel is one hash-sized token per value
// on requests that declare S256, which is what the protocol itself sends.
func isPKCES256Challenge(key, value string, s256 bool) bool {
	if !s256 || key != pkceChallengeParam || len(value) != pkceS256ChallengeLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// isAssetHashSlot reports whether token is a whole build-hash slot: 1 to 8
// characters from [A-Za-z0-9_-]. A longer token is never partly trimmed,
// because peeling eight characters off it could leave a stem under the
// length floor and hide the rest.
func isAssetHashSlot(token string) bool {
	if token == "" || len(token) > maxAssetHashSlotLen {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// assetEntropySubject returns the part of a path segment the entropy gate
// measures. For a static asset named <stem>.<hash>.<ext>, where <hash> is a
// whole slot of at most eight characters, that is the stem alone. Every other
// segment, including an asset whose name is all hash, is measured whole.
func assetEntropySubject(segment string) string {
	rest := segment
	if trimmed, ok := strings.CutSuffix(rest, sourceMapExtension); ok {
		rest = trimmed
	}
	matched := rest != segment
	for _, ext := range assetExtensions {
		if trimmed, ok := strings.CutSuffix(rest, ext); ok {
			rest = trimmed
			matched = true
			break
		}
	}
	if !matched {
		return segment
	}
	dot := strings.LastIndexByte(rest, '.')
	if dot < 0 || !isAssetHashSlot(rest[dot+1:]) {
		return segment
	}
	return rest[:dot]
}

// pathSegmentEntropy measures one path segment. It reports the entropy and
// whether it exceeded the gate.
func (s *Scanner) pathSegmentEntropy(segment string) (float64, bool) {
	subject := assetEntropySubject(segment)
	if len(subject) < s.entropyMinLen {
		return 0, false
	}
	entropy := payloadEntropy(subject)
	return entropy, entropy > s.entropyThreshold
}

// parseEntropyNestedURL returns value as a URL whose parts can be scored
// separately. The value is iteratively percent-decoded first, so an extra
// encoding layer cannot lower the entropy of what it carries. Only an http or
// https URL with a host qualifies. Any other scheme, including data: and
// javascript:, keeps its payload in Opaque or Path, so it stays on the
// whole-value check.
func parseEntropyNestedURL(value string) (*url.URL, bool) {
	decoded := IterativeDecode(value)
	if !strings.Contains(decoded, "://") {
		return nil, false
	}
	u, err := url.Parse(decoded)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return nil, false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u, true
	default:
		return nil, false
	}
}

// queryValueEntropy scores one decoded query value. A value that is an http(s)
// URL is scored part by part, down to maxNestedURLEntropyDepth URL layers;
// everything else, and anything past that depth, is scored as one string with
// the same gate as before. Nothing is skipped because it looks like a URL.
func (s *Scanner) queryValueEntropy(value string, depth int) (entropyFinding, bool) {
	if len(value) < s.entropyMinLen {
		return entropyFinding{}, false
	}
	if depth < maxNestedURLEntropyDepth {
		if nested, ok := parseEntropyNestedURL(value); ok {
			return s.nestedURLEntropy(nested, depth+1)
		}
	}
	// Free text such as a search query is scored one ASCII-whitespace token
	// at a time: search syntax is punctuation-dense but no single word is
	// random. Splitting alone would let random chunks shorter than the
	// minimum pass, so the value is also scored with ASCII punctuation and
	// whitespace removed: search words stay low (about 4.2 bits) while split
	// random text stays high. Unicode whitespace does not split.
	parts := []string{value}
	if strings.ContainsAny(value, " \t\n\r\v\f") {
		parts = strings.FieldsFunc(value, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
		})
		joined := asciiAlnumOnly(value)
		scored := joined
		// Too few letters and digits to score on their own: score the whole
		// value as before, so punctuation-heavy text cannot skip the check.
		if len(joined) < s.entropyMinLen {
			scored = value
		}
		if entropy := payloadEntropy(scored); entropy > s.entropyThreshold {
			return entropyFinding{entropy: entropy}, true
		}
	}
	for _, part := range parts {
		if len(part) < s.entropyMinLen {
			continue
		}
		entropy := payloadEntropy(part)
		if shouldSkipQueryValueEntropy(part, entropy, s.entropyThreshold) {
			continue
		}
		if entropy > s.entropyThreshold {
			return entropyFinding{entropy: entropy}, true
		}
	}
	return entropyFinding{}, false
}

// nestedURLEntropy scores every part of a URL carried in a query value: host
// labels, userinfo, path segments, query keys and values, and the fragment.
// Each part gets the same length floor and threshold as the outer URL. In a
// query value the fragment is real bytes on the wire, so it is measured too.
func (s *Scanner) nestedURLEntropy(u *url.URL, depth int) (entropyFinding, bool) {
	over := func(part, text string) (entropyFinding, bool) {
		if len(text) < s.entropyMinLen {
			return entropyFinding{}, false
		}
		if entropy := payloadEntropy(text); entropy > s.entropyThreshold {
			return entropyFinding{part: part, entropy: entropy}, true
		}
		return entropyFinding{}, false
	}
	for _, label := range strings.Split(u.Hostname(), ".") {
		if f, blocked := over("nested URL host label", label); blocked {
			return f, true
		}
	}
	if u.User != nil {
		if f, blocked := over("nested URL userinfo", u.User.Username()); blocked {
			return f, true
		}
		if password, ok := u.User.Password(); ok {
			if f, blocked := over("nested URL userinfo", password); blocked {
				return f, true
			}
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if entropy, blocked := s.pathSegmentEntropy(segment); blocked {
			return entropyFinding{part: "nested URL path segment", entropy: entropy}, true
		}
	}
	pairs := splitQueryEntropyPairs(u.RawQuery)
	s256 := pkceExemptionApplies(queryEntropyPairValues(pairs, pkceMethodParam), queryEntropyPairValues(pairs, pkceChallengeParam))
	dohMsg, dohQuery := parseDNSQuery(u.RawQuery)
	for _, p := range pairs {
		if len(p.key) >= s.entropyMinLen {
			if entropy := ShannonEntropy(p.key); entropy > s.entropyThreshold {
				return entropyFinding{part: "nested URL query key", entropy: entropy}, true
			}
		}
		if isPKCES256Challenge(p.key, p.value, s256) {
			continue
		}
		if dohQuery && p.key == dnsQueryParam {
			if f, blocked := s.dnsMessageEntropy(dohMsg); blocked {
				return f, true
			}
			continue
		}
		if f, blocked := s.queryValueEntropy(p.value, depth); blocked {
			if f.part == "" {
				f.part = "nested URL query value"
			}
			return f, true
		}
	}
	return over("nested URL fragment", u.Fragment)
}

// queryEntropyPairValues returns every value of key, in order.
func queryEntropyPairValues(pairs []queryEntropyPair, key string) []string {
	var out []string
	for _, p := range pairs {
		if p.key == key {
			out = append(out, p.value)
		}
	}
	return out
}

// queryEntropyParamResult builds the block for a query value finding. The
// reason keeps the queryEntropyParamReasonPrefix + quoted key shape that
// remediation and explain consumers match on; a nested part is named after it.
func (s *Scanner) queryEntropyParamResult(key string, f entropyFinding) Result {
	reason := fmt.Sprintf(queryEntropyParamReasonPrefix+"%q (%.2f > %.2f threshold)", key, f.entropy, s.entropyThreshold)
	if f.part != "" {
		reason = fmt.Sprintf(queryEntropyParamReasonPrefix+"%q %s (%.2f > %.2f threshold)", key, f.part, f.entropy, s.entropyThreshold)
	}
	return Result{
		Allowed: false,
		Reason:  reason,
		Scanner: ScannerEntropy,
		Class:   ClassHeuristicEntropy,
		Score:   math.Min(f.entropy/8.0, 1.0),
	}
}

// asciiAlnumOnly keeps ASCII letters and digits and drops everything else, so
// punctuation and spacing cannot raise or lower a free-text value's score.
func asciiAlnumOnly(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}
