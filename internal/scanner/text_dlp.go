// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/seedprotect"
)

// TextDLPMatch describes a single DLP pattern match in arbitrary text.
type TextDLPMatch struct {
	PatternName   string `json:"pattern_name"`
	Severity      string `json:"severity"`
	Encoded       string `json:"encoded,omitempty"` // "", "base64", "hex", "base32", "env", "url", "subdomain"
	Bundle        string `json:"bundle,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
	Warn          bool   `json:"warn,omitempty"` // true for warn-mode patterns (informational only)
}

// TextDLPResult describes the outcome of scanning text for DLP patterns.
type TextDLPResult struct {
	Clean                bool           `json:"clean"`
	Matches              []TextDLPMatch `json:"matches,omitempty"`
	InformationalMatches []TextDLPMatch `json:"informational_matches,omitempty"` // warn-mode matches (non-blocking)
}

// ScanTextForDLP checks arbitrary text for DLP pattern matches and env secret leaks.
// Unlike checkDLP (which operates on URLs), this method works on raw text strings
// from MCP tool arguments. It applies zero-width stripping, NFKC normalization,
// and checks encoded variants (base64, hex, base32) of the text for patterns.
func (s *Scanner) ScanTextForDLP(ctx context.Context, text string) TextDLPResult {
	// Core DLP runs FIRST — immutable safety floor. Core matches are
	// prepended to results; main scanner also runs to capture additional
	// findings (env leaks, seed phrases, non-core patterns).
	coreMatches := s.scanCoreDLP(text)

	if len(s.dlpPatterns) == 0 &&
		len(s.canaryTokens) == 0 &&
		len(s.envSecrets) == 0 &&
		len(s.fileSecrets) == 0 &&
		!s.seedEnabled {
		if len(coreMatches) > 0 {
			return TextDLPResult{Clean: false, Matches: coreMatches}
		}
		return TextDLPResult{Clean: true}
	}

	var matches []TextDLPMatch

	// Seed phrase detection runs FIRST so seed phrases get the correct label
	// ("BIP-39 Seed Phrase") instead of an accidental regex DLP match.
	// A base64-encoded seed phrase can decode to text matching WIF/xprv regex,
	// so seed detection must win the race.
	// Uses ForMatching() normalization (preserves whitespace for word boundaries)
	// instead of ForDLP() (strips whitespace, destroying word boundaries).
	if s.seedEnabled {
		seedText := normalize.ForMatching(text)
		type seedCandidate struct {
			text    string
			encoded string
		}
		candidates := []seedCandidate{{seedText, ""}}
		// URL-decoded variant
		if decoded := IterativeDecode(seedText); decoded != seedText {
			candidates = append(candidates, seedCandidate{decoded, "url"})
		}
		// Base64-decoded variant
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding,
		} {
			if decoded, err := enc.DecodeString(strings.TrimSpace(seedText)); err == nil && len(decoded) > 0 {
				candidates = append(candidates, seedCandidate{string(decoded), "base64"})
			}
		}
		// Hex-decoded variant
		if decoded, err := hex.DecodeString(strings.TrimSpace(seedText)); err == nil && len(decoded) > 0 {
			candidates = append(candidates, seedCandidate{string(decoded), "hex"})
		}
		// Base32-decoded variant
		if decoded, err := base32.StdEncoding.DecodeString(strings.TrimSpace(seedText)); err == nil && len(decoded) > 0 {
			candidates = append(candidates, seedCandidate{string(decoded), "base32"})
		}
		// Segment-level decoding: split on the same delimiters as decodeTextSegments()
		// to maintain parity. Catches encoded seed phrases embedded in URLs within
		// MCP tool arguments (e.g., "visit https://evil/<base64-seed> now").
		segments := strings.FieldsFunc(seedText, func(r rune) bool {
			return r == '/' || r == '?' || r == '&' || r == '=' || r == ' ' || r == '\n' || r == '\t'
		})
		for _, seg := range segments {
			if len(seg) < 20 { // seed phrases are long; skip short segments
				continue
			}
			for _, d := range decodeEncodings(seg) {
				candidates = append(candidates, seedCandidate{d.text, d.encoding})
			}
		}
		for _, c := range candidates {
			if seedMatches := seedprotect.Detect(c.text, s.seedMinWords, s.seedVerifyChecksum); len(seedMatches) > 0 {
				matches = append(matches, TextDLPMatch{
					PatternName: "BIP-39 Seed Phrase",
					Severity:    "critical",
					Encoded:     c.encoded,
				})
				break // one seed match per scan is sufficient
			}
		}
	}

	// Full normalization before DLP pattern matching: strip control chars,
	// NFKC, cross-script confusable mapping, and combining mark removal.
	// Must match response scanning depth — otherwise attackers use homoglyphs
	// in key prefixes (e.g., sk-օnt-... with Armenian օ U+0585 for 'a').
	cleaned := normalize.ForDLP(text)
	matches = append(matches, s.scanCanaryText(cleaned)...)

	// Check raw text against DLP patterns (before URL decoding).
	// This catches secrets that aren't URL-encoded.
	for _, idx := range s.dlpPreFilter.patternsToCheck(cleaned) {
		p := s.dlpPatterns[idx]
		if p.matches(cleaned) {
			matches = append(matches, TextDLPMatch{
				PatternName:   p.name,
				Severity:      p.severity,
				Bundle:        p.bundle,
				BundleVersion: p.bundleVersion,
				Warn:          p.warn,
			})
		}
	}

	// Iterative URL-decode and re-check DLP patterns (catches %2D → - etc.).
	// Uses IterativeDecode to defeat multi-layer encoding.
	if decoded := IterativeDecode(cleaned); decoded != cleaned {
		matches = append(matches, s.matchDLPPatterns(decoded, "url")...)
	}

	// Dot-collapse check: catches secrets split across DNS subdomains
	// (e.g. "sk-ant-api03.AABBCCDD.EEFFGGHH.evil.com" → "sk-ant-api03AABBCCDDEEFFGGHH...").
	// Only applied when text contains dots that could be subdomain separators.
	if strings.Contains(cleaned, ".") {
		dotless := strings.ReplaceAll(cleaned, ".", "")
		if dotless != cleaned {
			matches = append(matches, s.matchDLPPatterns(dotless, "subdomain")...)
		}
	}

	// Recursive encoding decode: try base64, hex, base32 decoding and re-check
	// DLP patterns on decoded content. Recurse up to 3 rounds to catch multi-layer
	// chains (e.g., base64(hex(secret)), URL-encode(base64(secret))).
	matches = append(matches, s.decodeAndMatchRecursive(cleaned, 0)...)

	// Segment-level encoding detection: split text on URL/path delimiters and
	// try decoding each segment individually. Catches encoded secrets embedded
	// in URLs within MCP tool arguments (e.g., "https://evil.com/<hex-key>/data")
	// where whole-string decode fails because the text isn't pure hex/base64.
	// Only skip segment decoding when enforced matches already exist.
	// Warn-only matches must not gate off further scanning — an enforced
	// match might hide in a decoded segment.
	if !hasEnforcedMatch(matches) {
		matches = append(matches, s.decodeTextSegments(cleaned)...)
	}

	// Check for env secret leaks (raw + encoded forms).
	matches = append(matches, s.checkSecretsInText(s.envSecrets, cleaned, "Environment Variable Leak", "env")...)

	// Check for file secret leaks (raw + encoded forms).
	matches = append(matches, s.checkSecretsInText(s.fileSecrets, cleaned, "Known Secret Leak", "")...)

	// Deduplicate matches by pattern name + encoding.
	matches = deduplicateMatches(matches)

	// Prepend core matches — core findings cannot be overridden.
	if len(coreMatches) > 0 {
		matches = append(coreMatches, matches...)
		matches = deduplicateMatches(matches)
	}

	if len(matches) == 0 {
		return TextDLPResult{Clean: true}
	}

	// Partition matches: warn-mode patterns go to InformationalMatches,
	// enforced patterns go to Matches. Warn-only results are Clean=true
	// so transports take no enforcement action.
	var enforced, informational []TextDLPMatch
	for _, m := range matches {
		if m.Warn {
			informational = append(informational, m)
		} else {
			enforced = append(enforced, m)
		}
	}

	// Emit warn events through the instance hook so callers don't need individual wiring.
	if len(informational) > 0 && s.dlpWarnHook != nil {
		for _, m := range informational {
			s.dlpWarnHook(ctx, m.PatternName, m.Severity)
		}
	}

	return TextDLPResult{
		Clean:                len(enforced) == 0,
		Matches:              enforced,
		InformationalMatches: informational,
	}
}

// maxDecodeDepth bounds recursive encoding decode to prevent CPU exhaustion.
const maxDecodeDepth = 3

// decodeAndMatchRecursive tries base64, hex, and base32 decoding, runs DLP
// patterns on decoded content, then recurses on the decoded result to catch
// multi-layer chains (e.g., base64(hex(secret))). Stops at maxDecodeDepth.
func (s *Scanner) decodeAndMatchRecursive(text string, depth int) []TextDLPMatch {
	if depth >= maxDecodeDepth {
		return nil
	}

	var matches []TextDLPMatch

	// Try base64 decoding (padded and unpadded variants).
	for _, enc := range []struct {
		e *base64.Encoding
	}{
		{base64.StdEncoding},
		{base64.URLEncoding},
		{base64.RawStdEncoding},
		{base64.RawURLEncoding},
	} {
		if decoded, err := enc.e.DecodeString(text); err == nil && len(decoded) > 0 {
			d := string(decoded)
			matches = append(matches, s.matchDLPPatterns(d, "base64")...)
			// Recurse: the decoded content may itself be encoded.
			matches = append(matches, s.decodeAndMatchRecursive(d, depth+1)...)
		}
	}

	// Try hex decoding (raw and delimiter-stripped).
	if decoded, err := hex.DecodeString(text); err == nil && len(decoded) > 0 {
		d := string(decoded)
		matches = append(matches, s.matchDLPPatterns(d, "hex")...)
		matches = append(matches, s.decodeAndMatchRecursive(d, depth+1)...)
	} else if normalized := normalizeHex(text); normalized != "" {
		if decoded, err := hex.DecodeString(normalized); err == nil && len(decoded) > 0 {
			d := string(decoded)
			matches = append(matches, s.matchDLPPatterns(d, "hex")...)
			matches = append(matches, s.decodeAndMatchRecursive(d, depth+1)...)
		}
	}

	// Try base32 decoding.
	if decoded, err := base32.StdEncoding.DecodeString(text); err == nil && len(decoded) > 0 {
		d := string(decoded)
		matches = append(matches, s.matchDLPPatterns(d, "base32")...)
		matches = append(matches, s.decodeAndMatchRecursive(d, depth+1)...)
	}

	// Iterative URL-decode on decoded content (catches URL(base64(secret))).
	if decoded := IterativeDecode(text); decoded != text {
		matches = append(matches, s.matchDLPPatterns(decoded, "url")...)
		matches = append(matches, s.decodeAndMatchRecursive(decoded, depth+1)...)
	}

	return matches
}

// matchDLPPatterns runs DLP regex patterns against text, tagging matches with encoding.
// Applies full normalization to decoded text, since URL/base64/hex decoding can
// reintroduce control chars and confusable characters after the initial pass.
func (s *Scanner) matchDLPPatterns(text, encoding string) []TextDLPMatch {
	text = normalize.ForDLP(text)
	var matches []TextDLPMatch
	for _, idx := range s.dlpPreFilter.patternsToCheck(text) {
		p := s.dlpPatterns[idx]
		if p.matches(text) {
			matches = append(matches, TextDLPMatch{
				PatternName:   p.name,
				Severity:      p.severity,
				Encoded:       encoding,
				Bundle:        p.bundle,
				BundleVersion: p.bundleVersion,
				Warn:          p.warn,
			})
		}
	}
	return matches
}

// checkSecretsInText scans text for leaked secrets (env vars or file-based).
// If encodedOverride is non-empty, all matches use that as the Encoded field (e.g. "env").
// Otherwise, the actual encoding label from matchSecretEncodings is used.
func (s *Scanner) checkSecretsInText(secrets []string, text, patternName, encodedOverride string) []TextDLPMatch {
	if len(secrets) == 0 {
		return nil
	}

	texts := []string{text}
	lowerTexts := []string{strings.ToLower(text)}

	for _, secret := range secrets {
		if matched, enc := matchSecretEncodings(secret, texts, lowerTexts); matched {
			m := TextDLPMatch{PatternName: patternName, Severity: "critical"}
			if encodedOverride != "" {
				m.Encoded = encodedOverride
			} else {
				m.Encoded = enc
			}
			return []TextDLPMatch{m}
		}
	}
	return nil
}

// deduplicateMatches removes duplicate matches with the same pattern name and encoding.
func deduplicateMatches(matches []TextDLPMatch) []TextDLPMatch {
	if len(matches) <= 1 {
		return matches
	}

	type key struct {
		name    string
		encoded string
	}
	seen := make(map[key]struct{}, len(matches))
	result := make([]TextDLPMatch, 0, len(matches))
	for _, m := range matches {
		k := key{name: m.PatternName, encoded: m.Encoded}
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			result = append(result, m)
		}
	}
	return result
}

// hasEnforcedMatch reports whether any match in the slice is non-warn (enforced).
func hasEnforcedMatch(matches []TextDLPMatch) bool {
	for _, m := range matches {
		if !m.Warn {
			return true
		}
	}
	return false
}

// decodeTextSegments splits text on common URL/path delimiters and tries
// hex/base64/base32 decoding on each segment. Catches encoded secrets
// embedded in URLs (e.g., "https://evil.com/<hex-encoded-key>/data") where
// whole-string decode fails because the surrounding text isn't valid encoding.
func (s *Scanner) decodeTextSegments(text string) []TextDLPMatch {
	// Split on URL-like delimiters: /, ?, &, =, space, newline.
	segments := strings.FieldsFunc(text, func(r rune) bool {
		return r == '/' || r == '?' || r == '&' || r == '=' || r == ' ' || r == '\n' || r == '\t'
	})

	var matches []TextDLPMatch
	for _, seg := range segments {
		if len(seg) < 10 {
			continue // too short to be a meaningful encoded secret
		}
		// Try direct decode + DLP match.
		for _, d := range decodeEncodings(seg) {
			if m := s.matchDLPPatterns(d.text, d.encoding); len(m) > 0 {
				matches = append(matches, m...)
				return matches // short-circuit on first match
			}
		}
		// Try recursive decode on the segment (catches multi-layer within a segment).
		if m := s.decodeAndMatchRecursive(seg, 0); len(m) > 0 {
			matches = append(matches, m...)
			return matches
		}
	}
	return matches
}
