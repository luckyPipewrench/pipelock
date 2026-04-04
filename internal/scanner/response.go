// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// ResponseScanResult describes the outcome of scanning response content.
type ResponseScanResult struct {
	Clean              bool
	Matches            []ResponseMatch
	TransformedContent string // set for strip and ask actions
}

// ResponseMatch describes a single pattern match in response content.
type ResponseMatch struct {
	PatternName   string `json:"pattern_name"`
	MatchText     string `json:"match_text"` // truncated to 100 chars
	Position      int    `json:"position"`
	Bundle        string `json:"bundle,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
}

// ScanResponse checks fetched content for prompt injection patterns.
// If scanning is disabled, returns Clean=true immediately.
// Zero-width Unicode characters are stripped before scanning to prevent
// evasion via invisible character insertion.
// For "strip" action, replaces matches with [REDACTED: PatternName].
func (s *Scanner) ScanResponse(ctx context.Context, content string) ResponseScanResult {
	// Fail-closed: if context is already canceled, block immediately.
	if ctx != nil && ctx.Err() != nil {
		return ResponseScanResult{
			Clean: false,
			Matches: []ResponseMatch{{
				PatternName: "context_canceled",
				MatchText:   ctx.Err().Error(),
			}},
		}
	}
	if !s.responseEnabled {
		return ResponseScanResult{Clean: true}
	}

	// Save original for secondary pass before normalization.
	original := content

	// Primary: drop invisible chars, then normalize. Catches mid-word ZW insertion
	// where the attacker splits a keyword: "igno\u200bre" → "ignore" (detected).
	content = normalize.ForMatching(content)

	// Primary: run response patterns whose keywords appear in content.
	// Pre-filter checks are per-pass: each normalized variant gets its
	// own keyword check because normalization reveals new keywords
	// (e.g., leetspeak "1gnore" → "ignore" after normalization).
	var matches []ResponseMatch
	matches = s.matchResponsePatternsPreFiltered(content)

	// Secondary: replace invisible chars with spaces, then normalize. Catches
	// word-boundary collapse where the attacker uses ZW instead of space:
	// "ignore\u200ball" → ForMatching drops ZW → "ignoreall" (bypass).
	// Replacing with space first → "ignore all" → regex `ignore\s+all` matches.
	if len(matches) == 0 {
		spaced := normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(original))
		if spaced != content {
			matches = s.matchResponsePatternsPreFiltered(spaced)
			if len(matches) > 0 {
				content = spaced // use spaced version for strip action
			}
		}
	}

	// Tertiary: leetspeak normalization. Pre-filter runs on the LEETED
	// content, catching keywords that emerge after digit-to-letter conversion.
	if len(matches) == 0 {
		leeted := normalize.Leetspeak(content)
		if leeted != content {
			matches = s.matchResponsePatternsPreFiltered(leeted)
		}
	}

	// Quaternary: optional-whitespace matching on ZW-stripped text. Catches the
	// combined attack where ZW chars split keywords AND replace word separators:
	// "i\u200bgnore\u200ball\u200bprevious" -> strip ZW -> "ignoreallprevious"
	// Standard \s+ patterns fail on zero whitespace; \s* variants match.
	if len(matches) == 0 && len(s.responseOptSpacePatterns) > 0 {
		matches = matchPatternsPreFiltered(s.responseOptSpacePreFilter, s.responseOptSpacePatterns, content)
	}

	// Quinary: vowel-folded matching. Catches confusable-vowel attacks where
	// one character (e.g., ø→o) replaces multiple different vowels, producing
	// near-miss words like "instroctions" that don't match "instructions".
	// Folding all vowels to 'a' in both content and patterns makes them match.
	if len(matches) == 0 && len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(content)
		if folded != content {
			matches = matchPatternsPreFiltered(s.responseVowelFoldPreFilter, s.responseVowelFoldPatterns, folded)
		}
	}

	// Senary: base64/hex decode pass. Only runs when content contains a
	// contiguous run of base64/hex alphabet characters long enough to be
	// a meaningful encoded payload. Skips expensive decode attempts on
	// normal text content.
	if len(matches) == 0 && hasEncodedRun(content) {
		matches = s.matchDecodedResponse(content)
	}

	// Post-scan context check: if context expired during scanning, fail closed.
	if ctx != nil && ctx.Err() != nil {
		return ResponseScanResult{
			Clean: false,
			Matches: []ResponseMatch{{
				PatternName: "context_canceled",
				MatchText:   ctx.Err().Error(),
			}},
		}
	}

	if len(matches) == 0 {
		return ResponseScanResult{Clean: true}
	}

	result := ResponseScanResult{
		Clean:   false,
		Matches: matches,
	}

	if s.responseAction == config.ActionStrip || s.responseAction == config.ActionAsk {
		transformed := content
		for _, p := range s.responsePatterns {
			replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
			transformed = p.re.ReplaceAllString(transformed, replacement)
		}
		for _, p := range s.responseOptSpacePatterns {
			replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
			transformed = p.re.ReplaceAllString(transformed, replacement)
		}
		for _, p := range s.responseVowelFoldPatterns {
			replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
			transformed = p.re.ReplaceAllString(transformed, replacement)
		}
		// If redaction had no effect (detection came from a transformed pass
		// like vowel-fold or decoded where patterns don't match the original
		// text form), leave TransformedContent empty. Callers treat empty
		// TransformedContent as "could not strip, fall back to block".
		if transformed != content {
			result.TransformedContent = transformed
		}
	}

	return result
}

// matchPatternsAgainst runs a pattern set against content and returns matches.
// Shared by standard response patterns and optional-whitespace variants.
func matchPatternsAgainst(patterns []*compiledPattern, content string) []ResponseMatch {
	var matches []ResponseMatch
	for _, p := range patterns {
		locs := p.re.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matchText := content[loc[0]:loc[1]]
			if runes := []rune(matchText); len(runes) > 100 {
				matchText = string(runes[:100])
			}
			matches = append(matches, ResponseMatch{
				PatternName:   p.name,
				MatchText:     matchText,
				Position:      loc[0],
				Bundle:        p.bundle,
				BundleVersion: p.bundleVersion,
			})
		}
	}
	return matches
}

// matchResponsePatternsPreFiltered checks the primary response pre-filter
// for keyword candidates, then runs only matching patterns' regex.
func (s *Scanner) matchResponsePatternsPreFiltered(content string) []ResponseMatch {
	return matchPatternsPreFiltered(s.responsePreFilter, s.responsePatterns, content)
}

// matchPatternsPreFiltered checks a pre-filter for keyword candidates in
// content, then runs ONLY the matching patterns' regex. If no pre-filter
// is configured, falls back to running all patterns. On clean 10KB content,
// the pre-filter finds no candidates and zero regex patterns execute.
func matchPatternsPreFiltered(pf *responsePreFilter, patterns []*compiledPattern, content string) []ResponseMatch {
	if pf == nil {
		return matchPatternsAgainst(patterns, content)
	}
	indices := pf.patternsToCheck(content)
	if len(indices) == 0 {
		return nil
	}
	var matches []ResponseMatch
	for _, idx := range indices {
		if idx < 0 || idx >= len(patterns) {
			continue
		}
		p := patterns[idx]
		locs := p.re.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matchText := content[loc[0]:loc[1]]
			if runes := []rune(matchText); len(runes) > 100 {
				matchText = string(runes[:100])
			}
			matches = append(matches, ResponseMatch{
				PatternName:   p.name,
				MatchText:     matchText,
				Position:      loc[0],
				Bundle:        p.bundle,
				BundleVersion: p.bundleVersion,
			})
		}
	}
	return matches
}

// minSegmentDecodeLen is the minimum length for an extracted base64/hex segment
// to attempt decoding. Short segments produce too many false decode attempts.
const minSegmentDecodeLen = 16

// responseDecodeMaxDepth bounds recursive decode to prevent CPU exhaustion.
// Set to 5 (vs text_dlp's 3) because the response path has no separate
// IterativeDecode pass for URL layers, so deeper nesting is plausible.
const responseDecodeMaxDepth = 5

// matchDecodedResponse tries base64/hex decoding content and checks the decoded
// result for injection patterns. Recurses up to responseDecodeMaxDepth to catch
// multi-layer chains (e.g., base64(hex(injection))). Two strategies per layer:
// whole-content decode and segment-level decode.
func (s *Scanner) matchDecodedResponse(content string) []ResponseMatch {
	return s.matchDecodedResponseRecursive(content, 0)
}

// matchDecodedResponseRecursive is the recursive implementation of matchDecodedResponse.
func (s *Scanner) matchDecodedResponseRecursive(content string, depth int) []ResponseMatch {
	if depth >= responseDecodeMaxDepth {
		return nil
	}

	// Strategy 1: whole-content decode.
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, content)

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(stripped); err == nil && len(decoded) > 0 {
			d := string(decoded)
			if matches := s.matchDecodedNormalized(d); len(matches) > 0 {
				return matches
			}
			// Always recurse on successful decode. The depth limit is the
			// safety bound; gating on hasEncodedRun lets attackers bypass
			// by splitting or punctuating the inner encoded layer.
			if matches := s.matchDecodedResponseRecursive(d, depth+1); len(matches) > 0 {
				return matches
			}
		}
	}
	if decoded, err := hex.DecodeString(stripped); err == nil && len(decoded) > 0 {
		d := string(decoded)
		if matches := s.matchDecodedNormalized(d); len(matches) > 0 {
			return matches
		}
		if matches := s.matchDecodedResponseRecursive(d, depth+1); len(matches) > 0 {
			return matches
		}
	}

	// Strategy 2: segment-level decode with recursion.
	if matches := s.matchDecodedSegmentsRecursive(content, depth); len(matches) > 0 {
		return matches
	}

	return nil
}

// matchDecodedSegmentsRecursive extracts contiguous base64-alphabet runs from
// content, decodes each individually, and checks for injection patterns.
// Recurses on decoded segments to catch multi-layer encoding.
func (s *Scanner) matchDecodedSegmentsRecursive(content string, depth int) []ResponseMatch {
	if depth >= responseDecodeMaxDepth {
		return nil
	}
	segments := extractEncodedRuns(content, minSegmentDecodeLen)
	for _, seg := range segments {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding,
		} {
			if decoded, err := enc.DecodeString(seg); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
				d := string(decoded)
				if matches := s.matchDecodedNormalized(d); len(matches) > 0 {
					return matches
				}
				if matches := s.matchDecodedResponseRecursive(d, depth+1); len(matches) > 0 {
					return matches
				}
			}
		}
		if decoded, err := hex.DecodeString(seg); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
			d := string(decoded)
			if matches := s.matchDecodedNormalized(d); len(matches) > 0 {
				return matches
			}
			if matches := s.matchDecodedResponseRecursive(d, depth+1); len(matches) > 0 {
				return matches
			}
		}
	}
	return nil
}

// extractEncodedRuns finds contiguous runs of base64/hex alphabet characters
// at least minLen long. Returns the segments without surrounding text.
//
// '=' is treated as a segment boundary (like key=value separators) rather than
// part of the alphabet. After each run is collected, up to 2 trailing '='
// characters are re-attached as base64 padding. This prevents "key=payload"
// from collapsing into one segment that decoders reject.
func extractEncodedRuns(content string, minLen int) []string {
	var runs []string
	start := -1
	for i := 0; i < len(content); i++ {
		c := content[i]
		inAlphabet := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			c == '-' || c == '_'
		if inAlphabet {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 {
				end := i
				// Re-attach up to 2 trailing '=' for base64 padding.
				end = attachBase64Padding(content, end)
				if end-start >= minLen {
					runs = append(runs, content[start:end])
				}
			}
			start = -1
		}
	}
	// Flush trailing run at end of content.
	if start >= 0 {
		end := len(content)
		if end-start >= minLen {
			runs = append(runs, content[start:end])
		}
	}
	return runs
}

// attachBase64Padding extends end past up to 2 consecutive '=' characters
// immediately following a base64 alphabet run.
func attachBase64Padding(content string, end int) int {
	for pad := 0; pad < 2 && end < len(content) && content[end] == '='; pad++ {
		end++
	}
	return end
}

// isPrintableText checks whether decoded bytes are mostly printable text.
// Accepts valid UTF-8 including non-ASCII letters and symbols (which the
// normalizer's confusable map handles), but rejects control characters and
// invalid byte sequences. Prevents false positives from random byte
// sequences that happen to base64-decode.
func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if !utf8.Valid(data) {
		return false
	}
	total := 0
	printable := 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		total++
		if unicode.IsPrint(r) || r == '\t' || r == '\n' || r == '\r' {
			printable++
		}
		i += size
	}
	// At least 80% printable runes to be considered text.
	return printable*5 >= total*4
}

// matchDecodedNormalized runs all response scanning passes (primary, opt-space,
// vowel-fold) against decoded content. Without this, encoded payloads carrying
// vowel-substituted or zero-width-separated injection would bypass detection.
func (s *Scanner) matchDecodedNormalized(decoded string) []ResponseMatch {
	normalized := normalize.ForMatching(decoded)
	if matches := matchPatternsPreFiltered(s.responsePreFilter, s.responsePatterns, normalized); len(matches) > 0 {
		return matches
	}
	if len(s.responseOptSpacePatterns) > 0 {
		if matches := matchPatternsPreFiltered(s.responseOptSpacePreFilter, s.responseOptSpacePatterns, normalized); len(matches) > 0 {
			return matches
		}
	}
	if len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(normalized)
		if folded != normalized {
			if matches := matchPatternsPreFiltered(s.responseVowelFoldPreFilter, s.responseVowelFoldPatterns, folded); len(matches) > 0 {
				return matches
			}
		}
	}
	return nil
}

// ResponseScanningEnabled returns whether response scanning is active.
func (s *Scanner) ResponseScanningEnabled() bool {
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
func (s *Scanner) ResponseAction() string {
	return s.responseAction
}
