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

	// StegoDetected fires when the raw response carries combining-mark density
	// at or above normalize.ZalgoSuspiciousThreshold. The pattern-matching
	// pipeline already neutralizes combining marks via StripCombiningMarks, so
	// this is an exposure/provenance signal - Clean is NOT flipped on the
	// basis of this field alone. The taint/authority policy layer may key on
	// this signal in strict mode without changing the scanner's verdict
	// contract today. Maps to emit.EventTextStego.
	StegoDetected bool
	StegoDensity  int // raw combining-mark density on original content
}

// ResponseMatch describes a single pattern match in response content.
type ResponseMatch struct {
	PatternName   string `json:"pattern_name"`
	MatchText     string `json:"match_text"` // truncated to 100 chars
	Position      int    `json:"position"`
	Bundle        string `json:"bundle,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
	matchLength   int
	span          MatchSpan
}

type responseMatchSet struct {
	matches []ResponseMatch
	content string
}

// Span returns retained coordinates for this match in the normalized scanner
// view named by MatchSpan.ViewLabel. It never includes matched bytes.
func (m ResponseMatch) Span() MatchSpan {
	return m.span
}

// ScanResponse checks fetched content for prompt injection patterns.
// If scanning is disabled, returns Clean=true immediately.
// Zero-width Unicode characters are stripped before scanning to prevent
// evasion via invisible character insertion.
// For "strip" action, replaces matches with [REDACTED: PatternName].
func (s *Scanner) ScanResponse(ctx context.Context, content string) (out ResponseScanResult) {
	original := content

	// Stego exposure signal. Computed on the raw content before normalization
	// strips combining marks. The deferred setter stamps every return path -
	// including the context_canceled and clean fast paths - so downstream
	// consumers (taint/authority layer, audit emitters) can key on the
	// signal without re-scanning. The signal does NOT flip Clean: the
	// matching passes already neutralize combining marks via
	// StripCombiningMarks, so this is an exposure/provenance event, not a
	// block trigger.
	stegoDensity := normalize.ZalgoDensity(original)
	stegoDetected := stegoDensity >= normalize.ZalgoSuspiciousThreshold
	defer func() {
		out.StegoDensity = stegoDensity
		out.StegoDetected = stegoDetected
	}()

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

	// Core response patterns run FIRST - immutable safety floor.
	// These run regardless of response_scanning.enabled.
	if coreSet := s.scanCoreResponse(ctx, original); len(coreSet.matches) > 0 {
		// Defensive anti-solicitation filtering happens per-pass inside
		// scanCoreResponse (not here), so an all-defensive early pass cannot
		// mask an encoded solicitation that only a later pass catches.
		coreMatches := filterEducationalQuotedResponseMatches(coreSet.content, coreSet.matches)
		if len(coreMatches) == 0 {
			if !s.responseEnabled {
				return ResponseScanResult{Clean: true}
			}
		} else {
			result := ResponseScanResult{
				Clean:   false,
				Matches: coreMatches,
			}
			// Support strip/ask actions on core matches so callers that
			// configured strip still get TransformedContent.
			if s.responseAction == config.ActionStrip || s.responseAction == config.ActionAsk {
				transformed := normalize.ForMatching(content)
				for _, p := range s.core.responsePatterns {
					replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
					transformed = p.re.ReplaceAllString(transformed, replacement)
				}
				if transformed != normalize.ForMatching(content) {
					result.TransformedContent = transformed
				}
			}
			return result
		}
	}

	if !s.responseEnabled {
		return ResponseScanResult{Clean: true}
	}

	// Primary: drop invisible chars, then normalize. Catches mid-word ZW insertion
	// where the attacker splits a keyword: "igno\u200bre" → "ignore" (detected).
	content = normalize.ForMatching(content)
	matchContent := content

	// Primary: run response patterns whose keywords appear in content.
	// Pre-filter checks are per-pass: each normalized variant gets its
	// own keyword check because normalization reveals new keywords
	// (e.g., leetspeak "1gnore" → "ignore" after normalization).
	// Defensive anti-solicitation matches are dropped per-pass (not after the
	// cascade) so an all-defensive early pass cannot mask an encoded
	// solicitation that only a later pass catches. See scanCoreResponse.
	var matches []ResponseMatch
	matches = withResponseSpans(filterDefensiveCredentialSolicitationMatches(content, s.matchResponsePatternsPreFiltered(content)), ViewForMatching)

	// Secondary: replace invisible chars with spaces, then normalize. Catches
	// word-boundary collapse where the attacker uses ZW instead of space:
	// "ignore\u200ball" → ForMatching drops ZW → "ignoreall" (bypass).
	// Replacing with space first → "ignore all" → regex `ignore\s+all` matches.
	if len(matches) == 0 {
		spaced := normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(original))
		if spaced != content {
			matches = withResponseSpans(filterDefensiveCredentialSolicitationMatches(spaced, s.matchResponsePatternsPreFiltered(spaced)), ViewInvisibleSpaced)
			if len(matches) > 0 {
				matchContent = spaced
				content = spaced // use spaced version for strip action
			}
		}
	}

	// Tertiary: leetspeak normalization. Pre-filter runs on the LEETED
	// content, catching keywords that emerge after digit-to-letter conversion.
	if len(matches) == 0 {
		leeted := normalize.Leetspeak(content)
		if leeted != content {
			matches = withResponseSpans(filterDefensiveCredentialSolicitationMatches(leeted, s.matchResponsePatternsPreFiltered(leeted)), ViewLeetspeak)
			if len(matches) > 0 {
				matchContent = leeted
			}
		}
	}

	// Quaternary: optional-whitespace matching on ZW-stripped text. Catches the
	// combined attack where ZW chars split keywords AND replace word separators:
	// "i\u200bgnore\u200ball\u200bprevious" -> strip ZW -> "ignoreallprevious"
	// Standard \s+ patterns fail on zero whitespace; \s* variants match.
	if len(matches) == 0 && len(s.responseOptSpacePatterns) > 0 {
		matches = withResponseSpans(filterDefensiveCredentialSolicitationMatches(content, matchPatternsPreFiltered(s.responseOptSpacePreFilter, s.responseOptSpacePatterns, content)), ViewForMatching)
		if len(matches) > 0 {
			matchContent = content
		}
	}

	// Quinary: vowel-folded matching. Catches confusable-vowel attacks where
	// one character (e.g., ø→o) replaces multiple different vowels, producing
	// near-miss words like "instroctions" that don't match "instructions".
	// Folding all vowels to 'a' in both content and patterns makes them match.
	if len(matches) == 0 && len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(content)
		if folded != content {
			matches = withResponseSpans(filterDefensiveCredentialSolicitationMatches(folded, matchPatternsPreFiltered(s.responseVowelFoldPreFilter, s.responseVowelFoldPatterns, folded)), ViewVowelFold)
			if len(matches) > 0 {
				matchContent = folded
			}
		}
	}

	// Senary: base64/hex decode pass. Only runs when content contains a
	// contiguous run of base64/hex alphabet characters long enough to be
	// a meaningful encoded payload. Skips expensive decode attempts on
	// normal text content.
	if len(matches) == 0 && hasEncodedRun(content) {
		decodedSet := s.matchDecodedResponse(content)
		matches = decodedSet.matches
		if len(matches) > 0 {
			matchContent = decodedSet.content
		}
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
	matches = filterEducationalQuotedResponseMatches(matchContent, matches)
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

func filterDefensiveCredentialSolicitationMatches(content string, matches []ResponseMatch) []ResponseMatch {
	if len(matches) == 0 {
		return matches
	}

	filtered := matches[:0]
	for _, match := range matches {
		if isSecretAskPattern(match.PatternName) && isDefensiveCredentialSolicitation(content, match) {
			continue
		}
		filtered = append(filtered, match)
	}
	return filtered
}

func isSecretAskPattern(name string) bool {
	return name == "Credential "+"Solicitation"
}

// foldedContains / foldedHasSuffix match a literal in both its raw form and its
// vowel-folded form. The defensive-context check runs on whichever normalization
// pass surfaced the match, and the vowel-fold pass turns keywords like "never"
// into "navar"; matching the folded literal too keeps defensive detection
// invariant across passes without re-indexing folded content positions.
func foldedContains(haystack, needle string) bool {
	return strings.Contains(haystack, needle) || strings.Contains(haystack, normalize.FoldVowels(needle))
}

func foldedHasSuffix(s, suffix string) bool {
	return strings.HasSuffix(s, suffix) || strings.HasSuffix(s, normalize.FoldVowels(suffix))
}

func isDefensiveCredentialSolicitation(content string, match ResponseMatch) bool {
	start := match.Position
	if start < 0 || start > len(content) {
		return false
	}
	end := start + match.matchLength
	if match.matchLength == 0 {
		end = start + len(match.MatchText)
	}
	if end < start || end > len(content) {
		end = len(content)
	}

	lower := strings.ToLower(content)
	if hasDefensiveSolicitationPivot(lower[start:end]) {
		return false
	}
	if hasSolicitationContinuation(lower[end:]) {
		return false
	}
	sentenceStart := strings.LastIndexAny(lower[:start], ".!?\n\r;:") + 1
	prefix := strings.TrimSpace(lower[sentenceStart:start])
	if prefix == "" {
		return false
	}

	for _, phrase := range []string{
		"do not",
		"don't",
		"never",
		"must not",
		"must never",
		"should not",
		"should never",
		"will not",
		"will never",
		"won't",
		"cannot",
		"can't",
		"never ask you to",
		"not ask you to",
		"do not ask you to",
		"don't ask you to",
		"won't ask you to",
	} {
		if foldedHasSuffix(prefix, phrase) {
			return true
		}
	}
	return false
}

func hasDefensiveSolicitationPivot(matchText string) bool {
	for _, pivot := range []string{
		"; instead",
		", instead",
		" instead ",
		"; rather",
		", rather",
		" rather ",
		"; actually",
		", actually",
		" actually ",
		"; but ",
		", but ",
		" but ",
		"; however",
		", however",
		" however ",
	} {
		if foldedContains(matchText, pivot) {
			return true
		}
	}
	return false
}

func hasSolicitationContinuation(suffix string) bool {
	sentenceEnd := strings.IndexAny(suffix, ".!?\n\r")
	if sentenceEnd >= 0 {
		suffix = suffix[:sentenceEnd]
	}
	for _, phrase := range []string{
		", send it ",
		"; send it ",
		", send them ",
		"; send them ",
		", provide it ",
		"; provide it ",
		", provide them ",
		"; provide them ",
		", paste it ",
		"; paste it ",
		", paste them ",
		"; paste them ",
		", email it ",
		"; email it ",
		", email them ",
		"; email them ",
		", forward it ",
		"; forward it ",
		", forward them ",
		"; forward them ",
	} {
		if foldedContains(suffix, phrase) {
			return true
		}
	}
	return false
}

func filterEducationalQuotedResponseMatches(content string, matches []ResponseMatch) []ResponseMatch {
	if len(matches) == 0 || !hasEducationalPromptInjectionContext(content) {
		return matches
	}

	filtered := matches[:0]
	for _, match := range matches {
		if isSystemPromptDisclosureMatch(match) {
			filtered = append(filtered, match)
			continue
		}
		if isQuotedResponseExampleMatch(content, match) {
			continue
		}
		filtered = append(filtered, match)
	}
	return filtered
}

// isSystemPromptDisclosureMatch identifies matches from the immutable
// "System Prompt Disclosure" core pattern, which targets system prompt,
// tool definition, and developer instruction disclosure directives. The
// pattern itself enforces the verb + target structure via its regex; the
// name check alone is sufficient. Inspecting match.MatchText would be
// unsafe - matchPatternsPreFiltered truncates MatchText at 100 runes and
// an attacker can fill the regex's 80-char gap to push the target past
// the truncation cap.
func isSystemPromptDisclosureMatch(match ResponseMatch) bool {
	return match.PatternName == "System Prompt Disclosure"
}

func hasEducationalPromptInjectionContext(content string) bool {
	lower := strings.ToLower(normalize.ForMatching(content))
	if !strings.Contains(lower, "prompt injection") {
		return false
	}

	metaContext := strings.Contains(lower, "common injection pattern") ||
		strings.Contains(lower, "common attack pattern") ||
		strings.Contains(lower, "attack pattern is") ||
		strings.Contains(lower, "include phrases like")
	defensiveContext := strings.Contains(lower, "defense") ||
		strings.Contains(lower, "defenders") ||
		strings.Contains(lower, "input validation") ||
		strings.Contains(lower, "scan for these patterns")
	return metaContext && defensiveContext
}

func isQuotedResponseExampleMatch(content string, match ResponseMatch) bool {
	start := match.Position
	matchLength := match.matchLength
	if matchLength == 0 {
		matchLength = len(match.MatchText)
	}
	end := start + matchLength
	if start < 0 || end > len(content) || start >= end {
		return false
	}
	if !strings.HasPrefix(content[start:], match.MatchText) {
		return false
	}
	return isASCIIQuotedSpan(content, start, end, '\'') || isASCIIQuotedSpan(content, start, end, '"')
}

func isASCIIQuotedSpan(content string, start, end int, quote byte) bool {
	left := strings.LastIndexByte(content[:start], quote)
	if left < 0 {
		return false
	}
	lineStart := strings.LastIndexAny(content[:left], "\r\n") + 1
	if strings.Count(content[lineStart:left], string(rune(quote)))%2 != 0 {
		return false
	}
	nextAfterLeft := strings.IndexByte(content[left+1:], quote)
	if nextAfterLeft < 0 {
		return false
	}
	closing := left + 1 + nextAfterLeft
	if closing < end {
		return false
	}
	return !strings.ContainsAny(content[left+1:closing], "\r\n")
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
				matchLength:   loc[1] - loc[0],
			})
		}
	}
	return matches
}

func withResponseSpans(matches []ResponseMatch, viewLabel string) []ResponseMatch {
	for i := range matches {
		end := matches[i].Position + matches[i].matchLength
		matches[i].span = newMatchSpan(
			matches[i].Position,
			end,
			viewLabel,
			matches[i].PatternName,
			matches[i].Bundle,
			matches[i].BundleVersion,
		)
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
				matchLength:   loc[1] - loc[0],
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
func (s *Scanner) matchDecodedResponse(content string) responseMatchSet {
	return s.matchDecodedResponseRecursive(content, 0)
}

// matchDecodedResponseRecursive is the recursive implementation of matchDecodedResponse.
func (s *Scanner) matchDecodedResponseRecursive(content string, depth int) responseMatchSet {
	if depth >= responseDecodeMaxDepth {
		return responseMatchSet{}
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
			if decodedSet := s.matchDecodedNormalized(d, ViewBase64Decoded); len(decodedSet.matches) > 0 {
				return decodedSet
			}
			// Always recurse on successful decode. The depth limit is the
			// safety bound; gating on hasEncodedRun lets attackers bypass
			// by splitting or punctuating the inner encoded layer.
			if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
				return decodedSet
			}
		}
	}
	if decoded, err := hex.DecodeString(stripped); err == nil && len(decoded) > 0 {
		d := string(decoded)
		if decodedSet := s.matchDecodedNormalized(d, ViewHexDecoded); len(decodedSet.matches) > 0 {
			return decodedSet
		}
		if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
			return decodedSet
		}
	}

	// Strategy 2: segment-level decode with recursion.
	if decodedSet := s.matchDecodedSegmentsRecursive(content, depth); len(decodedSet.matches) > 0 {
		return decodedSet
	}

	return responseMatchSet{}
}

// matchDecodedSegmentsRecursive extracts contiguous base64-alphabet runs from
// content, decodes each individually, and checks for injection patterns.
// Recurses on decoded segments to catch multi-layer encoding.
func (s *Scanner) matchDecodedSegmentsRecursive(content string, depth int) responseMatchSet {
	if depth >= responseDecodeMaxDepth {
		return responseMatchSet{}
	}
	segments := extractEncodedRuns(content, minSegmentDecodeLen)
	for _, seg := range segments {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding,
		} {
			if decoded, err := enc.DecodeString(seg); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
				d := string(decoded)
				if decodedSet := s.matchDecodedNormalized(d, ViewBase64Decoded); len(decodedSet.matches) > 0 {
					return decodedSet
				}
				if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
					return decodedSet
				}
			}
		}
		if decoded, err := hex.DecodeString(seg); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
			d := string(decoded)
			if decodedSet := s.matchDecodedNormalized(d, ViewHexDecoded); len(decodedSet.matches) > 0 {
				return decodedSet
			}
			if decodedSet := s.matchDecodedResponseRecursive(d, depth+1); len(decodedSet.matches) > 0 {
				return decodedSet
			}
		}
	}
	return responseMatchSet{}
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
func (s *Scanner) matchDecodedNormalized(decoded, decodedViewLabel string) responseMatchSet {
	normalized := normalize.ForMatching(decoded)
	if matches := filterDefensiveCredentialSolicitationMatches(normalized, matchPatternsPreFiltered(s.responsePreFilter, s.responsePatterns, normalized)); len(matches) > 0 {
		return responseMatchSet{matches: withResponseSpans(matches, decodedViewLabel), content: normalized}
	}
	if len(s.responseOptSpacePatterns) > 0 {
		if matches := filterDefensiveCredentialSolicitationMatches(normalized, matchPatternsPreFiltered(s.responseOptSpacePreFilter, s.responseOptSpacePatterns, normalized)); len(matches) > 0 {
			return responseMatchSet{matches: withResponseSpans(matches, decodedViewLabel), content: normalized}
		}
	}
	if len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(normalized)
		if folded != normalized {
			if matches := filterDefensiveCredentialSolicitationMatches(folded, matchPatternsPreFiltered(s.responseVowelFoldPreFilter, s.responseVowelFoldPatterns, folded)); len(matches) > 0 {
				return responseMatchSet{matches: withResponseSpans(matches, vowelFoldViewLabel(decodedViewLabel)), content: folded}
			}
		}
	}
	return responseMatchSet{}
}

// ResponseScanningEnabled returns whether response scanning is active.
// Always returns true when core response patterns exist, even if the
// user disabled response_scanning.enabled - core is the safety floor.
func (s *Scanner) ResponseScanningEnabled() bool {
	if s.core != nil && len(s.core.responsePatterns) > 0 {
		return true
	}
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
// When main response scanning is disabled but core patterns are active,
// defaults to "block" - core findings are non-negotiable.
func (s *Scanner) ResponseAction() string {
	if s.responseAction == "" && s.core != nil && len(s.core.responsePatterns) > 0 {
		return config.ActionBlock
	}
	return s.responseAction
}
