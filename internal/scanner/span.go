// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"unicode/utf8"
)

// View labels name the exact scanner view that byte offsets index. Labels use
// a transform-stack scheme: "<stage>" or "<stage>:<provenance>". Consumers must
// slice the named view, not the raw input that produced it.
const (
	ViewForMatching     = "for_matching"
	ViewInvisibleSpaced = "for_matching:invisible_spaced"
	ViewLeetspeak       = "leetspeak:for_matching"
	ViewVowelFold       = "vowel_fold:for_matching"
	ViewBase64Decoded   = "for_matching:base64_decoded"
	ViewHexDecoded      = "for_matching:hex_decoded"
	ViewDLPNormalized   = "dlp_normalized"
)

// MatchSpan is retained scanner evidence metadata for a pattern match.
// It carries coordinates and provenance only; it never carries matched bytes.
type MatchSpan struct {
	ByteStart     int
	ByteEnd       int
	ViewLabel     string
	RuleID        string
	Bundle        string
	BundleVersion string
}

func newMatchSpan(start, end int, viewLabel, ruleID, bundle, bundleVersion string) MatchSpan {
	if start < 0 || end < start || viewLabel == "" || ruleID == "" {
		return MatchSpan{}
	}
	return MatchSpan{
		ByteStart:     start,
		ByteEnd:       end,
		ViewLabel:     viewLabel,
		RuleID:        ruleID,
		Bundle:        bundle,
		BundleVersion: bundleVersion,
	}
}

// Valid reports whether the span has coordinates, a view label, and rule ID.
func (s MatchSpan) Valid() bool {
	return s.ByteStart >= 0 && s.ByteEnd >= s.ByteStart && s.ViewLabel != "" && s.RuleID != ""
}

func dlpEncodedViewLabel(encoding string) string {
	return dlpViewLabel(encoding)
}

func dlpViewLabel(provenance string) string {
	return spanViewLabel(ViewDLPNormalized, provenance)
}

func lowerViewLabel(base string) string {
	return spanViewLabel("lowercase", base)
}

func canonicalLowerViewLabel(base string) string {
	return spanViewLabel("canonicalized", lowerViewLabel(base))
}

func vowelFoldViewLabel(base string) string {
	return spanViewLabel("vowel_fold", base)
}

func spanViewLabel(stage string, provenance ...string) string {
	label := stage
	for _, p := range provenance {
		if p == "" {
			continue
		}
		label += ":" + p
	}
	return label
}

func copySpans(spans []MatchSpan) []MatchSpan {
	if len(spans) == 0 {
		return nil
	}
	out := make([]MatchSpan, len(spans))
	copy(out, spans)
	return out
}

func (p *compiledPattern) matchSpan(text string) (start, end int, ok bool) {
	return p.matchSpanInView(text, text)
}

// matchSpanInView returns the credential span rather than a raw-text delimiter
// consumed by an RE2-compatible left-boundary expression. source is the view
// before separators were removed or fields were concatenated. A mid-word
// candidate is suppressed only when that same candidate genuinely existed
// mid-word in source; otherwise the scanner manufactured the adjacency.
func (p *compiledPattern) matchSpanInView(text, source string) (start, end int, ok bool) {
	if p.withoutLeftBoundary == nil {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			if p.validate == nil || p.validate(text[loc[0]:loc[1]]) {
				return loc[0], loc[1], true
			}
		}
		return 0, 0, false
	}
	if source == text {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			bodyLoc := p.withoutLeftBoundary.FindStringIndex(text[loc[0]:loc[1]])
			if bodyLoc == nil {
				continue
			}
			start = loc[0] + bodyLoc[0]
			end = loc[0] + bodyLoc[1]
			if p.validate == nil || p.validate(text[start:end]) {
				return start, end, true
			}
		}
		return 0, 0, false
	}

	invalidSourceCandidates := p.invalidLeadingCandidates(source)
	invalidIndex := 0
	for _, loc := range p.providerCandidateSpans(text) {
		start, end = loc[0], loc[1]
		candidate := strings.ToLower(text[start:end])
		if invalidIndex < len(invalidSourceCandidates) && sameProviderCandidate(candidate, invalidSourceCandidates[invalidIndex]) {
			invalidIndex++
			continue
		}
		if p.validate == nil || p.validate(text[start:end]) {
			return start, end, true
		}
	}
	return 0, 0, false
}

func sameProviderCandidate(candidate, sourceCandidate string) bool {
	// Concatenating another field can extend the provider pattern's greedy
	// suffix. Treat that as the same prose candidate when one string is the
	// other's prefix; unrelated candidates in the same source remain distinct.
	return strings.HasPrefix(candidate, sourceCandidate) || strings.HasPrefix(sourceCandidate, candidate)
}

func (p *compiledPattern) invalidLeadingCandidates(source string) []string {
	var candidates []string
	for _, loc := range p.providerCandidateSpans(source) {
		if p.candidateHasLeftBoundary(source, loc) {
			continue
		}
		candidates = append(candidates, strings.ToLower(source[loc[0]:loc[1]]))
	}
	return candidates
}

// providerCandidateSpans includes nested provider prefixes. The suffix regex is
// greedy, so FindAllStringIndex would let a suppressed prose candidate consume
// a later reconstructed key and mask it from enforcement.
func (p *compiledPattern) providerCandidateSpans(text string) [][2]int {
	return p.canonicalProviderCandidateSpans(text)
}

// canonicalProviderCandidateSpans expands nested prefixes inside each greedy
// provider-key match without rerunning the regex over the remaining text. All
// three canonical bodies share the existing 20-byte opaque-suffix minimum.
func (p *compiledPattern) canonicalProviderCandidateSpans(text string) [][2]int {
	outer := p.withoutLeftBoundary.FindAllStringIndex(text, -1)
	spans := make([][2]int, 0, len(outer))
	minimumLength := len(p.providerKeyPrefix) + 20
	for _, loc := range outer {
		spans = append(spans, [2]int{loc[0], loc[1]})
		lower := strings.ToLower(text[loc[0]:loc[1]])
		for searchFrom := 1; searchFrom < len(lower); {
			relative := strings.Index(lower[searchFrom:], p.providerKeyPrefix)
			if relative < 0 {
				break
			}
			start := searchFrom + relative
			if len(lower)-start >= minimumLength {
				spans = append(spans, [2]int{loc[0] + start, loc[1]})
			}
			searchFrom = start + 1
		}
	}
	return spans
}

func (p *compiledPattern) candidateHasLeftBoundary(source string, candidateLoc [2]int) bool {
	windowStart := candidateLoc[0]
	if windowStart > 0 {
		_, size := utf8.DecodeLastRuneInString(source[:windowStart])
		windowStart -= size
	}
	window := source[windowStart:candidateLoc[1]]
	for _, loc := range p.re.FindAllStringIndex(window, -1) {
		bodyLoc := p.withoutLeftBoundary.FindStringIndex(window[loc[0]:loc[1]])
		if bodyLoc != nil && windowStart+loc[0]+bodyLoc[0] == candidateLoc[0] {
			return true
		}
	}
	return false
}
