package scanner

import (
	"fmt"

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
	PatternName string `json:"pattern_name"`
	MatchText   string `json:"match_text"` // truncated to 100 chars
	Position    int    `json:"position"`
}

// InvisibleRanges re-exports normalize.InvisibleRanges for backward compatibility.
// Callers should migrate to normalize.InvisibleRanges directly.
var InvisibleRanges = normalize.InvisibleRanges

// Delegate wrappers — these preserve the old function signatures so existing
// tests and callers continue to compile. They will be removed once all callers
// migrate to the normalize package directly.

func normalizeWhitespace(s string) string       { return normalize.NormalizeWhitespace(s) }
func stripZeroWidth(s string) string            { return normalize.StripZeroWidth(s) }
func replaceInvisibleWithSpace(s string) string { return normalize.ReplaceInvisibleWithSpace(s) }
func stripControlChars(s string) string         { return normalize.StripControlChars(s) }
func ConfusableToASCII(s string) string         { return normalize.ConfusableToASCII(s) }
func StripCombiningMarks(s string) string       { return normalize.StripCombiningMarks(s) }
func NormalizeLeetspeak(s string) string        { return normalize.NormalizeLeetspeak(s) }
func NormalizeForMatching(s string) string      { return normalize.ForMatching(s) }
func NormalizeForPolicy(s string) string        { return normalize.ForPolicy(s) }

// ScanResponse checks fetched content for prompt injection patterns.
// If scanning is disabled, returns Clean=true immediately.
// Zero-width Unicode characters are stripped before scanning to prevent
// evasion via invisible character insertion.
// For "strip" action, replaces matches with [REDACTED: PatternName].
func (s *Scanner) ScanResponse(content string) ResponseScanResult {
	if !s.responseEnabled {
		return ResponseScanResult{Clean: true}
	}

	// Save original for secondary pass before normalization.
	original := content

	// Primary: drop invisible chars, then normalize. Catches mid-word ZW insertion
	// where the attacker splits a keyword: "igno\u200bre" → "ignore" (detected).
	content = normalize.ForMatching(content)
	matches := s.matchResponsePatterns(content)

	// Secondary: replace invisible chars with spaces, then normalize. Catches
	// word-boundary collapse where the attacker uses ZW instead of space:
	// "ignore\u200ball" → ForMatching drops ZW → "ignoreall" (bypass).
	// Replacing with space first → "ignore all" → regex `ignore\s+all` matches.
	if len(matches) == 0 {
		spaced := normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(original))
		if spaced != content {
			matches = s.matchResponsePatterns(spaced)
			if len(matches) > 0 {
				content = spaced // use spaced version for strip action
			}
		}
	}

	// Tertiary: leetspeak normalization. Only fires when both prior passes found
	// nothing, avoiding FPs on digit-heavy text (e.g., "API v3.0").
	if len(matches) == 0 {
		leeted := normalize.NormalizeLeetspeak(content)
		if leeted != content {
			matches = s.matchResponsePatterns(leeted)
		}
	}

	if len(matches) == 0 {
		return ResponseScanResult{Clean: true}
	}

	result := ResponseScanResult{
		Clean:   false,
		Matches: matches,
	}

	if s.responseAction == "strip" || s.responseAction == "ask" { //nolint:goconst // action string used as-is from config
		transformed := content
		for _, p := range s.responsePatterns {
			replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
			transformed = p.re.ReplaceAllString(transformed, replacement)
		}
		result.TransformedContent = transformed
	}

	return result
}

// matchResponsePatterns runs all response patterns against content and returns matches.
func (s *Scanner) matchResponsePatterns(content string) []ResponseMatch {
	var matches []ResponseMatch
	for _, p := range s.responsePatterns {
		locs := p.re.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matchText := content[loc[0]:loc[1]]
			if runes := []rune(matchText); len(runes) > 100 {
				matchText = string(runes[:100])
			}
			matches = append(matches, ResponseMatch{
				PatternName: p.name,
				MatchText:   matchText,
				Position:    loc[0],
			})
		}
	}
	return matches
}

// ResponseScanningEnabled returns whether response scanning is active.
func (s *Scanner) ResponseScanningEnabled() bool {
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
func (s *Scanner) ResponseAction() string {
	return s.responseAction
}
