package scanner

import (
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
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

// stripZeroWidth removes Unicode zero-width and invisible characters that could
// be used to evade regex pattern matching (e.g., "ig\u200Bnore" bypassing "ignore").
func stripZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u200B', // zero-width space
			'\u200C', // zero-width non-joiner
			'\u200D', // zero-width joiner
			'\u2060', // word joiner
			'\u2061', // function application
			'\u2062', // invisible times
			'\u2063', // invisible separator
			'\u2064', // invisible plus
			'\u00AD', // soft hyphen
			'\u200E', // left-to-right mark
			'\u200F', // right-to-left mark
			'\uFEFF': // byte order mark / zero-width no-break space
			return -1 // drop
		}
		return r
	}, s)
}

// ScanResponse checks fetched content for prompt injection patterns.
// If scanning is disabled, returns Clean=true immediately.
// Zero-width Unicode characters are stripped before scanning to prevent
// evasion via invisible character insertion.
// For "strip" action, replaces matches with [REDACTED: PatternName].
func (s *Scanner) ScanResponse(content string) ResponseScanResult {
	if !s.responseEnabled {
		return ResponseScanResult{Clean: true}
	}

	// Strip zero-width characters before pattern matching to prevent bypass.
	content = stripZeroWidth(content)
	// NFKC normalization catches Unicode confusables (e.g., Cyrillic 'а' → Latin 'a').
	content = norm.NFKC.String(content)

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

// ResponseScanningEnabled returns whether response scanning is active.
func (s *Scanner) ResponseScanningEnabled() bool {
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
func (s *Scanner) ResponseAction() string {
	return s.responseAction
}
