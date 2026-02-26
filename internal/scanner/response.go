package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

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
	PatternName string `json:"pattern_name"`
	MatchText   string `json:"match_text"` // truncated to 100 chars
	Position    int    `json:"position"`
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
		leeted := normalize.Leetspeak(content)
		if leeted != content {
			matches = s.matchResponsePatterns(leeted)
		}
	}

	// Quaternary: optional-whitespace matching on ZW-stripped text. Catches the
	// combined attack where ZW chars split keywords AND replace word separators:
	// "i\u200bgnore\u200ball\u200bprevious" -> strip ZW -> "ignoreallprevious"
	// Standard \s+ patterns fail on zero whitespace; \s* variants match.
	if len(matches) == 0 && len(s.responseOptSpacePatterns) > 0 {
		matches = matchPatternsAgainst(s.responseOptSpacePatterns, content)
	}

	// Quinary: vowel-folded matching. Catches confusable-vowel attacks where
	// one character (e.g., ø→o) replaces multiple different vowels, producing
	// near-miss words like "instroctions" that don't match "instructions".
	// Folding all vowels to 'a' in both content and patterns makes them match.
	if len(matches) == 0 && len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(content)
		if folded != content {
			matches = matchPatternsAgainst(s.responseVowelFoldPatterns, folded)
		}
	}

	// Senary: base64/hex decode pass. Catches injection phrases hidden in
	// encoded content (e.g., base64 "ignore all previous instructions" in MCP
	// tool arguments). Parallels ScanTextForDLP's encoding checks.
	if len(matches) == 0 {
		matches = s.matchDecodedResponse(content)
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
				PatternName: p.name,
				MatchText:   matchText,
				Position:    loc[0],
			})
		}
	}
	return matches
}

// matchResponsePatterns runs all response patterns against content and returns matches.
func (s *Scanner) matchResponsePatterns(content string) []ResponseMatch {
	return matchPatternsAgainst(s.responsePatterns, content)
}

// matchDecodedResponse tries base64/hex decoding content and checks the decoded
// result for injection patterns. Catches encoded injection phrases in MCP tool
// arguments (e.g., base64-encoded "ignore all previous instructions").
func (s *Scanner) matchDecodedResponse(content string) []ResponseMatch {
	// Strip whitespace for decode attempts (base64 with embedded newlines).
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
			if matches := s.matchDecodedNormalized(string(decoded)); len(matches) > 0 {
				return matches
			}
		}
	}
	if decoded, err := hex.DecodeString(stripped); err == nil && len(decoded) > 0 {
		if matches := s.matchDecodedNormalized(string(decoded)); len(matches) > 0 {
			return matches
		}
	}
	return nil
}

// matchDecodedNormalized runs all response scanning passes (primary, opt-space,
// vowel-fold) against decoded content. Without this, encoded payloads carrying
// vowel-substituted or zero-width-separated injection would bypass detection.
func (s *Scanner) matchDecodedNormalized(decoded string) []ResponseMatch {
	normalized := normalize.ForMatching(decoded)
	if matches := matchPatternsAgainst(s.responsePatterns, normalized); len(matches) > 0 {
		return matches
	}
	if len(s.responseOptSpacePatterns) > 0 {
		if matches := matchPatternsAgainst(s.responseOptSpacePatterns, normalized); len(matches) > 0 {
			return matches
		}
	}
	if len(s.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(normalized)
		if folded != normalized {
			if matches := matchPatternsAgainst(s.responseVowelFoldPatterns, folded); len(matches) > 0 {
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
