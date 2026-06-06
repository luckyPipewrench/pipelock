// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// compiledCanaryToken stores normalized canary values for fast matching.
type compiledCanaryToken struct {
	name            string
	normalizedLower string
	canonicalLower  string
}

func compileCanaryTokens(cfg config.CanaryTokens) []compiledCanaryToken {
	if !cfg.Enabled || len(cfg.Tokens) == 0 {
		return nil
	}
	out := make([]compiledCanaryToken, 0, len(cfg.Tokens))
	for _, token := range cfg.Tokens {
		normalized := strings.ToLower(normalize.ForDLP(token.Value))
		if normalized == "" {
			continue
		}
		canonical := strings.ToLower(canonicalizeCanaryText(normalized))
		out = append(out, compiledCanaryToken{
			name:            token.Name,
			normalizedLower: normalized,
			canonicalLower:  canonical,
		})
	}
	return out
}

// scanCanaryText scans text for configured canary tokens. It owns DLP
// normalization, then checks URL-decoded, encoded, and separator-canonicalized
// views. Span labels name the lowercased/canonicalized view that was indexed.
func (s *Scanner) scanCanaryText(text string) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}

	cleaned := normalize.ForDLP(text)
	if cleaned == "" {
		return nil
	}

	var matches []TextDLPMatch
	matches = append(matches, s.matchCanaryTokens(cleaned, "", false, ViewDLPNormalized)...)

	if decoded := IterativeDecode(cleaned); decoded != cleaned {
		matches = append(matches, s.matchCanaryTokens(decoded, "url", false, spanViewLabel("url_decoded", ViewDLPNormalized))...)
	}
	if strings.Contains(cleaned, ".") {
		dotless := strings.ReplaceAll(cleaned, ".", "")
		if dotless != cleaned {
			matches = append(matches, s.matchCanaryTokens(dotless, "subdomain", false, spanViewLabel("dotless_hostname", ViewDLPNormalized))...)
		}
	}
	if collapsed := canonicalizeCanaryText(cleaned); collapsed != "" && collapsed != cleaned {
		matches = append(matches, s.matchCanaryTokens(cleaned, "split", true, ViewDLPNormalized)...)
	}

	for _, d := range decodeEncodings(cleaned) {
		matches = append(matches, s.matchCanaryTokens(d.text, d.encoding, false, spanViewLabel(d.encoding+"_decoded", ViewDLPNormalized))...)
	}

	segments := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == '/' || r == '?' || r == '&' || r == '=' || r == ' ' || r == '\n' || r == '\t'
	})
	for _, seg := range segments {
		if len(seg) < 8 {
			continue
		}
		for _, d := range decodeEncodings(seg) {
			matches = append(matches, s.matchCanaryTokens(d.text, d.encoding, false, spanViewLabel(d.encoding+"_decoded", "dlp_segment"))...)
		}
		if collapsed := canonicalizeCanaryText(seg); collapsed != "" && collapsed != seg {
			matches = append(matches, s.matchCanaryTokens(seg, "split", true, "dlp_segment")...)
		}
	}

	return deduplicateMatches(matches)
}

// matchCanaryTokens checks a pre-built view for canary token matches. It always
// indexes a lowercased view and, for split matches, a canonicalized lowercased
// view, so the span label must include those final transforms.
func (s *Scanner) matchCanaryTokens(text, encoding string, canonical bool, inputViewLabel string) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}

	haystack := strings.ToLower(text)
	viewLabel := lowerViewLabel(inputViewLabel)
	if canonical {
		haystack = strings.ToLower(canonicalizeCanaryText(haystack))
		if haystack == "" {
			return nil
		}
		viewLabel = canonicalLowerViewLabel(inputViewLabel)
	}

	var matches []TextDLPMatch
	for _, token := range s.canaryTokens {
		needle := token.normalizedLower
		if canonical {
			needle = token.canonicalLower
		}
		if needle == "" {
			continue
		}
		if start := strings.Index(haystack, needle); start >= 0 {
			end := start + len(needle)
			patternName := "Canary Token (" + token.name + ")"
			matches = append(matches, TextDLPMatch{
				PatternName: patternName,
				Severity:    "critical",
				Encoded:     encoding,
				span:        newMatchSpan(start, end, viewLabel, patternName, "", ""),
			})
		}
	}

	return matches
}

// canonicalizeCanaryText collapses separators commonly used to split tokens
// across URL/path/query boundaries.
func canonicalizeCanaryText(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '/', '\\', '?', '&', '=', ' ', '\t', '\n', '\r',
			':', ';', ',', '-', '_', '@', '%', '+', '#':
			return -1
		}
		return r
	}, s)
}
