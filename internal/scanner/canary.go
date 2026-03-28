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

// scanCanaryText scans text for configured canary tokens using the same
// normalization + decode strategy as text DLP matching.
func (s *Scanner) scanCanaryText(text string) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}

	cleaned := normalize.ForDLP(text)
	if cleaned == "" {
		return nil
	}

	var matches []TextDLPMatch
	matches = append(matches, s.matchCanaryTokens(cleaned, "", false)...)

	if decoded := IterativeDecode(cleaned); decoded != cleaned {
		matches = append(matches, s.matchCanaryTokens(decoded, "url", false)...)
	}
	if strings.Contains(cleaned, ".") {
		dotless := strings.ReplaceAll(cleaned, ".", "")
		if dotless != cleaned {
			matches = append(matches, s.matchCanaryTokens(dotless, "subdomain", false)...)
		}
	}
	if collapsed := canonicalizeCanaryText(cleaned); collapsed != "" && collapsed != cleaned {
		matches = append(matches, s.matchCanaryTokens(collapsed, "split", true)...)
	}

	for _, d := range decodeEncodings(cleaned) {
		matches = append(matches, s.matchCanaryTokens(d.text, d.encoding, false)...)
	}

	segments := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == '/' || r == '?' || r == '&' || r == '=' || r == ' ' || r == '\n' || r == '\t'
	})
	for _, seg := range segments {
		if len(seg) < 8 {
			continue
		}
		for _, d := range decodeEncodings(seg) {
			matches = append(matches, s.matchCanaryTokens(d.text, d.encoding, false)...)
		}
		if collapsed := canonicalizeCanaryText(seg); collapsed != "" && collapsed != seg {
			matches = append(matches, s.matchCanaryTokens(collapsed, "split", true)...)
		}
	}

	return deduplicateMatches(matches)
}

// matchCanaryTokens checks pre-normalized text for canary token matches.
// The caller (scanCanaryText) is responsible for ForDLP normalization —
// this function only lowercases and optionally canonicalizes.
func (s *Scanner) matchCanaryTokens(text, encoding string, canonical bool) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}

	haystack := strings.ToLower(text)
	if canonical {
		haystack = strings.ToLower(canonicalizeCanaryText(haystack))
		if haystack == "" {
			return nil
		}
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
		if strings.Contains(haystack, needle) {
			matches = append(matches, TextDLPMatch{
				PatternName: "Canary Token (" + token.name + ")",
				Severity:    "critical",
				Encoded:     encoding,
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
