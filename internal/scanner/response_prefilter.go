// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// responsePreFilter provides fast keyword-based pre-screening for response
// pattern matching. Before running expensive regex against the full content,
// it checks whether any literal keyword anchor from the pattern set appears
// in the text. If no keywords are found, regex matching is skipped entirely.
//
// This sits ahead of passes 1+2 (the primary bottleneck) and the opt-space
// pass. Content-based, not position-based: no blind spots.
//
// Conservative: false positives (running regex unnecessarily) are fine.
// False negatives (skipping regex when keywords exist) are not.
type responsePreFilter struct {
	// keywords maps lowercased keyword anchors to the pattern indices
	// in the parent Scanner.responsePatterns slice that share that keyword.
	keywords map[string][]int

	// alwaysRun holds indices of patterns with no extractable keyword.
	// These are always evaluated regardless of content. Typically cheap
	// patterns like the Pliny divider (short literal, fast regex failure).
	alwaysRun []int
}

// newResponsePreFilter builds a pre-filter from response patterns.
// Extracts keyword anchors from each pattern, handling literal prefixes
// and leading alternation groups.
func newResponsePreFilter(patterns []*compiledPattern) *responsePreFilter {
	pf := &responsePreFilter{
		keywords: make(map[string][]int),
	}

	for i, p := range patterns {
		keywords := extractResponseKeywords(p.re.String())
		if len(keywords) == 0 {
			pf.alwaysRun = append(pf.alwaysRun, i)
			continue
		}
		for _, kw := range keywords {
			lower := strings.ToLower(kw)
			pf.keywords[lower] = append(pf.keywords[lower], i)
		}
	}

	return pf
}

// patternsToCheck returns the combined set of pattern indices that should
// be evaluated: keyword-matched candidates plus alwaysRun patterns.
// Returns nil when no patterns need to run.
func (pf *responsePreFilter) patternsToCheck(content string) []int {
	lower := strings.ToLower(content)
	var hits []int
	seen := make(map[int]bool)
	for kw, indices := range pf.keywords {
		if strings.Contains(lower, kw) {
			for _, idx := range indices {
				if !seen[idx] {
					seen[idx] = true
					hits = append(hits, idx)
				}
			}
		}
	}
	for _, idx := range pf.alwaysRun {
		if !seen[idx] {
			seen[idx] = true
			hits = append(hits, idx)
		}
	}
	return hits
}

// extractResponseKeywords extracts keyword anchors from a response pattern
// regex. Handles two cases:
//  1. Literal prefix: "(?i)from\s+now\s+on" -> ["from"]
//  2. Leading alternation: "(?i)(ignore|disregard|forget)" -> ["ignore", "disregard", "forget"]
//
// Returns nil if no reliable keywords can be extracted.
func extractResponseKeywords(regex string) []string {
	s := regex

	// Strip ALL leading inline flag groups: (?i), (?im), (?-i), etc.
	// These are non-capturing groups that only set flags, not match content.
	for strings.HasPrefix(s, "(?") {
		closeIdx := strings.Index(s, ")")
		if closeIdx < 0 {
			return nil
		}
		flagContent := s[2:closeIdx]
		isFlags := true
		for _, c := range flagContent {
			if (c < 'a' || c > 'z') && c != '-' {
				isFlags = false
				break
			}
		}
		if !isFlags {
			break
		}
		s = s[closeIdx+1:]
	}

	// Skip leading anchors and optional whitespace that don't contribute
	// keyword content: ^, \s*, \s+, \b
	for {
		if strings.HasPrefix(s, "^") {
			s = s[1:]
		} else if strings.HasPrefix(s, "\\s*") || strings.HasPrefix(s, "\\s+") || strings.HasPrefix(s, "\\b") {
			s = s[3:]
		} else {
			break
		}
	}

	// Leading alternation group: (ignore|disregard|forget)
	// ALL branches must produce a keyword. If any branch has no extractable
	// keyword, the pattern goes to alwaysRun (conservative: never skip a
	// pattern that could match through a keywordless branch).
	if strings.HasPrefix(s, "(") {
		closeIdx := findMatchingParen(s)
		if closeIdx > 0 && strings.Contains(s[1:closeIdx], "|") {
			branches := splitTopLevelAlternation(s[1:closeIdx])
			var keywords []string
			for _, b := range branches {
				b = strings.TrimPrefix(b, "?:")
				b = strings.TrimPrefix(b, "?-i:")
				lit := extractLiteralRun(b)
				if len(lit) >= 3 {
					keywords = append(keywords, lit)
				} else {
					// Branch without keyword → can't gate this pattern.
					return nil
				}
			}
			if len(keywords) > 0 {
				return keywords
			}
			return nil
		}
	}

	// Literal prefix
	prefix := extractLiteralPrefix(regex)
	if len(prefix) >= 3 {
		return []string{prefix}
	}
	return nil
}

// findMatchingParen finds the index of the closing paren matching the
// opening paren at s[0]. Handles nested groups.
func findMatchingParen(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		case '\\':
			i++ // skip escaped character
		}
	}
	return -1
}

// splitTopLevelAlternation splits on | that is not inside nested parens.
func splitTopLevelAlternation(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		case '\\':
			i++ // skip escaped character
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// extractLiteralRun extracts leading literal characters from a string,
// stopping at the first regex metacharacter. Handles nested flag groups
// like (?-i:\bDAN\b) by stripping the group syntax and anchors first.
func extractLiteralRun(s string) string {
	// Strip leading flag groups: (?-i:, (?:, etc.
	for strings.HasPrefix(s, "(?") {
		colon := strings.Index(s, ":")
		closeIdx := strings.Index(s, ")")
		if colon > 0 && (closeIdx < 0 || colon < closeIdx) {
			// Flag group (?-i: or (?: — skip past the colon
			s = s[colon+1:]
			// Also strip trailing ) if it's the last char
			s = strings.TrimSuffix(s, ")")
		} else {
			break
		}
	}
	// Strip word boundary anchors
	for strings.HasPrefix(s, "\\b") {
		s = s[2:]
	}
	s = strings.TrimSuffix(s, "\\b)")
	s = strings.TrimSuffix(s, "\\b")
	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 < len(s) {
				next := s[i+1]
				switch next {
				case '.', '\\', '-', '_', '\'', '[', ']', '(', ')', '{', '}', '+', '*', '?', '^', '$', '|', '/', '!', ':':
					// Escaped literal character — treat as keyword content.
					result = append(result, next)
					i++
					continue
				default:
					// \s, \d, \b, \w, etc. are metacharacters — stop.
					return string(result)
				}
			}
			return string(result)
		}
		switch c {
		case '[', '(', '.', '*', '+', '?', '{', '}', '^', '$', '|':
			return string(result)
		}
		result = append(result, c)
	}
	return string(result)
}

// hasEncodedRun checks whether content contains a contiguous run of
// base64 or hex alphabet characters long enough to be a meaningful
// encoded payload. Used to skip expensive decode attempts on content
// that is clearly not encoded. Set low (8) to catch short encoded
// payloads like base64("system:") = "c3lzdGVtOg==" (12 chars).
const minEncodedRunLen = 8

func hasEncodedRun(content string) bool {
	run := 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			c == '-' || c == '_' || c == '=' {
			run++
			if run >= minEncodedRunLen {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}
