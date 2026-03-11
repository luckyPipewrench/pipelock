// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sort"
	"strings"
)

// dlpPreFilter provides fast prefix-based pre-screening for DLP patterns.
// Before running expensive regex evaluations, it checks whether any known
// literal prefix appears in the input text. If no prefix is found, all regex
// checks can be skipped entirely. This is the common case for clean traffic.
//
// The pre-filter maps each literal prefix to the indices of DLP patterns that
// could match. When a prefix hits, only those specific patterns are tested
// instead of the full set.
type dlpPreFilter struct {
	// prefixes maps each lowercased literal prefix to the pattern indices
	// in the parent Scanner.dlpPatterns slice that share that prefix.
	prefixes map[string][]int

	// alwaysRun holds pattern indices that have no extractable literal prefix
	// (e.g., SSN with \d digits, generic credential patterns with alternations).
	// These patterns must always be evaluated regardless of pre-filter results.
	alwaysRun []int
}

// newDLPPreFilter builds a pre-filter from compiled DLP patterns.
// It extracts the longest literal prefix from each pattern's regex source.
func newDLPPreFilter(patterns []*compiledPattern) *dlpPreFilter {
	pf := &dlpPreFilter{
		prefixes: make(map[string][]int),
	}

	for i, p := range patterns {
		prefix := extractLiteralPrefix(p.re.String())
		if prefix == "" {
			pf.alwaysRun = append(pf.alwaysRun, i)
			continue
		}
		// Store lowercased: the input will also be lowercased before checking.
		lower := strings.ToLower(prefix)
		pf.prefixes[lower] = append(pf.prefixes[lower], i)
	}

	return pf
}

// candidates returns the pattern indices that might match the given text.
// The text should already be normalized (normalize.ForDLP) before calling.
// Returns nil if no candidates are found (callers should still run alwaysRun).
func (pf *dlpPreFilter) candidates(text string) []int {
	lower := strings.ToLower(text)
	var hits []int
	for prefix, indices := range pf.prefixes {
		if strings.Contains(lower, prefix) {
			hits = append(hits, indices...)
		}
	}
	return hits
}

// patternsToCheck returns the combined set of pattern indices that should be
// evaluated against the given text: prefix-matched candidates plus alwaysRun.
// Returns nil only when both candidates and alwaysRun are empty.
// Indices are returned in ascending order for deterministic match reporting.
func (pf *dlpPreFilter) patternsToCheck(text string) []int {
	hits := pf.candidates(text)
	if len(hits) == 0 {
		if len(pf.alwaysRun) == 0 {
			return nil
		}
		return pf.alwaysRun
	}
	result := append(hits, pf.alwaysRun...)
	sort.Ints(result)
	return result
}

// extractLiteralPrefix extracts the longest leading literal string from a regex.
// It stops at the first metacharacter that could match variable content.
// The (?i) flag (forced by scanner compilation) is stripped first.
//
// Examples:
//
//	"(?i)sk-ant-[a-zA-Z0-9]{10,}"  → "sk-ant-"
//	"(?i)(AKIA|A3T|AGPA)..."       → ""  (alternation at start = no single prefix)
//	"(?i)github_pat_[a-zA-Z0-9]+"  → "github_pat_"
//	"(?i)\\bpassword=.+"           → ""  (\b is a metachar)
//	"(?i)-----BEGIN\\s+..."        → "-----begin"  (stops before \s)
//	"(?i)[sr]k_(live|test)_..."    → ""  (char class at start)
func extractLiteralPrefix(regex string) string {
	// Strip (?i) flag prefix added by scanner compilation.
	s := strings.TrimPrefix(regex, "(?i)")

	// Strip any remaining inline flags like (?:...) at the very start.
	// Non-capturing groups with a single literal alternative are handled
	// by walking into the group.
	if strings.HasPrefix(s, "(?:") {
		// If the group contains alternation (|), there's no single prefix.
		closeIdx := strings.Index(s, ")")
		if closeIdx < 0 {
			return ""
		}
		groupContent := s[3:closeIdx]
		if strings.Contains(groupContent, "|") {
			return ""
		}
		// If the group is quantified (?, *, +, {n}), the prefix is optional
		// and cannot be used as a required match gate.
		if closeIdx+1 < len(s) {
			switch s[closeIdx+1] {
			case '?', '*', '+', '{':
				return ""
			}
		}
		// Single-alternative non-capturing group: treat content as literal prefix
		// followed by rest of regex.
		s = groupContent + s[closeIdx+1:]
	}

	var prefix []byte
	i := 0
	for i < len(s) {
		c := s[i]

		// Backslash escapes: some produce literals, some are metacharacters.
		if c == '\\' {
			if i+1 >= len(s) {
				break
			}
			next := s[i+1]
			switch next {
			case '.', '\\', '-', '_', '[', ']', '(', ')', '{', '}', '+', '*', '?', '^', '$', '|', '/':
				// Escaped literal character.
				prefix = append(prefix, next)
				i += 2
				continue
			default:
				// \s, \d, \b, \w, etc. are variable-width metacharacters.
				break
			}
			break
		}

		// Regex metacharacters that end the literal prefix.
		switch c {
		case '[', '(', '.', '*', '+', '?', '{', '}', '^', '$', '|':
			// Hit a metacharacter; stop extracting.
			return strings.ToLower(string(prefix))
		}

		prefix = append(prefix, c)
		i++
	}

	return strings.ToLower(string(prefix))
}
