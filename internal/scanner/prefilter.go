// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp/syntax"
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
		anchors := extractRequiredLiteralAnchors(p.re.String())
		if len(anchors) == 0 {
			pf.alwaysRun = append(pf.alwaysRun, i)
			continue
		}
		for _, anchor := range anchors {
			// Store lowercased: the input will also be lowercased before checking.
			lower := strings.ToLower(anchor)
			pf.prefixes[lower] = append(pf.prefixes[lower], i)
		}
	}

	return pf
}

const minPreFilterAnchorLength = 3

// extractRequiredLiteralAnchors returns literal alternatives where every match
// of the regex must contain at least one returned string. The full syntax tree
// is always analyzed: a textual prefix is not necessarily required when a bare
// top-level alternation follows it. If any branch cannot prove an anchor, the
// pattern stays in alwaysRun.
func extractRequiredLiteralAnchors(regex string) []string {
	result := extractConservativeLiteralAnchors(regex, true)
	if isGenericCredentialAnchorSet(result) {
		return nil
	}
	return result
}

// extractConservativeLiteralAnchors returns literal alternatives where every
// regex match must contain at least one returned string. It is shared by the
// DLP and response prefilters so both fail closed on the same regex syntax.
// preferLeading lets the DLP hot path choose a longer proven leading set;
// response keywords stay on literal runs and do not absorb whitespace classes.
func extractConservativeLiteralAnchors(regex string, preferLeading bool) []string {
	re, err := syntax.Parse(regex, syntax.Perl)
	if err != nil {
		return nil
	}
	anchors := requiredLiteralAnchors(re)
	if preferLeading {
		if leading, _ := leadingLiteralAnchors(re); betterAnchorSet(leading, anchors) {
			anchors = leading
		}
	}
	if len(anchors) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(anchors))
	result := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		anchor = strings.ToLower(anchor)
		if len(anchor) < minPreFilterAnchorLength || !isASCIIString(anchor) {
			return nil
		}
		if _, ok := seen[anchor]; ok {
			continue
		}
		seen[anchor] = struct{}{}
		result = append(result, anchor)
	}
	sort.Strings(result)
	return result
}

// leadingLiteralAnchors enumerates a bounded set of literal starts. The bool
// reports whether the expression is fully literal and callers may continue
// concatenating the next expression. A false bool can still carry valid
// prefixes collected before the first variable-width construct.
func leadingLiteralAnchors(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return []string{""}, true
		}
		return []string{string(re.Rune)}, true
	case syntax.OpCharClass:
		return smallCharClassAlternatives(re.Rune)
	case syntax.OpCapture:
		if len(re.Sub) != 1 {
			return nil, false
		}
		return leadingLiteralAnchors(re.Sub[0])
	case syntax.OpConcat:
		prefixes := []string{""}
		for _, sub := range re.Sub {
			parts, complete := leadingLiteralAnchors(sub)
			if len(parts) == 0 {
				return allNonEmptyStrings(prefixes), false
			}
			prefixes = combineLiteralAlternatives(prefixes, parts)
			if len(prefixes) == 0 {
				return nil, false
			}
			if !complete {
				return allNonEmptyStrings(prefixes), false
			}
		}
		return allNonEmptyStrings(prefixes), true
	case syntax.OpAlternate:
		var combined []string
		complete := true
		for _, sub := range re.Sub {
			parts, branchComplete := leadingLiteralAnchors(sub)
			if len(parts) == 0 {
				return nil, false
			}
			combined = append(combined, parts...)
			complete = complete && branchComplete
		}
		return combined, complete
	case syntax.OpPlus:
		if len(re.Sub) != 1 {
			return nil, false
		}
		parts, _ := leadingLiteralAnchors(re.Sub[0])
		return parts, false
	case syntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) != 1 {
			return nil, false
		}
		parts, complete := leadingLiteralAnchors(re.Sub[0])
		if len(parts) == 0 {
			return nil, false
		}
		if re.Min != re.Max || !complete {
			return parts, false
		}
		result := []string{""}
		for range re.Min {
			result = combineLiteralAlternatives(result, parts)
			if len(result) == 0 {
				return nil, false
			}
		}
		return result, true
	default:
		return nil, false
	}
}

func smallCharClassAlternatives(ranges []rune) ([]string, bool) {
	const maxAlternatives = 8
	var result []string
	for i := 0; i+1 < len(ranges); i += 2 {
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			if len(result) == maxAlternatives {
				return nil, false
			}
			result = append(result, string(r))
			if r == ranges[i+1] {
				break
			}
		}
	}
	return result, len(result) > 0
}

func combineLiteralAlternatives(left, right []string) []string {
	const maxAlternatives = 64
	if len(left) == 0 || len(right) == 0 || len(left) > maxAlternatives/len(right) {
		return nil
	}
	result := make([]string, 0, len(left)*len(right))
	for _, prefix := range left {
		for _, suffix := range right {
			result = append(result, prefix+suffix)
		}
	}
	return result
}

func allNonEmptyStrings(values []string) []string {
	for _, value := range values {
		if value == "" {
			return nil
		}
	}
	return values
}

func isASCIIString(value string) bool {
	for i := range len(value) {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Generic credential-field words are common in benign URLs. They are safe as
// gates but not selective enough to pay for candidate-slice allocation on the
// query reconstruction hot path, so those patterns remain in alwaysRun.
func isGenericCredentialAnchorSet(anchors []string) bool {
	if len(anchors) == 0 {
		return false
	}
	for _, anchor := range anchors {
		switch anchor {
		case "api", "key", "passw", "password", "secret", "token":
		default:
			return false
		}
	}
	return true
}

// requiredLiteralAnchors finds one conservative required-literal set for re.
// For concatenation, any mandatory child can prove the gate; prefer the set
// with the longest shortest anchor. For alternation, every branch must prove an
// anchor, because a missing branch would turn the optimization into a bypass.
func requiredLiteralAnchors(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture:
		if len(re.Sub) != 1 {
			return nil
		}
		return requiredLiteralAnchors(re.Sub[0])
	case syntax.OpConcat:
		var best []string
		for _, sub := range re.Sub {
			candidate := requiredLiteralAnchors(sub)
			if betterAnchorSet(candidate, best) {
				best = candidate
			}
		}
		return best
	case syntax.OpAlternate:
		var combined []string
		for _, sub := range re.Sub {
			candidate := requiredLiteralAnchors(sub)
			if len(candidate) == 0 {
				return nil
			}
			combined = append(combined, candidate...)
		}
		return combined
	case syntax.OpPlus:
		if len(re.Sub) != 1 {
			return nil
		}
		return requiredLiteralAnchors(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) != 1 {
			return nil
		}
		return requiredLiteralAnchors(re.Sub[0])
	default:
		return nil
	}
}

func betterAnchorSet(candidate, current []string) bool {
	if len(candidate) == 0 {
		return false
	}
	if len(current) == 0 {
		return true
	}
	return shortestStringLength(candidate) > shortestStringLength(current)
}

func shortestStringLength(values []string) int {
	shortest := -1
	for _, value := range values {
		if shortest < 0 || len(value) < shortest {
			shortest = len(value)
		}
	}
	if shortest < 0 {
		return 0
	}
	return shortest
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
	unique := result[:1]
	for _, idx := range result[1:] {
		if idx != unique[len(unique)-1] {
			unique = append(unique, idx)
		}
	}
	return unique
}
