// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// responseGate is a necessary condition for a regex match. A nil gate means
// no useful literal could be proved, so the pattern must run.
type responseGate struct {
	literal string
	folded  string
	hasFold bool
	all     []*responseGate
	any     []*responseGate
}

func (g *responseGate) matches(content, folded string) bool {
	if g.literal != "" {
		if !g.hasFold {
			return strings.Contains(content, g.literal)
		}
		return strings.Contains(folded, g.folded)
	}
	if g.all != nil {
		for _, part := range g.all {
			if !part.matches(content, folded) {
				return false
			}
		}
		return true
	}
	for _, branch := range g.any {
		if branch.matches(content, folded) {
			return true
		}
	}
	return false
}

// responseLiteralGate keeps the boolean structure of mandatory regex paths.
// Concat needs every mandatory part; alternate needs one complete branch.
func responseLiteralGate(re *syntax.Regexp) *responseGate {
	switch re.Op {
	case syntax.OpLiteral, syntax.OpCharClass:
		literal, fold := responseLiteralPart(re)
		return newResponseLiteralGate(literal, fold)
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return responseLiteralGate(re.Sub[0])
		}
	case syntax.OpConcat:
		var parts []*responseGate
		var run strings.Builder
		var runFold bool
		flush := func() {
			if gate := newResponseLiteralGate(run.String(), runFold); gate != nil {
				parts = append(parts, gate)
			}
			run.Reset()
		}
		for _, child := range re.Sub {
			literal, fold := responseLiteralPart(child)
			if literal != "" {
				if run.Len() > 0 && fold != runFold {
					flush()
				}
				run.WriteString(literal)
				runFold = fold
				continue
			}
			flush()
			if gate := responseLiteralGate(child); gate != nil {
				parts = append(parts, gate)
			}
		}
		flush()
		if leading := responseLeadingGate(re); leading != nil {
			parts = append(parts, leading)
		}
		sort.SliceStable(parts, func(i, j int) bool { return parts[i].minLength() > parts[j].minLength() })
		return allResponseGates(parts)
	case syntax.OpAlternate:
		branches := make([]*responseGate, 0, len(re.Sub))
		for _, child := range re.Sub {
			gate := responseLiteralGate(child)
			if gate == nil {
				return nil
			}
			branches = append(branches, gate)
		}
		if len(branches) == 1 {
			return branches[0]
		}
		return &responseGate{any: branches}
	case syntax.OpPlus, syntax.OpRepeat:
		if re.Op == syntax.OpRepeat && re.Min == 0 {
			return nil
		}
		if len(re.Sub) == 1 {
			return responseLiteralGate(re.Sub[0])
		}
	}
	return nil
}

// regexp/syntax factors common prefixes across alternatives. Rebuild a bounded
// literal leading set so p(?:rovide|aste) can gate on provide|paste rather
// than the weaker rovide|aste. Folded matching is a safe superset here even
// when an individual source rune was case sensitive.
func responseLeadingGate(re *syntax.Regexp) *responseGate {
	values, _ := leadingLiteralAnchors(re)
	if len(values) == 0 {
		return nil
	}
	branches := make([]*responseGate, 0, len(values))
	for _, value := range values {
		gate := newResponseLiteralGate(value, true)
		if gate == nil {
			return nil
		}
		branches = append(branches, gate)
	}
	if len(branches) == 1 {
		return branches[0]
	}
	return &responseGate{any: branches}
}

func allResponseGates(parts []*responseGate) *responseGate {
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return &responseGate{all: parts}
}

func (g *responseGate) minLength() int {
	if g.literal != "" {
		return len(g.literal)
	}
	if g.all != nil {
		longest := 0
		for _, part := range g.all {
			longest = max(longest, part.minLength())
		}
		return longest
	}
	shortest := -1
	for _, branch := range g.any {
		if shortest < 0 || branch.minLength() < shortest {
			shortest = branch.minLength()
		}
	}
	return shortest
}

func responseLiteralPart(re *syntax.Regexp) (string, bool) {
	if re.Op == syntax.OpLiteral {
		return string(re.Rune), re.Flags&syntax.FoldCase != 0
	}
	if re.Op != syntax.OpCharClass {
		return "", false
	}
	// A singleton or one simple-fold family can be represented by one rune.
	var first rune
	count := 0
	for i := 0; i+1 < len(re.Rune); i += 2 {
		for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
			count++
			if count > 4 {
				return "", false
			}
			if count == 1 {
				first = r
			} else if !sameSimpleFold(first, r) {
				return "", false
			}
			if r == re.Rune[i+1] {
				break
			}
		}
	}
	if count == 0 {
		return "", false
	}
	return string(first), count > 1 || re.Flags&syntax.FoldCase != 0
}

func sameSimpleFold(first, other rune) bool {
	for r := unicode.SimpleFold(first); r != first; r = unicode.SimpleFold(r) {
		if r == other {
			return true
		}
	}
	return first == other
}

func newResponseLiteralGate(literal string, fold bool) *responseGate {
	if utf8.RuneCountInString(literal) < minPreFilterAnchorLength {
		return nil
	}
	gate := &responseGate{literal: literal}
	if fold {
		gate.hasFold = true
		gate.folded = responseSimpleFold(literal)
	}
	return gate
}

// Canonicalize each Unicode simple-fold orbit. Go's regexp (?i) uses these
// orbits, including Kelvin sign and long s; ToLower alone is insufficient.
func responseSimpleFold(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		canonical := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < canonical {
				canonical = folded
			}
		}
		out.WriteRune(canonical)
	}
	return out.String()
}
