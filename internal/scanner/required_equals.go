// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
)

// patternRequiresEquals proves a necessary condition for every effective
// matching grammar. Transformed provider views can use withoutLeftBoundary
// instead of re, so both must prove the condition before it is enabled.
// An absent or uncertain proof always leaves the original matcher running.
func patternRequiresEquals(re, withoutLeftBoundary *regexp.Regexp) bool {
	return analyzePatternMatchRequirements(re, withoutLeftBoundary).requiresEquals
}

func regexpRequiresEquals(regex string) bool {
	return analyzeRegexpMatchRequirements(regex).requiresEquals
}

// regexpTreeRequiresEquals only proves the literal U+003D. It has no Unicode
// case-fold siblings and is always the byte '=' in the exact view matched by
// the regex. Concatenation needs one mandatory child; alternation needs every
// branch. Optional, empty and unrecognized constructs do not establish proof.
func regexpTreeRequiresEquals(tree *syntax.Regexp) bool {
	if tree == nil {
		return false
	}
	switch tree.Op {
	case syntax.OpLiteral:
		for _, r := range tree.Rune {
			if r == '=' {
				return true
			}
		}
	case syntax.OpCapture, syntax.OpPlus:
		return len(tree.Sub) == 1 && regexpTreeRequiresEquals(tree.Sub[0])
	case syntax.OpRepeat:
		return tree.Min > 0 && len(tree.Sub) == 1 && regexpTreeRequiresEquals(tree.Sub[0])
	case syntax.OpConcat:
		for _, child := range tree.Sub {
			if regexpTreeRequiresEquals(child) {
				return true
			}
		}
	case syntax.OpAlternate:
		if len(tree.Sub) == 0 {
			return false
		}
		for _, child := range tree.Sub {
			if !regexpTreeRequiresEquals(child) {
				return false
			}
		}
		return true
	}
	return false
}
