// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
)

type compiledMatchRequirements struct {
	requiresEquals bool
	minASCIIDigits uint8
	// shape is nil when the grammar cannot be gated or when a second
	// boundary-free grammar also runs against the same views.
	shape *regexShapeGate
}

// analyzePatternMatchRequirements parses each effective compiled regex once
// at construction. Transformed provider views can use the boundary-free
// grammar, so a requirement must hold for both grammars. Zero facts leave
// the complete original matching path enabled.
func analyzePatternMatchRequirements(re, withoutLeftBoundary *regexp.Regexp) compiledMatchRequirements {
	if re == nil {
		return compiledMatchRequirements{}
	}
	requirements := analyzeRegexpMatchRequirements(re.String())
	if withoutLeftBoundary != nil {
		body := analyzeRegexpMatchRequirements(withoutLeftBoundary.String())
		requirements.requiresEquals = requirements.requiresEquals && body.requiresEquals
		requirements.minASCIIDigits = min(requirements.minASCIIDigits, body.minASCIIDigits)
		requirements.shape = nil
	}
	if prefix, _ := re.LiteralPrefix(); prefix != "" {
		// The regexp engine already skips to its literal prefix, which is
		// cheaper than a byte-shape pass. Dropping a gate only costs time.
		requirements.shape = nil
	}
	return requirements
}

func analyzeRegexpMatchRequirements(expression string) compiledMatchRequirements {
	tree, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return compiledMatchRequirements{}
	}
	return compiledMatchRequirements{
		requiresEquals: regexpTreeRequiresEquals(tree),
		minASCIIDigits: regexpTreeMinASCIIDigits(tree),
		shape:          analyzeRegexShape(tree),
	}
}
