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
	}
}
