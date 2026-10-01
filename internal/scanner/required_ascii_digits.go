// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
)

// Larger requirements are rounded DOWN to this bound. Saturating a proved
// minimum admits extra regex work; it cannot exclude a possible match.
const maxRequiredASCIIDigits uint8 = 255

func patternMinASCIIDigits(re, withoutLeftBoundary *regexp.Regexp) uint8 {
	return analyzePatternMatchRequirements(re, withoutLeftBoundary).minASCIIDigits
}

func regexpMinASCIIDigits(expression string) uint8 {
	return analyzeRegexpMatchRequirements(expression).minASCIIDigits
}

// regexpTreeMinASCIIDigits counts only digit requirements proved by the parsed
// grammar. Literal ASCII digits have singleton Unicode case-fold orbits, and
// a class counts only when every permitted rune is an ASCII digit. Unicode
// digit properties and mixed alphanumeric classes therefore prove nothing.
// Counts describe the exact matched view, never its pre-normalization source.
func regexpTreeMinASCIIDigits(tree *syntax.Regexp) uint8 {
	if tree == nil {
		return 0
	}
	switch tree.Op {
	case syntax.OpLiteral:
		var minimum uint8
		for _, r := range tree.Rune {
			if r >= '0' && r <= '9' {
				minimum = addASCIIDigitMinimum(minimum, 1)
			}
		}
		return minimum
	case syntax.OpCharClass:
		if len(tree.Rune) == 0 || len(tree.Rune)%2 != 0 {
			return 0
		}
		for i := 0; i < len(tree.Rune); i += 2 {
			if tree.Rune[i] < '0' || tree.Rune[i+1] > '9' || tree.Rune[i] > tree.Rune[i+1] {
				return 0
			}
		}
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		if len(tree.Sub) == 1 {
			return regexpTreeMinASCIIDigits(tree.Sub[0])
		}
	case syntax.OpRepeat:
		if tree.Min > 0 && (tree.Max < 0 || tree.Max >= tree.Min) && len(tree.Sub) == 1 {
			return multiplyASCIIDigitMinimum(regexpTreeMinASCIIDigits(tree.Sub[0]), tree.Min)
		}
	case syntax.OpConcat:
		var minimum uint8
		for _, child := range tree.Sub {
			minimum = addASCIIDigitMinimum(minimum, regexpTreeMinASCIIDigits(child))
		}
		return minimum
	case syntax.OpAlternate:
		if len(tree.Sub) == 0 {
			return 0
		}
		minimum := maxRequiredASCIIDigits
		for _, child := range tree.Sub {
			minimum = min(minimum, regexpTreeMinASCIIDigits(child))
		}
		return minimum
	}
	return 0
}

func addASCIIDigitMinimum(left, right uint8) uint8 {
	if right > maxRequiredASCIIDigits-left {
		return maxRequiredASCIIDigits
	}
	return left + right
}

func multiplyASCIIDigitMinimum(minimum uint8, count int) uint8 {
	if minimum == 0 || count <= 0 {
		return 0
	}
	if count > int(maxRequiredASCIIDigits)/int(minimum) {
		return maxRequiredASCIIDigits
	}
	// #nosec G115 -- 0 < count <= 255/minimum is checked above.
	return minimum * uint8(count)
}

// hasMinimumASCIIDigits stops counting as soon as the necessary floor is met.
// A shortfall only rules out work whose grammar independently proves that
// floor, including the decimal decoder's minimum accepted-number run length.
func hasMinimumASCIIDigits(text string, minimum uint8) bool {
	if minimum == 0 {
		return true
	}
	var digits uint8
	for i := 0; i < len(text); i++ {
		if text[i] >= '0' && text[i] <= '9' {
			digits++
			if digits == minimum {
				return true
			}
		}
	}
	return false
}
