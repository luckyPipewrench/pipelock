// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// A distance gate only rejects input when mandatory literal starts cannot be
// close enough for the regex. It never restricts the input passed to the regex.
type responseNearGate struct {
	left, right []string
	maxBytes    int
}

func (g *responseNearGate) matches(folded string) bool {
	const maxCandidates = 4096
	candidates := 0
	for _, right := range g.right {
		for offset := 0; offset < len(folded); {
			index := strings.Index(folded[offset:], right)
			if index < 0 {
				break
			}
			start := offset + index
			candidates++
			if candidates > maxCandidates {
				return true // Dense input falls back to the original matcher.
			}
			for _, left := range g.left {
				begin := max(0, start-g.maxBytes)
				end := min(len(folded), start+len(left))
				if strings.Contains(folded[begin:end], left) {
					return true
				}
			}
			offset = start + 1
		}
	}
	return false
}

func responseNearGates(re *syntax.Regexp) []*responseGate {
	var gates []*responseGate
	var previous []string
	distance := 0
	for _, child := range re.Sub {
		anchors, _ := leadingLiteralAnchors(child)
		useful := len(anchors) > 0
		for _, anchor := range anchors {
			// Empty or short alternatives cannot prove a selective mandatory start.
			if utf8.RuneCountInString(anchor) < minPreFilterAnchorLength {
				useful = false
				break
			}
		}
		if useful {
			folded := make([]string, len(anchors))
			for i, anchor := range anchors {
				folded[i] = responseDistanceText(responseSimpleFold(anchor))
				if folded[i] == "" {
					useful = false
				}
			}
			if !useful {
				previous = nil
				distance = -1
				continue
			}
			if previous != nil && distance >= 0 {
				gates = append(gates, &responseGate{near: &responseNearGate{
					left: previous, right: folded, maxBytes: distance * utf8.UTFMax,
				}})
			}
			previous = folded
			distance = 0
		}
		width := responseMaxRunes(child)
		if width < 0 || distance < 0 || width > responseDistanceLimit-distance {
			previous = nil
			distance = -1
		} else {
			distance += width
		}
	}
	return gates
}

// This is a proof-work limit, never a bound on accepted input. Unknown or
// unbounded expressions receive no distance gate. Four bytes per retained rune
// also covers Unicode simple-fold orbits and replacement of malformed UTF-8.
const responseDistanceLimit = 4096

func responseMaxRunes(re *syntax.Regexp) int {
	if responseOnlyWhitespace(re) {
		return 0
	}
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		if len(re.Rune) <= responseDistanceLimit {
			return len(re.Rune)
		}
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpQuest:
		if len(re.Sub) == 1 {
			return responseMaxRunes(re.Sub[0])
		}
	case syntax.OpRepeat:
		if re.Max >= 0 && len(re.Sub) == 1 {
			width := responseMaxRunes(re.Sub[0])
			if width >= 0 && (width == 0 || re.Max <= responseDistanceLimit/width) {
				return width * re.Max
			}
		}
	case syntax.OpConcat, syntax.OpAlternate:
		width := 0
		for _, child := range re.Sub {
			part := responseMaxRunes(child)
			if part < 0 {
				return -1
			}
			if re.Op == syntax.OpAlternate {
				width = max(width, part)
			} else {
				if part > responseDistanceLimit-width {
					return -1
				}
				width += part
			}
		}
		return width
	}
	return -1
}

// Removing whitespace is a projection used only by the necessary-condition
// gate. It makes arbitrary whitespace runs cost zero without bounding the
// actual matcher or changing any of its input, spans, or findings.
func responseDistanceText(value string) string {
	return strings.Map(func(r rune) rune {
		if responseDistanceWhitespace(r) {
			return -1
		}
		return r
	}, value)
}

func responseDistanceWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f'
}

func responseOnlyWhitespace(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if !responseDistanceWhitespace(r) {
				return false
			}
		}
		return true
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i+1]-re.Rune[i] > 5 {
				return false
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if !responseDistanceWhitespace(r) {
					return false
				}
			}
		}
		return len(re.Rune) > 0
	case syntax.OpCapture, syntax.OpQuest, syntax.OpStar, syntax.OpPlus, syntax.OpRepeat,
		syntax.OpConcat, syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return false
		}
		for _, child := range re.Sub {
			if !responseOnlyWhitespace(child) {
				return false
			}
		}
		return true
	}
	return false
}
