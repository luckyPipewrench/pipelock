// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// asciiByteSet is a membership set over the 128 ASCII byte values.
type asciiByteSet [2]uint64

func (s *asciiByteSet) add(b byte) {
	s[b/64] |= uint64(1) << (b % 64)
}

// addRune adds an ASCII rune; callers check r < utf8.RuneSelf.
func (s *asciiByteSet) addRune(r rune) {
	s[r/64] |= uint64(1) << (r % 64)
}

func (s *asciiByteSet) has(b byte) bool {
	return b < utf8.RuneSelf && s[b/64]&(uint64(1)<<(b%64)) != 0
}

func (s *asciiByteSet) union(other asciiByteSet) {
	s[0] |= other[0]
	s[1] |= other[1]
}

func (s asciiByteSet) subsetOf(other asciiByteSet) bool {
	return s[0]&^other[0] == 0 && s[1]&^other[1] == 0
}

// asciiWordBytes is the byte set regexp's \b treats as word characters.
var asciiWordBytes = func() asciiByteSet {
	var set asciiByteSet
	for b := byte(0); b < utf8.RuneSelf; b++ {
		if syntax.IsWordChar(rune(b)) {
			set.add(b)
		}
	}
	return set
}()

const (
	// A grammar that can match more distinct non-ASCII runes than this proves
	// nothing about bytes; case folding of ASCII letters only adds two runes.
	maxShapeNonASCIIRunes = 4
	// Leading position classes are only needed to reject common words early.
	maxShapePositions = 16
	// Saturating lengths only weakens the gate; it never excludes a match.
	maxShapeLength = 1 << 20
)

// regexShapeGate is a necessary condition for a regex match, derived from the
// parsed grammar at construction. It is a pure speed gate: admits returning
// false proves the regex has no match anywhere in the text, so skipping the
// regex cannot change a verdict. Any grammar feature it cannot reason about
// leaves the pattern without a gate.
//
// Every match consumes only runes from the grammar's rune set. When that set
// is ASCII plus a few non-ASCII runes (case folding adds U+017F for s and
// U+212A for k), a text containing none of those non-ASCII runes can only be
// matched by a contiguous run of ASCII class bytes. Any other byte, including
// invalid UTF-8 (decoded as U+FFFD) and every other non-ASCII rune, ends a run
// and is never a word character for \b.
type regexShapeGate struct {
	class     asciiByteSet
	nonASCII  []rune // texts containing any of these bypass the gate
	minLen    int    // minimum match length in runes (bytes, for ASCII matches)
	minDigits uint8
	// literals: every match contains one of these, compared ASCII
	// case-insensitively. Empty means no literal requirement.
	literals []string
	// wholeWord: the match is a maximal run of ASCII word characters, so its
	// length lies in [minLen, maxLen] and its leading runes follow positions.
	wholeWord bool
	maxLen    int // -1 is unbounded; used only with wholeWord
	positions []asciiByteSet
}

// analyzeRegexShape returns nil when the grammar cannot be gated.
func analyzeRegexShape(tree *syntax.Regexp) *regexShapeGate {
	if tree == nil {
		return nil
	}
	g := &regexShapeGate{}
	var nonASCII map[rune]struct{}
	if !collectShapeRunes(tree, &g.class, &nonASCII) {
		return nil
	}
	for r := range nonASCII {
		g.nonASCII = append(g.nonASCII, r)
	}
	g.minLen = shapeMinLen(tree)
	if g.minLen == 0 {
		return nil
	}
	g.minDigits = regexpTreeMinASCIIDigits(tree)
	if anchors := requiredLiteralAnchors(tree); len(anchors) > 0 {
		usable := true
		for _, anchor := range anchors {
			if anchor == "" || !isASCIIString(anchor) {
				usable = false
				break
			}
		}
		if usable {
			g.literals = anchors
		}
	}
	g.positions, _ = shapeLeadingPositions(tree)
	if isWholeWordGrammar(tree) && g.class.subsetOf(asciiWordBytes) {
		g.wholeWord = true
		g.maxLen = shapeMaxLen(tree)
	}
	return g
}

// collectShapeRunes adds every rune a match may consume. It fails when the set
// is not ASCII plus a few named non-ASCII runes, or when it contains U+FFFD,
// which invalid UTF-8 bytes also decode to.
func collectShapeRunes(tree *syntax.Regexp, class *asciiByteSet, nonASCII *map[rune]struct{}) bool {
	addRune := func(r rune) bool {
		if r < utf8.RuneSelf {
			class.addRune(r)
			return true
		}
		if r == utf8.RuneError {
			return false
		}
		if *nonASCII == nil {
			*nonASCII = make(map[rune]struct{})
		}
		(*nonASCII)[r] = struct{}{}
		return len(*nonASCII) <= maxShapeNonASCIIRunes
	}
	switch tree.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpLiteral:
		for _, r := range tree.Rune {
			if tree.Flags&syntax.FoldCase == 0 {
				if !addRune(r) {
					return false
				}
				continue
			}
			for folded := r; ; {
				if !addRune(folded) {
					return false
				}
				folded = unicode.SimpleFold(folded)
				if folded == r {
					break
				}
			}
		}
		return true
	case syntax.OpCharClass:
		if len(tree.Rune)%2 != 0 {
			return false
		}
		for i := 0; i < len(tree.Rune); i += 2 {
			lo, hi := tree.Rune[i], tree.Rune[i+1]
			if hi < lo || hi-lo > maxShapeNonASCIIRunes+utf8.RuneSelf {
				return false
			}
			for r := lo; r <= hi; r++ {
				if !addRune(r) {
					return false
				}
			}
		}
		return true
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat,
		syntax.OpConcat, syntax.OpAlternate:
		for _, sub := range tree.Sub {
			if !collectShapeRunes(sub, class, nonASCII) {
				return false
			}
		}
		return true
	default:
		// OpAnyChar, OpAnyCharNotNL and anything newer prove nothing.
		return false
	}
}

func shapeMinLen(tree *syntax.Regexp) int {
	switch tree.Op {
	case syntax.OpLiteral:
		return len(tree.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		if len(tree.Sub) == 1 {
			return shapeMinLen(tree.Sub[0])
		}
	case syntax.OpRepeat:
		if len(tree.Sub) == 1 && tree.Min > 0 {
			return min(maxShapeLength, tree.Min*shapeMinLen(tree.Sub[0]))
		}
	case syntax.OpConcat:
		total := 0
		for _, sub := range tree.Sub {
			total = min(maxShapeLength, total+shapeMinLen(sub))
		}
		return total
	case syntax.OpAlternate:
		if len(tree.Sub) == 0 {
			return 0
		}
		shortest := maxShapeLength
		for _, sub := range tree.Sub {
			shortest = min(shortest, shapeMinLen(sub))
		}
		return shortest
	}
	return 0
}

// shapeMaxLen returns -1 when the grammar has no finite maximum.
func shapeMaxLen(tree *syntax.Regexp) int {
	switch tree.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		return len(tree.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpQuest:
		if len(tree.Sub) == 1 {
			return shapeMaxLen(tree.Sub[0])
		}
	case syntax.OpRepeat:
		if len(tree.Sub) == 1 && tree.Max >= 0 {
			sub := shapeMaxLen(tree.Sub[0])
			if sub < 0 {
				return -1
			}
			if sub > 0 && tree.Max > maxShapeLength/sub {
				return -1
			}
			return tree.Max * sub
		}
	case syntax.OpConcat:
		total := 0
		for _, sub := range tree.Sub {
			length := shapeMaxLen(sub)
			if length < 0 || total > maxShapeLength-length {
				return -1
			}
			total += length
		}
		return total
	case syntax.OpAlternate:
		longest := 0
		for _, sub := range tree.Sub {
			length := shapeMaxLen(sub)
			if length < 0 {
				return -1
			}
			longest = max(longest, length)
		}
		return longest
	}
	return -1
}

// isWholeWordGrammar reports a concatenation that starts and ends with \b.
// With every consumed rune an ASCII word character, such a match begins and
// ends at word boundaries with only word characters between, so it is exactly
// one maximal word.
func isWholeWordGrammar(tree *syntax.Regexp) bool {
	for tree.Op == syntax.OpCapture && len(tree.Sub) == 1 {
		tree = tree.Sub[0]
	}
	if tree.Op != syntax.OpConcat || len(tree.Sub) < 3 {
		return false
	}
	return tree.Sub[0].Op == syntax.OpWordBoundary && tree.Sub[len(tree.Sub)-1].Op == syntax.OpWordBoundary
}

// shapeLeadingPositions returns the byte class of each fixed leading rune
// position. The bool reports whether the expression has a fixed width, so a
// concatenation may continue into the next child.
func shapeLeadingPositions(tree *syntax.Regexp) ([]asciiByteSet, bool) {
	switch tree.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return nil, true
	case syntax.OpLiteral:
		positions := make([]asciiByteSet, 0, len(tree.Rune))
		for _, r := range tree.Rune {
			var position asciiByteSet
			var ignored map[rune]struct{}
			single := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{r}, Flags: tree.Flags}
			if !collectShapeRunes(single, &position, &ignored) {
				return positions, false
			}
			positions = append(positions, position)
		}
		return positions, true
	case syntax.OpCharClass:
		var position asciiByteSet
		var ignored map[rune]struct{}
		if !collectShapeRunes(tree, &position, &ignored) {
			return nil, false
		}
		return []asciiByteSet{position}, true
	case syntax.OpCapture:
		if len(tree.Sub) == 1 {
			return shapeLeadingPositions(tree.Sub[0])
		}
	case syntax.OpPlus:
		if len(tree.Sub) == 1 {
			positions, _ := shapeLeadingPositions(tree.Sub[0])
			return positions, false
		}
	case syntax.OpRepeat:
		if len(tree.Sub) != 1 || tree.Min <= 0 {
			return nil, false
		}
		child, complete := shapeLeadingPositions(tree.Sub[0])
		if !complete {
			return child, false
		}
		var positions []asciiByteSet
		for range tree.Min {
			if len(positions)+len(child) > maxShapePositions {
				break
			}
			positions = append(positions, child...)
		}
		return positions, tree.Min == tree.Max && len(positions) == tree.Min*len(child)
	case syntax.OpAlternate:
		// A match follows one branch, so position i holds a rune from that
		// branch's class at i, which the union over branches contains.
		var positions []asciiByteSet
		complete := true
		var width int
		for n, sub := range tree.Sub {
			child, childComplete := shapeLeadingPositions(sub)
			if n == 0 {
				positions = append(positions, child...)
				width = len(child)
			} else {
				if len(child) != width {
					complete = false
				}
				if len(child) < len(positions) {
					positions = positions[:len(child)]
				}
				for i := range positions {
					positions[i].union(child[i])
				}
			}
			complete = complete && childComplete
		}
		return positions, complete && len(tree.Sub) > 0
	case syntax.OpConcat:
		var positions []asciiByteSet
		for _, sub := range tree.Sub {
			child, complete := shapeLeadingPositions(sub)
			positions = append(positions, child...)
			if len(positions) >= maxShapePositions {
				return positions[:maxShapePositions], false
			}
			if !complete {
				return positions, false
			}
		}
		return positions, true
	}
	return nil, false
}

// admits reports whether the text may contain a match. It is one pass over the
// text and allocates nothing.
func (g *regexShapeGate) admits(text string) bool {
	if g == nil {
		return true
	}
	for _, r := range g.nonASCII {
		if strings.ContainsRune(text, r) {
			return true
		}
	}
	if len(text) < g.minLen {
		return false
	}
	if g.wholeWord {
		return g.admitsWord(text)
	}
	return g.admitsRun(text)
}

func (g *regexShapeGate) admitsRun(text string) bool {
	start, digits := 0, 0
	for i := 0; i <= len(text); i++ {
		if i < len(text) && g.class.has(text[i]) {
			if text[i] >= '0' && text[i] <= '9' {
				digits++
			}
			continue
		}
		if i-start >= g.minLen && digits >= int(g.minDigits) && g.hasLeadingStart(text[start:i]) && g.containsLiteral(text[start:i]) {
			return true
		}
		start, digits = i+1, 0
	}
	return false
}

func (g *regexShapeGate) admitsWord(text string) bool {
	start, digits, inClass := 0, 0, true
	for i := 0; i <= len(text); i++ {
		if i < len(text) && asciiWordBytes.has(text[i]) {
			c := text[i]
			if !g.class.has(c) || (i-start < len(g.positions) && !g.positions[i-start].has(c)) {
				inClass = false
			}
			if c >= '0' && c <= '9' {
				digits++
			}
			continue
		}
		length := i - start
		if inClass && length >= g.minLen && (g.maxLen < 0 || length <= g.maxLen) &&
			digits >= int(g.minDigits) && g.containsLiteral(text[start:i]) {
			return true
		}
		start, digits, inClass = i+1, 0, true
	}
	return false
}

// hasLeadingStart reports whether some offset in run leaves room for minLen
// runes and starts with bytes from the leading position classes. A match lies
// inside one run, so it starts at such an offset.
func (g *regexShapeGate) hasLeadingStart(run string) bool {
	for start := 0; start+g.minLen <= len(run); start++ {
		fits := true
		for i, position := range g.positions {
			if start+i >= len(run) || !position.has(run[start+i]) {
				fits = false
				break
			}
		}
		if fits {
			return true
		}
	}
	return false
}

func (g *regexShapeGate) containsLiteral(run string) bool {
	if len(g.literals) == 0 {
		return true
	}
	for _, literal := range g.literals {
		if indexASCIIFold(run, literal) >= 0 {
			return true
		}
	}
	return false
}

// indexASCIIFold finds needle in haystack ignoring ASCII case. needle is ASCII.
func indexASCIIFold(haystack, needle string) int {
	n := len(needle)
	for i := 0; i+n <= len(haystack); i++ {
		match := true
		for j := 0; j < n; j++ {
			if asciiLower(haystack[i+j]) != asciiLower(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
