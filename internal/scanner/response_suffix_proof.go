// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"io"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// responseSuffixProof proves a regex has no match by running it anchored at
// each position where one of its mandatory suffix literals in reversed text occurs. Any
// positive or inconclusive result falls back to the original FindAll on the
// full input, so findings, spans and order are produced only by the original
// matcher.
type responseSuffixProof struct {
	anchors []string       // simple-folded reversed suffixes
	head    *regexp.Regexp // ^(?:R), for a candidate at offset 0
	mid     *regexp.Regexp // ^(?s:.)(?:R), consumes the real preceding rune
}

func newResponseSuffixProof(re *regexp.Regexp) *responseSuffixProof {
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	tree = reverseResponseSyntax(tree)
	if tree == nil {
		return nil
	}
	starts, _ := leadingLiteralAnchors(responseSuffixAnchorSyntax(tree))
	if len(starts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(starts))
	proof := &responseSuffixProof{}
	for _, start := range starts {
		if utf8.RuneCountInString(start) < minPreFilterAnchorLength {
			return nil
		}
		folded := responseSimpleFold(start)
		if _, ok := seen[folded]; !ok {
			seen[folded] = struct{}{}
			proof.anchors = append(proof.anchors, folded)
		}
	}
	head, err1 := regexp.Compile(`^(?:` + tree.String() + `)`)
	mid, err2 := regexp.Compile(`^(?s:.)(?:` + tree.String() + `)`)
	if err1 != nil || err2 != nil {
		return nil
	}
	proof.head, proof.mid = head, mid
	return proof
}

// responseFoldView is call-local reversed text used only by serial prefilter
// proofs; no worker or Scanner retains or shares its offset map.
type responseFoldView struct {
	content, folded string
	sameOffsets     bool
	offsets         []int // folded byte -> content byte, built lazily
}

func newResponseFoldView(content, folded string) *responseFoldView {
	return &responseFoldView{content: content, folded: folded, sameOffsets: isASCII(content)}
}

func (v *responseFoldView) buildOffsets() {
	if v.sameOffsets || v.offsets != nil {
		return
	}
	v.offsets = make([]int, 0, len(v.folded)+1)
	for i, r := range v.content {
		n := len(responseSimpleFold(string(r)))
		for range n {
			v.offsets = append(v.offsets, i)
		}
	}
	v.offsets = append(v.offsets, len(v.content))
}

const responseSuffixProofMaxCandidateRatio = 32 // one candidate per 32 bytes

// provesEmpty reports true only when no match of the original regex can exist.
func (p *responseSuffixProof) provesEmpty(v *responseFoldView) bool {
	if p == nil || v == nil {
		return false
	}
	content, folded := v.content, v.folded
	limit := min(len(content)/responseSuffixProofMaxCandidateRatio+1, 16384)
	var cands []int
	for _, anchor := range p.anchors {
		for off := 0; off < len(folded); {
			i := strings.Index(folded[off:], anchor)
			if i < 0 {
				break
			}
			at := off + i
			off = at + 1
			cands = append(cands, at)
			if len(cands) > limit {
				return false
			}
		}
	}
	if !v.sameOffsets && len(cands) > 0 {
		v.buildOffsets()
	}
	budget := len(content) // total runes the anchored runs may read
	reader := &responseBudgetReader{}
	done := make(map[int]struct{}, len(cands))
	for _, at := range cands {
		pos := at
		if !v.sameOffsets {
			if at > 0 && v.offsets[at] == v.offsets[at-1] {
				continue // not a folded-rune boundary
			}
			pos = v.offsets[at]
		}
		if _, ok := done[pos]; ok {
			continue
		}
		done[pos] = struct{}{}
		re, from := p.head, 0
		if pos > 0 {
			re, from = p.mid, responsePreviousRuneStart(content, pos)
		}
		reader.reset(content[from:], budget)
		matched := re.MatchReader(reader)
		if reader.exhausted {
			return false
		}
		if matched {
			return false
		}
		budget -= reader.read
	}
	return true
}

// Forward decoding is what regexp uses; find the start of the rune ending at pos.
func responsePreviousRuneStart(content string, pos int) int {
	for back := 1; back <= utf8.UTFMax && back <= pos; back++ {
		q := pos - back
		if _, n := utf8.DecodeRuneInString(content[q:]); q+n == pos && utf8.RuneStart(content[q]) {
			if back == 1 || n == back {
				return q
			}
		}
	}
	return pos - 1
}

// responseBudgetReader reports exhaustion instead of silently truncating: a
// run that asked for input beyond the budget is inconclusive, never negative.
type responseBudgetReader struct {
	s         string
	i, read   int
	budget    int
	exhausted bool
}

func (r *responseBudgetReader) reset(s string, budget int) {
	*r = responseBudgetReader{s: s, budget: budget}
}

func (r *responseBudgetReader) ReadRune() (rune, int, error) {
	if r.i >= len(r.s) {
		return 0, 0, io.EOF
	}
	if r.read >= r.budget {
		r.exhausted = true
		return 0, 0, io.EOF
	}
	c := r.s[r.i]
	if c < utf8.RuneSelf {
		r.i++
		r.read++
		return rune(c), 1, nil
	}
	ch, n := utf8.DecodeRuneInString(r.s[r.i:])
	r.i += n
	r.read++
	return ch, n, nil
}

// reverseResponseSyntax reverses the recognized rune language, not the
// match preference. The original expression alone produces every finding.
func reverseResponseSyntax(r *syntax.Regexp) *syntax.Regexp {
	n := *r
	n.Sub = make([]*syntax.Regexp, len(r.Sub))
	n.Rune = append([]rune(nil), r.Rune...)
	for i, sub := range r.Sub {
		n.Sub[i] = reverseResponseSyntax(sub)
		if n.Sub[i] == nil {
			return nil
		}
	}
	switch r.Op {
	case syntax.OpConcat:
		for i, j := 0, len(n.Sub)-1; i < j; i, j = i+1, j-1 {
			n.Sub[i], n.Sub[j] = n.Sub[j], n.Sub[i]
		}
	case syntax.OpLiteral:
		for i, j := 0, len(n.Rune)-1; i < j; i, j = i+1, j-1 {
			n.Rune[i], n.Rune[j] = n.Rune[j], n.Rune[i]
		}
	case syntax.OpBeginLine:
		n.Op = syntax.OpEndLine
	case syntax.OpEndLine:
		n.Op = syntax.OpBeginLine
	case syntax.OpBeginText:
		n.Op = syntax.OpEndText
	case syntax.OpEndText:
		n.Op = syntax.OpBeginText
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpCharClass,
		syntax.OpAnyCharNotNL, syntax.OpAnyChar, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary, syntax.OpCapture, syntax.OpStar,
		syntax.OpPlus, syntax.OpRepeat, syntax.OpAlternate, syntax.OpQuest:
	default:
		return nil
	}
	return &n
}

// Decode in the forward direction first: invalid UTF-8 must have exactly the
// replacement-rune semantics of regexp, including stray continuation bytes.
func reverseResponseText(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// Only the anchor-analysis tree expands finite optional terms. Keeping the
// actual reversed expression unchanged preserves its compiler shape and avoids
// turning a cheap negative proof into an expensive alternate search.
func responseSuffixAnchorSyntax(r *syntax.Regexp) *syntax.Regexp {
	n := *r
	n.Sub = make([]*syntax.Regexp, len(r.Sub))
	for i, sub := range r.Sub {
		n.Sub[i] = responseSuffixAnchorSyntax(sub)
	}
	if r.Op == syntax.OpQuest && len(n.Sub) == 1 {
		_, complete := leadingLiteralAnchors(n.Sub[0])
		if complete {
			n.Op = syntax.OpAlternate
			n.Sub = append([]*syntax.Regexp{{Op: syntax.OpEmptyMatch}}, n.Sub...)
		} else {
			// Star has no required start. This is deliberately inconclusive for anchor
			// extraction and is never compiled or used as the matching expression.
			n.Op = syntax.OpStar
		}
	}
	return &n
}
