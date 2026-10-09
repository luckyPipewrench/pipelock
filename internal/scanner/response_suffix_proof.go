// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"io"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

// responseSuffixProof is the bounded anchored negative engine. Suffix proofs
// use a reversed expression and text; interior proofs use a necessary forward
// suffix. Positive or inconclusive results fall back to the original FindAll on
// the full input, so only the original matcher produces findings and spans.
type responseSuffixProof struct {
	anchors    []string       // simple-folded required starts in the proof's direction
	head       *regexp.Regexp // ^(?:R), for a candidate at offset 0
	mid        *regexp.Regexp // ^(?s:.)(?:R), consumes the real preceding rune
	tree       *syntax.Regexp
	expression string
	once       sync.Once
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
	return newResponseAnchoredProof(tree)
}

// newResponsePrefixProof constructs a forward negative proof beginning at a
// mandatory interior literal. It reads the complete remaining text, or reports
// an exhausted budget as inconclusive. Its caller establishes Perl compilation
// provenance; the original matcher owns all findings.
func newResponsePrefixProof(re *regexp.Regexp) *responseSuffixProof {
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	original := tree
	tree = responseInteriorProofSyntax(original)
	if tree == nil {
		return nil
	}
	proof := newResponseAnchoredProof(tree)
	if proof != nil && tree == original {
		proof.expression = re.String()
	}
	return proof
}

// responseInteriorProofSyntax drops only consumed prefixes. Every match of the
// input expression therefore contains a match of the returned suffix ending at
// the same position. Alternation requires a suffix for EVERY branch; a required
// repetition uses its final iteration. Optional iterations cannot prove a suffix.
// Assertions are retained and evaluated with the real preceding rune by mid.
func responseInteriorProofSyntax(tree *syntax.Regexp) *syntax.Regexp {
	if newResponseAnchoredProof(tree) != nil {
		return tree
	}
	switch tree.Op {
	case syntax.OpCapture:
		if len(tree.Sub) == 1 {
			return responseInteriorProofSyntax(tree.Sub[0])
		}
	case syntax.OpConcat:
		for i, sub := range tree.Sub {
			if suffix := responseInteriorProofSyntax(sub); suffix != nil {
				parts := append([]*syntax.Regexp{suffix}, tree.Sub[i+1:]...)
				return &syntax.Regexp{Op: syntax.OpConcat, Sub: parts}
			}
		}
	case syntax.OpAlternate:
		parts := make([]*syntax.Regexp, 0, len(tree.Sub))
		for _, sub := range tree.Sub {
			suffix := responseInteriorProofSyntax(sub)
			if suffix == nil {
				return nil
			}
			parts = append(parts, suffix)
		}
		if len(parts) > 0 {
			return &syntax.Regexp{Op: syntax.OpAlternate, Sub: parts}
		}
	case syntax.OpPlus, syntax.OpRepeat:
		if (tree.Op == syntax.OpPlus || tree.Min > 0) && len(tree.Sub) == 1 {
			return responseInteriorProofSyntax(tree.Sub[0])
		}
	}
	return nil
}

func newResponseAnchoredProof(tree *syntax.Regexp) *responseSuffixProof {
	starts, _ := leadingLiteralAnchors(responseSuffixAnchorSyntax(tree))
	if len(starts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(starts))
	proof := &responseSuffixProof{tree: tree}
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
	return proof
}

// compile defers expensive syntax printing and compilation until a large body
// actually has a suffix candidate. Each immutable proof is shared by scans and
// memo-filtered pattern lists, so initialization publishes both matchers once.
func (p *responseSuffixProof) compile() bool {
	p.once.Do(func() {
		if p.tree == nil {
			return
		}
		expr := p.expression
		if expr == "" {
			expr = p.tree.String()
		}
		head, err1 := regexp.Compile(`^(?:` + expr + `)`)
		mid, err2 := regexp.Compile(`^(?s:.)(?:` + expr + `)`)
		if err1 == nil && err2 == nil {
			p.head, p.mid = head, mid
		}
		p.tree = nil
	})
	return p.head != nil && p.mid != nil
}

// responseFoldView is call-local reversed text used only by serial prefilter
// proofs; no worker or Scanner retains or shares it.
type responseFoldView struct {
	content, folded string
	sameOffsets     bool
	literals        responseLiteralMemo
	candidates      map[string][]int
	candidateCount  int
}

// folded must be responseSimpleFold(content). Folding picks the lowest code
// point of an orbit and UTF-8 length never decreases with code point. For valid
// UTF-8 no rune grows, so equal total length preserves every byte offset.
func newResponseFoldView(content, folded string) *responseFoldView {
	return &responseFoldView{content: content, folded: folded, sameOffsets: utf8.ValidString(content) && len(content) == len(folded)}
}

// contentOffsets rewrites sorted folded byte offsets as content byte offsets
// in one lockstep walk, using storage proportional to the candidates rather
// than the body. Folding maps each rune to exactly one rune. An offset that is
// not a folded-rune boundary, or a fold that disagrees with its text, makes
// the proof inconclusive.
func (v *responseFoldView) contentOffsets(sorted []int) bool {
	if v.sameOffsets {
		return true
	}
	ci, fi := 0, 0
	for k := 0; k < len(sorted); {
		// A candidate starts a non-empty anchor, so it maps inside both texts.
		if sorted[k] < fi || fi >= len(v.folded) || ci >= len(v.content) {
			return false
		}
		if sorted[k] == fi {
			sorted[k] = ci
			k++
			continue
		}
		_, cn := utf8.DecodeRuneInString(v.content[ci:])
		_, fn := utf8.DecodeRuneInString(v.folded[fi:])
		ci += cn
		fi += fn
	}
	return true
}

const responseSuffixProofMaxCandidateRatio = 32 // one candidate per 32 bytes

// Candidate lists contain complete folded offsets, never a truncated search.
// They are bounded across the view and copied before mapping to source offsets.
func (v *responseFoldView) anchorCandidates(anchor string, limit int) ([]int, bool) {
	if positions, known := v.candidates[anchor]; known {
		return positions, true
	}
	var positions []int
	for off := 0; off < len(v.folded); {
		i := strings.Index(v.folded[off:], anchor)
		if i < 0 {
			break
		}
		at := off + i
		off = at + 1
		positions = append(positions, at)
		if len(positions) > limit {
			return nil, false
		}
	}
	if len(positions) > 0 && len(v.candidates) < responseMemoMaxEntries && v.candidateCount+len(positions) <= limit {
		if v.candidates == nil {
			v.candidates = make(map[string][]int)
		}
		v.candidates[anchor] = positions
		v.candidateCount += len(positions)
	}
	return positions, true
}

// provesEmpty reports true only when no match of the original regex can exist.
func (p *responseSuffixProof) provesEmpty(v *responseFoldView) bool {
	if p == nil || v == nil {
		return false
	}
	content := v.content
	limit := min(len(content)/responseSuffixProofMaxCandidateRatio+1, 16384)
	var cands []int
	for _, anchor := range p.anchors {
		key := responseLiteralKey{text: anchor, fold: true}
		if present, known := v.literals[key]; known && !present {
			continue
		}
		positions, complete := v.anchorCandidates(anchor, limit)
		if !complete || len(cands)+len(positions) > limit {
			return false
		}
		cands = append(cands, positions...)
		if v.literals != nil && len(v.literals) < responseMemoMaxEntries {
			v.literals[key] = len(positions) > 0
		}
	}
	slices.Sort(cands)
	if !v.contentOffsets(cands) {
		return false
	}
	if len(cands) != 0 && !p.compile() {
		return false
	}
	budget := len(content) // total runes the anchored runs may read
	reader := &responseBudgetReader{}
	prev := -1
	for _, pos := range cands {
		if pos == prev {
			continue // several anchors at one position need one run
		}
		prev = pos
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
	if utf8.ValidString(s) {
		out := make([]byte, len(s))
		for i, w := 0, len(s); i < len(s); {
			_, n := utf8.DecodeRuneInString(s[i:])
			w -= n
			copy(out[w:], s[i:i+n])
			i += n
		}
		return string(out)
	}
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
