// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"io"
	"math/rand"
	"reflect"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func suffixProofView(content string) *responseFoldView {
	reversed := reverseResponseText(content)
	return newResponseFoldView(reversed, responseSimpleFold(reversed))
}

func TestResponseSuffixProofParity(t *testing.T) {
	s := MustNew(config.Defaults())
	defer s.Close()
	groups := [][]*compiledPattern{s.responsePatterns, s.responseOptSpacePatterns, s.responseVowelFoldPatterns, s.core.responsePatterns, s.core.responseOptSpacePatterns, s.core.responseVowelFoldPatterns}
	rnd := rand.New(rand.NewSource(725)) // #nosec G404 -- reproducible corpus.
	checked, negatives := 0, 0
	for _, group := range groups {
		for _, p := range group {
			proof := newResponseSuffixProof(p.re)
			if proof == nil {
				continue
			}
			tree, err := syntax.Parse(p.re.String(), syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 20; attempt++ {
				positive := genMatch(tree.Simplify(), rnd, 0)
				for _, content := range []string{positive, " x " + positive, "\n" + positive + "\n", positive + " suffix", "\xff\xfe" + positive + "\x80", strings.Repeat("ordinary javascript ;", 3), strings.Repeat("prompt system secret ", 10)} {
					empty := proof.provesEmpty(suffixProofView(content))
					checked++
					if empty {
						negatives++
						if p.re.MatchString(content) {
							t.Fatalf("negative proof dropped %s", p.name)
						}
					}
				}
			}
		}
	}
	if checked == 0 || negatives == 0 {
		t.Fatal("empty comparison corpus")
	}
	t.Logf("comparisons=%d negative-proofs=%d", checked, negatives)
}

func TestResponseSuffixProofAssertions(t *testing.T) {
	for _, expr := range []string{`(?im)^alpha.*suffix$`, `(?s)alpha.*suffix`, `(?i)\bkey.*secrets?\b`, `\Aalpha.*suffix\z`, `alpha.*(?:suffix|ending)`, `alpha.*suffix\B`, `(?m)alpha$\n^suffix`, `alpha[\s\S]*suffix`, `(?i)alpha.*(?:secret|SECRET)`, `alpha.*(?:中文模式|開発者模式)`, `alpha.*\x{fffd}suffix`} {
		t.Run(expr, func(t *testing.T) {
			re := regexp.MustCompile(expr)
			proof := newResponseSuffixProof(re)
			if proof == nil {
				t.Fatal("expected extractable suffix")
			}
			for _, content := range []string{"alpha suffix", "alpha\nsuffix", "xalpha suffixx", "ALPHA KEY SECRETS", "KEY ſecrets", "alpha\xffsuffix", "ordinary suffix", "alpha 中文模式", "alpha 開発者模式", "alpha", "alpha\xff\xfesuffix"} {
				if proof.provesEmpty(suffixProofView(content)) && re.MatchString(content) {
					t.Fatalf("dropped a match for %q", content)
				}
			}
		})
	}
}

func TestResponseSuffixProofFallback(t *testing.T) {
	for _, expr := range []string{`.*`, `alpha.*`, `(?:alpha|x)`, `alpha.*[0-9]`, `alpha.*s?`, `(?:alpha)?`, `alpha(?:.*suffix)?`} {
		if newResponseSuffixProof(regexp.MustCompile(expr)) != nil {
			t.Errorf("must fall back for %q", expr)
		}
	}
	if (*responseSuffixProof)(nil).provesEmpty(nil) {
		t.Fatal("nil is inconclusive")
	}
	proof := newResponseSuffixProof(regexp.MustCompile(`alpha.*suffix`))
	if proof.provesEmpty(nil) {
		t.Fatal("nil view is inconclusive")
	}
	// Dense candidates must run the original matcher, including a late match.
	dense := strings.Repeat("suffix ", 100) + "alpha suffix"
	if proof.provesEmpty(suffixProofView(dense)) {
		t.Fatal("dense proof must fall back")
	}
	// Each suffix forces a long anchored search; the shared read budget expires.
	exhausted := strings.Repeat("suffix"+strings.Repeat(" ", 500), 20)
	if proof.provesEmpty(suffixProofView(exhausted)) {
		t.Fatal("exhausted proof must fall back")
	}
	if proof.provesEmpty(suffixProofView("alpha suffix")) {
		t.Fatal("positive must run original matcher")
	}
	if !proof.provesEmpty(suffixProofView("ordinary text")) {
		t.Fatal("absent suffix must prove empty")
	}
}

func TestResponseSuffixProofPrefilterAndMemo(t *testing.T) {
	p := &compiledPattern{name: "synthetic", re: regexp.MustCompile(`alpha.*suffix`)}
	p.responseMemoRegexp = p.re
	pf := newResponsePreFilter([]*compiledPattern{p})
	negative := "suffix " + strings.Repeat(" ", responseMemoMinBytes) + " alpha"
	if !pf.gates[0].matches(negative, responseSimpleFold(negative)) {
		t.Fatal("existing gate must admit positive control")
	}
	if slices.Contains(pf.patternsToCheck(negative), 0) {
		t.Fatal("suffix proof must reject reversed order")
	}
	positive := strings.Repeat(" ", responseMemoMinBytes) + "alpha suffix and alpha suffix"
	want := matchPatternsAgainst([]*compiledPattern{p}, positive)
	if len(want) == 0 {
		t.Fatal("positive control absent")
	}
	if got := matchPatternsPreFiltered(pf, []*compiledPattern{p}, positive); !reflect.DeepEqual(got, want) {
		t.Fatal("finding/span attribution changed")
	}
	// A reused negative pattern is removed; remaining proof indices must stay aligned.
	q := &compiledPattern{name: "second", re: regexp.MustCompile(`beta.*ending`)}
	q.responseMemoRegexp = q.re
	pats := []*compiledPattern{p, q}
	filter := newResponsePreFilter(pats)
	memo := newResponseMatchMemo(len(positive))
	if len(memo.match(filter, pats, negative)) != 0 {
		t.Fatal("negative has findings")
	}
	for _, content := range []string{negative, positive, strings.Repeat(" ", responseMemoMinBytes) + "beta ending"} {
		if got, want := memo.match(filter, pats, content), matchPatternsAgainst(pats, content); !reflect.DeepEqual(got, want) {
			t.Fatal("memo parity changed")
		}
	}
	// Hand-constructed filters without proofs retain the old full-matcher behavior.
	plain := &responsePreFilter{gates: filter.gates}
	if got, want := matchPatternsPreFiltered(plain, pats, positive), matchPatternsAgainst(pats, positive); !reflect.DeepEqual(got, want) {
		t.Fatal("absent proof must fall back")
	}
	companion := &compiledPattern{name: externalDataTransferDirectivePatternName, re: regexp.MustCompile(config.ExternalDataTransferDirectiveRegex)}
	if newResponsePreFilter([]*compiledPattern{companion}).proofs[0] != nil {
		t.Fatal("companions cannot use regexp-only proof")
	}
}

func TestResponseSuffixProofRuneOffsets(t *testing.T) {
	for _, content := range []string{"ASCII", "Key ſecrets 中文", "\xff\xf0\x80\xfe alpha suffix"} {
		view := suffixProofView(content)
		view.buildOffsets()
		view.buildOffsets()
		if !view.sameOffsets && len(view.offsets) != len(view.folded)+1 {
			t.Fatal("folded offsets incomplete")
		}
		for pos := 0; pos < len(view.content); {
			_, size := utf8.DecodeRuneInString(view.content[pos:])
			next := pos + size
			if got := responsePreviousRuneStart(view.content, next); got != pos {
				t.Fatalf("previous rune=%d want %d", got, pos)
			}
			pos = next
		}
	}
	// Defensive fallback for an offset not ending a decoded rune.
	if responsePreviousRuneStart("中文", 1) != 0 {
		t.Fatal("partial offset fallback")
	}
}

func TestResponseSuffixProofBudgetReader(t *testing.T) {
	var r responseBudgetReader
	r.reset("aK\xff", 3)
	for _, want := range []rune{'a', 'K', utf8.RuneError} {
		got, _, err := r.ReadRune()
		if err != nil || got != want {
			t.Fatal("rune semantics changed")
		}
	}
	if _, _, err := r.ReadRune(); !errors.Is(err, io.EOF) || r.exhausted {
		t.Fatal("real EOF is conclusive")
	}
	r.reset("ab", 1)
	if _, _, err := r.ReadRune(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ReadRune(); !errors.Is(err, io.EOF) || !r.exhausted {
		t.Fatal("budget EOF must be inconclusive")
	}
	unknown := &syntax.Regexp{Op: syntax.Op(255)}
	if reverseResponseSyntax(unknown) != nil || reverseResponseSyntax(&syntax.Regexp{Op: syntax.OpCapture, Sub: []*syntax.Regexp{unknown}}) != nil {
		t.Fatal("unknown syntax must be inconclusive")
	}
}
