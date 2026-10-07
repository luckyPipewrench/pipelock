// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Pieces cover case-fold orbits with non-ASCII members, CJK, line and word
// boundaries, and the invalid UTF-8 forms regexp decodes as U+FFFD.
var suffixDiffPieces = []string{
	"a", "b", "c", "k", "s", "K", "S", "ſ", "K", "中", "文", " ", "\n", "_", "1",
	"abc", "kss", "中文字", "\xff", "\x80", "\xe4\xb8", "�",
}

func suffixDiffAtom(rnd *rand.Rand, depth int) string {
	if depth > 3 {
		return regexp.QuoteMeta(suffixDiffPieces[rnd.Intn(len(suffixDiffPieces))])
	}
	switch rnd.Intn(16) {
	case 0, 1, 2, 3:
		return regexp.QuoteMeta(suffixDiffPieces[rnd.Intn(len(suffixDiffPieces))])
	case 4:
		return []string{`[abc]`, `[a-c]`, `[^a]`, `\w`, `\s`, `.`, `[\s\S]`, `[kK]`, `\d`, `[中文]`}[rnd.Intn(10)]
	case 5:
		return []string{`^`, `$`, `\b`, `\B`, `\A`, `\z`}[rnd.Intn(6)]
	case 6:
		return "(?:" + suffixDiffExpr(rnd, depth+1) + "|" + suffixDiffExpr(rnd, depth+1) + ")"
	case 7:
		return "(" + suffixDiffExpr(rnd, depth+1) + ")" + []string{"?", "*", "+", "{2}", "{1,3}", "{0,2}", "??", "*?", "+?"}[rnd.Intn(9)]
	case 8:
		return []string{"(?i:", "(?m:", "(?s:", "(?-i:", "(?im:"}[rnd.Intn(5)] + suffixDiffExpr(rnd, depth+1) + ")"
	default:
		return regexp.QuoteMeta(suffixDiffPieces[rnd.Intn(len(suffixDiffPieces))]) + regexp.QuoteMeta(suffixDiffPieces[rnd.Intn(len(suffixDiffPieces))])
	}
}

func suffixDiffExpr(rnd *rand.Rand, depth int) string {
	var b strings.Builder
	for n := 1 + rnd.Intn(4); n > 0; n-- {
		b.WriteString(suffixDiffAtom(rnd, depth))
	}
	return b.String()
}

func suffixDiffText(rnd *rand.Rand) string {
	var b strings.Builder
	for n := rnd.Intn(24); n > 0; n-- {
		b.WriteString(suffixDiffPieces[rnd.Intn(len(suffixDiffPieces))])
	}
	return b.String()
}

// TestResponseSuffixProofRandomGrammar checks soundness against generated
// expressions rather than the production pattern set, so it also covers the
// reversal, flag printing and anchor contract on shapes no current rule uses.
func TestResponseSuffixProofRandomGrammar(t *testing.T) {
	rnd := rand.New(rand.NewSource(20261006)) // #nosec G404 -- reproducible corpus.
	prefixes := []string{"", "(?i)", "(?m)", "(?s)", "(?im)"}
	proofs, checks, negatives, positives := 0, 0, 0, 0
	for attempt := 0; attempt < 6000; attempt++ {
		expr := prefixes[rnd.Intn(len(prefixes))] + suffixDiffExpr(rnd, 0)
		re, err := regexp.Compile(expr)
		if err != nil {
			continue
		}
		proof := newResponseSuffixProof(re)
		if proof == nil {
			continue
		}
		proofs++
		tree, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 60; j++ {
			content := suffixDiffText(rnd)
			if j%3 == 0 {
				// Embed a generated match so positives are common.
				content += genMatch(tree.Simplify(), rnd, 0) + suffixDiffText(rnd)
			}
			checks++
			matched := re.MatchString(content)
			if matched {
				positives++
			}
			if proof.provesEmpty(suffixProofView(content)) {
				negatives++
				if matched {
					t.Fatalf("negative proof dropped a match: expr=%q content=%q", expr, content)
				}
			}
		}
	}
	if proofs < 500 || negatives == 0 || positives == 0 {
		t.Fatalf("weak corpus: proofs=%d negatives=%d positives=%d", proofs, negatives, positives)
	}
	t.Logf("proofs=%d checks=%d negatives=%d positives=%d", proofs, checks, negatives, positives)
}

// TestResponseSuffixProofProducerAssets compares proof-enabled and
// proof-free matching on real response bodies, with and without generated
// matches inserted. Set RESPONSE_BENCH_DIR to run it.
func TestResponseSuffixProofProducerAssets(t *testing.T) {
	root := os.Getenv("RESPONSE_BENCH_DIR")
	if root == "" {
		t.Skip("set RESPONSE_BENCH_DIR")
	}
	s := MustNew(config.Defaults())
	defer s.Close()
	type group struct {
		pf       *responsePreFilter
		patterns []*compiledPattern
	}
	groups := []group{
		{s.responsePreFilter, s.responsePatterns},
		{s.responseOptSpacePreFilter, s.responseOptSpacePatterns},
		{s.responseVowelFoldPreFilter, s.responseVowelFoldPatterns},
		{s.core.responsePreFilter, s.core.responsePatterns},
		{s.core.responseOptSpacePreFilter, s.core.responseOptSpacePatterns},
		{s.core.responseVowelFoldPreFilter, s.core.responseVowelFoldPatterns},
	}
	rnd := rand.New(rand.NewSource(7)) // #nosec G404 -- reproducible corpus.
	for _, name := range []string{"echarts.js", "monaco.js"} {
		body, err := os.ReadFile(filepath.Clean(filepath.Join(root, name)))
		if err != nil {
			t.Fatal(err)
		}
		proved, inserted := 0, 0
		for _, g := range groups {
			if g.pf == nil {
				continue
			}
			plain := &responsePreFilter{gates: g.pf.gates, alwaysRun: g.pf.alwaysRun}
			bodies := []string{string(body)}
			for i, p := range g.patterns {
				if g.pf.proofs[i] == nil {
					continue // no proof: the prefilter path is unchanged
				}
				tree, err := syntax.Parse(p.re.String(), syntax.Perl)
				if err != nil {
					t.Fatal(err)
				}
				at := rnd.Intn(len(body))
				bodies = append(bodies, string(body[:at])+" "+genMatch(tree.Simplify(), rnd, 0)+" "+string(body[at:]))
			}
			view := suffixProofView(bodies[0])
			for i, p := range g.patterns {
				if g.pf.proofs[i] != nil && g.pf.proofs[i].provesEmpty(view) {
					proved++
					if p.re.MatchString(bodies[0]) {
						t.Fatalf("%s: proof dropped %s", name, p.name)
					}
				}
			}
			for _, content := range bodies {
				got := matchPatternsPreFiltered(g.pf, g.patterns, content)
				want := matchPatternsPreFiltered(plain, g.patterns, content)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: findings differ with proofs enabled", name)
				}
				inserted += len(got)
			}
		}
		if proved == 0 || inserted == 0 {
			t.Fatalf("%s: no proof exercised (proved=%d findings=%d)", name, proved, inserted)
		}
		t.Logf("%s proved-empty=%d findings-compared=%d", name, proved, inserted)
	}
}

// The prefilter reverses the folded text it already has instead of folding the
// reversed text again. Both must agree, including invalid UTF-8.
func TestResponseSuffixReverseFoldIdentity(t *testing.T) {
	rnd := rand.New(rand.NewSource(11)) // #nosec G404 -- reproducible corpus.
	for i := 0; i < 5000; i++ {
		s := suffixDiffText(rnd)
		r := []rune(s)
		slices.Reverse(r)
		if got := reverseResponseText(s); got != string(r) {
			t.Fatalf("reverse(%q)=%q want %q", s, got, string(r))
		}
		if a, b := reverseResponseText(responseSimpleFold(s)), responseSimpleFold(reverseResponseText(s)); a != b {
			t.Fatalf("fold and reverse do not commute for %q", s)
		}
	}
}

func TestResponseSuffixFoldViewOffsets(t *testing.T) {
	// Non-ASCII runes whose fold keeps their width share offsets.
	if v := suffixProofView("中文 \u00a9 alpha"); !v.sameOffsets {
		t.Fatal("width-preserving fold must use shared offsets")
	}
	// Kelvin sign and long s shrink when folded and need mapping. Duplicate
	// offsets from different anchors map to the same content offset.
	forward := "\u212aey \u017fecret"
	v := newResponseFoldView(forward, responseSimpleFold(forward))
	offsets := []int{0, 0, 1, 4, 5}
	if v.sameOffsets || !v.contentOffsets(offsets) || !slices.Equal(offsets, []int{0, 0, 3, 6, 8}) {
		t.Fatalf("shrinking fold mapped to %v", offsets)
	}
	proof := newResponseSuffixProof(regexp.MustCompile(`(?i)key.*secret`))
	if proof.provesEmpty(suffixProofView(forward)) {
		t.Fatal("folded match must not be proved empty")
	}
	// A mid-rune offset or a fold that disagrees with its text is
	// inconclusive, never negative.
	if newResponseFoldView("\u00e9\u212a", responseSimpleFold("\u00e9\u212a")).contentOffsets([]int{1}) {
		t.Fatal("mid-rune offset must be rejected")
	}
	if newResponseFoldView("TERCES", "TERCES\u00e9").contentOffsets([]int{6}) {
		t.Fatal("offset beyond the text must be rejected")
	}
	// Long enough that the candidate cap admits both candidates, so the
	// rejection comes from the offset walk.
	pad := strings.Repeat(" ", 58)
	if newResponseSuffixProof(regexp.MustCompile(`secret`)).provesEmpty(newResponseFoldView("terces"+pad, "TERCES"+pad+"TERCES\u00e9")) {
		t.Fatal("unusable offsets must run the original matcher")
	}
}

// Filters built without proofs keep alignment when the memo removes a known
// negative pattern, and still produce the full matcher's findings.
func TestResponseSuffixMemoWithoutProofs(t *testing.T) {
	p := &compiledPattern{name: "first", re: regexp.MustCompile(`alpha.*suffix`)}
	q := &compiledPattern{name: "second", re: regexp.MustCompile(`beta.*ending`)}
	p.responseMemoRegexp = p.re // q stays ineligible, so it always remains
	pats := []*compiledPattern{p, q}
	plain := &responsePreFilter{gates: newResponsePreFilter(pats).gates}
	pad := strings.Repeat(" ", responseMemoMinBytes)
	memo := newResponseMatchMemo(len(pad) + 64)
	if got := memo.match(plain, pats, pad+"beta"); len(got) != 0 {
		t.Fatal("negative has findings")
	}
	for _, content := range []string{pad + "beta", pad + "beta ending alpha suffix"} {
		if got, want := memo.match(plain, pats, content), matchPatternsAgainst(pats, content); !reflect.DeepEqual(got, want) {
			t.Fatal("memo parity changed without proofs")
		}
	}
}
