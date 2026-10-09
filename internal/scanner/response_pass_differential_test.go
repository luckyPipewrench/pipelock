// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The reference side of these comparisons is matchPatternsAgainst with no
// pre-filter, no proof and no memo: every pattern runs on the full text. The
// optimized side is the production pipeline. Any difference is a missed or
// reordered finding. Bodies are at least responseMemoMinBytes so proofs run.

// responsePassPureReference removes every pre-filter and memo from a private
// scanner copy so each pattern runs on the full text of every pass.
func responsePassPureReference(s *Scanner) {
	core := *s.core
	s.core = &core
	strip := func(pf **responsePreFilter, patterns *[]*compiledPattern) {
		*pf = nil
		list := append([]*compiledPattern(nil), (*patterns)...)
		for i, p := range list {
			cp := *p
			cp.responseMemoRegexp = nil
			list[i] = &cp
		}
		*patterns = list
	}
	strip(&s.core.responsePreFilter, &s.core.responsePatterns)
	strip(&s.core.responseOptSpacePreFilter, &s.core.responseOptSpacePatterns)
	strip(&s.core.responseVowelFoldPreFilter, &s.core.responseVowelFoldPatterns)
	strip(&s.responsePreFilter, &s.responsePatterns)
	strip(&s.responseOptSpacePreFilter, &s.responseOptSpacePatterns)
	strip(&s.responseVowelFoldPreFilter, &s.responseVowelFoldPatterns)
}

// responsePassBody builds a body of at least responseMemoMinBytes from random
// grammar text plus generated matches, including malformed UTF-8 and fold
// orbit members that change byte offsets.
func responsePassBody(rnd *rand.Rand, trees []*syntax.Regexp) string {
	var b strings.Builder
	target := responseMemoMinBytes + rnd.Intn(5000)
	for b.Len() < target {
		if len(trees) > 0 && rnd.Intn(40) == 0 {
			b.WriteString(genMatch(trees[rnd.Intn(len(trees))], rnd, 0))
		}
		b.WriteString(suffixDiffText(rnd))
		b.WriteString("ordinary; ")
	}
	return b.String()
}

func TestResponsePassRandomGrammarPipeline(t *testing.T) {
	rnd := rand.New(rand.NewSource(20261008)) // #nosec G404 -- reproducible corpus.
	prefixes := []string{"", "(?i)", "(?m)", "(?s)", "(?im)", "(?i)", "(?is)"}
	checks, positives, skipping := 0, 0, 0
	for attempt := 0; attempt < 120; attempt++ {
		var patterns []*compiledPattern
		var trees []*syntax.Regexp
		for k := 0; k < 3+rnd.Intn(5); k++ {
			expr := prefixes[rnd.Intn(len(prefixes))] + suffixDiffExpr(rnd, 0)
			if rnd.Intn(3) == 0 {
				expr = strings.ReplaceAll(expr, "abc", `abc\s+kss`)
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				continue
			}
			patterns = append(patterns, &compiledPattern{name: "fixture", re: re, responseMemoRegexp: re})
			if tree, err := syntax.Parse(expr, syntax.Perl); err == nil {
				trees = append(trees, tree.Simplify())
			}
		}
		if len(patterns) == 0 {
			continue
		}
		pf := newResponsePreFilter(patterns)
		for range 8 {
			content := responsePassBody(rnd, trees)
			memo := newResponseMatchMemo(len(content))
			want := matchPatternsAgainst(patterns, content)
			first := memo.match(pf, patterns, content)
			again := memo.match(pf, patterns, content)
			checks++
			if len(want) > 0 {
				positives++
			}
			if len(pf.patternsToCheck(content)) < len(patterns) {
				skipping++
			}
			if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(again, want) {
				t.Fatalf("optimized matching changed findings: first=%d again=%d want=%d", len(first), len(again), len(want))
			}
		}
	}
	if positives < checks/4 || skipping < checks/10 {
		t.Fatalf("corpus was vacuous: checks=%d positives=%d skipping=%d", checks, positives, skipping)
	}
}

func TestResponsePassCustomPatternScanParity(t *testing.T) {
	rnd := rand.New(rand.NewSource(20261009)) // #nosec G404 -- reproducible corpus.
	prefixes := []string{"", "(?i)", "(?m)", "(?s)", "(?im)"}
	dirty, total := 0, 0
	for round := range 6 {
		cfg := config.Defaults()
		cfg.Internal = nil
		var trees []*syntax.Regexp
		for range 8 {
			expr := prefixes[rnd.Intn(len(prefixes))] + suffixDiffExpr(rnd, 0)
			if _, err := regexp.Compile(expr); err != nil {
				continue
			}
			tree, err := syntax.Parse(expr, syntax.Perl)
			if err != nil {
				continue
			}
			trees = append(trees, tree.Simplify())
			cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "fixture", Regex: expr})
		}
		cfg.ResponseScanning.Enabled = round%3 != 0
		optimized, reference := MustNew(cfg), MustNew(cfg)
		responsePassPureReference(reference)
		for range 12 {
			body := responsePassBody(rnd, trees)
			got := optimized.ScanResponseWithSuppress(t.Context(), body, "", nil)
			want := reference.ScanResponseWithSuppress(t.Context(), body, "", nil)
			total++
			if !want.Clean {
				dirty++
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round %d: optimized scan changed the result: got clean=%v n=%d want clean=%v n=%d", round, got.Clean, len(got.Matches), want.Clean, len(want.Matches))
			}
		}
		optimized.Close()
		reference.Close()
	}
	if dirty < total/4 {
		t.Fatalf("corpus was vacuous: dirty=%d total=%d", dirty, total)
	}
}
