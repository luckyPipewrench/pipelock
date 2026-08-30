// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestExtractRequiredLiteralAnchors(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  []string
	}{
		{
			name:  "leading prefix fast path",
			regex: `(?i)sk-ant-[a-z0-9_-]{20,}`,
			want:  []string{"sk-ant-"},
		},
		{
			name:  "all alternation branches are covered",
			regex: `(?i)(?:live|test)_[a-z0-9]{20,}`,
			want:  []string{"live_", "test_"},
		},
		{
			name:  "bare top-level alternation covers every branch",
			regex: `(?i)sk-live-\w+|sk-test-\w+`,
			want:  []string{"sk-live-", "sk-test-"},
		},
		{
			name:  "factored provider branches retain their prefix",
			regex: `(?i)(?:AKIA|ASIA|A3T[A-Z0-9])[A-Z0-9]{16}`,
			want:  []string{"a3t", "akia", "asia"},
		},
		{
			name:  "mandatory literal after optional prefix",
			regex: `(?i)(?:prefix-)?required_[a-z0-9]+`,
			want:  []string{"required_"},
		},
		{
			name:  "keywordless branch fails closed",
			regex: `(?i)(?:mfa\.[a-z0-9]+|[a-z0-9]{24})`,
			want:  nil,
		},
		{
			name:  "empty leading branch fails closed",
			regex: `(?i)(?:fixed|)[a-z0-9]{24}`,
			want:  nil,
		},
		{
			name:  "generic credential words stay always-run",
			regex: `(?i)(?:api|passw|secret|token)[a-z0-9_]*=`,
			want:  nil,
		},
		{
			name:  "expanded generic credential words stay always-run",
			regex: `(?i)(?:api|key|password|passw|secret|token)[a-z0-9_]*=`,
			want:  nil,
		},
		{
			name:  "single generic credential word stays always-run",
			regex: `(?i)token[a-z0-9_]*=`,
			want:  nil,
		},
		{
			name:  "mixed generic and selective anchors remain gated",
			regex: `(?i)(?:token|provider_credential_)[a-z0-9_]*=`,
			want:  []string{"provider_credential_", "token"},
		},
		{
			name:  "non-ASCII custom anchors stay always-run",
			regex: `(?i)(?:sëcret|tøken)[a-z0-9_]*=`,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRequiredLiteralAnchors(tt.regex)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("extractRequiredLiteralAnchors(%q) = %v, want %v", tt.regex, got, tt.want)
			}
		})
	}
}

func TestDLPPreFilter_AlternationAnchorsRemainLoadBearing(t *testing.T) {
	patterns := []*compiledPattern{
		mustCompilePattern(t, "provider alternation", `(?i)(?:live|test)_[a-z0-9]{20,}`),
		mustCompilePattern(t, "keywordless branch", `(?i)(?:mfa\.[a-z0-9]+|[a-z0-9]{24})`),
	}
	pf := newDLPPreFilter(patterns)

	for _, branch := range []string{"live", "test"} {
		got := pf.patternsToCheck("prefix-" + branch + "_abcdefghijklmnopqrstuvwxyz")
		if !reflect.DeepEqual(got, []int{0, 1}) {
			t.Fatalf("matching %q branch candidates = %v, want [0 1]", branch, got)
		}
	}
	if got := pf.patternsToCheck("ordinary-weather-forecast"); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("clean candidates = %v, want only always-run pattern [1]", got)
	}
}

func TestDLPPreFilter_BareTopLevelAlternationCannotSkipBranch(t *testing.T) {
	patterns := []*compiledPattern{
		mustCompilePattern(t, "bare alternation", `(?i)sk-live-\w+|sk-test-\w+`),
	}
	pf := newDLPPreFilter(patterns)

	for _, text := range []string{
		"sk-live-credential",
		"sk-test-credential",
		"sk-live-credential and sk-test-credential",
	} {
		if !patterns[0].re.MatchString(text) {
			t.Fatalf("test pattern does not match %q", text)
		}
		if got := pf.patternsToCheck(text); !reflect.DeepEqual(got, []int{0}) {
			t.Fatalf("matching input %q candidates = %v, want [0]", text, got)
		}
	}
}

func TestRequiredLiteralAnchorConservativeFallbacks(t *testing.T) {
	t.Run("malformed regex", func(t *testing.T) {
		if got := extractRequiredLiteralAnchors(`(`); got != nil {
			t.Fatalf("malformed regex anchors = %v, want nil", got)
		}
	})

	t.Run("malformed syntax nodes", func(t *testing.T) {
		tests := []struct {
			name string
			re   *syntax.Regexp
		}{
			{name: "empty literal", re: &syntax.Regexp{Op: syntax.OpLiteral}},
			{name: "capture without child", re: &syntax.Regexp{Op: syntax.OpCapture}},
			{name: "plus without child", re: &syntax.Regexp{Op: syntax.OpPlus}},
			{name: "optional repeat", re: &syntax.Regexp{Op: syntax.OpRepeat, Min: 0}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				anchors, _ := leadingLiteralAnchors(tt.re)
				if tt.name == "empty literal" {
					if !reflect.DeepEqual(anchors, []string{""}) {
						t.Fatalf("anchors = %v, want empty literal", anchors)
					}
					return
				}
				if anchors != nil {
					t.Fatalf("anchors = %v, want nil", anchors)
				}
			})
		}
	})

	t.Run("bounded expansion", func(t *testing.T) {
		if got := combineLiteralAlternatives(nil, []string{"a"}); got != nil {
			t.Fatalf("empty left expansion = %v, want nil", got)
		}
		many := make([]string, 33)
		if got := combineLiteralAlternatives(many, []string{"a", "b"}); got != nil {
			t.Fatalf("oversized expansion = %v, want nil", got)
		}
	})

	t.Run("repeat handling", func(t *testing.T) {
		literal := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{'x'}}
		fixed := &syntax.Regexp{Op: syntax.OpRepeat, Min: 2, Max: 2, Sub: []*syntax.Regexp{literal}}
		if got, complete := leadingLiteralAnchors(fixed); !complete || !reflect.DeepEqual(got, []string{"xx"}) {
			t.Fatalf("fixed repeat = %v, %v; want [xx], true", got, complete)
		}
		variable := &syntax.Regexp{Op: syntax.OpRepeat, Min: 2, Max: 3, Sub: []*syntax.Regexp{literal}}
		if got, complete := leadingLiteralAnchors(variable); complete || !reflect.DeepEqual(got, []string{"x"}) {
			t.Fatalf("variable repeat = %v, %v; want [x], false", got, complete)
		}
	})

	t.Run("required anchor malformed nodes", func(t *testing.T) {
		for _, re := range []*syntax.Regexp{
			{Op: syntax.OpLiteral},
			{Op: syntax.OpCapture},
			{Op: syntax.OpPlus},
		} {
			if got := requiredLiteralAnchors(re); got != nil {
				t.Fatalf("required anchors for %v = %v, want nil", re.Op, got)
			}
		}
	})

	t.Run("shortest string length", func(t *testing.T) {
		tests := []struct {
			name   string
			values []string
			want   int
		}{
			{name: "empty slice", want: 0},
			{name: "empty string", values: []string{"long", ""}, want: 0},
			{name: "shortest non-empty", values: []string{"long", "xy", "mid"}, want: 2},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := shortestStringLength(tt.values); got != tt.want {
					t.Fatalf("shortestStringLength(%v) = %d, want %d", tt.values, got, tt.want)
				}
			})
		}
	})
}

// genMatch walks a parsed regex tree and produces a random string intended to
// match it. Zero-width assertions emit nothing and are reconciled by rejecting
// non-matching samples at the call site. Fold-case literals randomly pick a
// case variant, which is exactly the axis the ASCII-anchor guard must survive.
func genMatch(re *syntax.Regexp, rnd *rand.Rand, depth int) string {
	if depth > 40 {
		return ""
	}
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return ""
	case syntax.OpLiteral:
		var b strings.Builder
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				r = randFold(r, rnd)
			}
			b.WriteRune(r)
		}
		return b.String()
	case syntax.OpCharClass:
		return string(randRuneFromClass(re.Rune, rnd))
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/"
		return string(letters[rnd.Intn(len(letters))])
	case syntax.OpCapture:
		return genMatch(re.Sub[0], rnd, depth+1)
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range re.Sub {
			b.WriteString(genMatch(sub, rnd, depth+1))
		}
		return b.String()
	case syntax.OpAlternate:
		return genMatch(re.Sub[rnd.Intn(len(re.Sub))], rnd, depth+1)
	case syntax.OpStar:
		return repeatGen(re.Sub[0], rnd, depth, rnd.Intn(4))
	case syntax.OpPlus:
		return repeatGen(re.Sub[0], rnd, depth, 1+rnd.Intn(3))
	case syntax.OpQuest:
		return repeatGen(re.Sub[0], rnd, depth, rnd.Intn(2))
	case syntax.OpRepeat:
		n := re.Min
		if re.Max > re.Min {
			extra := re.Max - re.Min
			if extra > 2 {
				extra = 2
			}
			n += rnd.Intn(extra + 1)
		}
		return repeatGen(re.Sub[0], rnd, depth, n)
	default:
		return ""
	}
}

func repeatGen(sub *syntax.Regexp, rnd *rand.Rand, depth, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(genMatch(sub, rnd, depth+1))
	}
	return b.String()
}

func randFold(r rune, rnd *rand.Rand) rune {
	variants := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		variants = append(variants, f)
	}
	return variants[rnd.Intn(len(variants))]
}

func randRuneFromClass(ranges []rune, rnd *rand.Rand) rune {
	// Weighted pick across the class's ranges, restricted to printable ASCII
	// where possible so generated samples stay valid URL/text bytes.
	type span struct{ lo, hi rune }
	var spans []span
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if lo < 0x20 {
			lo = 0x20
		}
		if hi > 0x7e {
			hi = 0x7e
		}
		if lo <= hi {
			spans = append(spans, span{lo, hi})
		}
	}
	if len(spans) == 0 {
		// Fall back to the first raw range start.
		return ranges[0]
	}
	s := spans[rnd.Intn(len(spans))]
	// #nosec G115 -- each span is clamped to printable ASCII above.
	return s.lo + rune(rnd.Intn(int(s.hi-s.lo)+1))
}

// TestExtractRequiredLiteralAnchors_PropertyOnRealPatterns is the load-bearing
// safety check, modelled on production: it feeds the prefilter AND the regex the
// SAME normalize.ForDLP text (exactly what every scanner call site does). For
// every generated match of a real DLP pattern, patternsToCheck must select that
// pattern. A miss is a skipped DLP scan -- the fail-open direction this must
// never take -- and covers the ToLower-vs-(?i)-fold divergence end to end.
func TestExtractRequiredLiteralAnchors_PropertyOnRealPatterns(t *testing.T) {
	s, err := New(config.Defaults())
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	rnd := rand.New(rand.NewSource(int64(0x3779b97f4a7c15))) // #nosec G404 -- repeatable test generation.
	assertPreFilterSelectsGeneratedMatches(t, "configured", s.dlpPatterns, s.dlpPreFilter, rnd)
	assertPreFilterSelectsGeneratedMatches(t, "core", s.core.dlpPatterns, s.core.dlpPreFilter, rnd)
}

func assertPreFilterSelectsGeneratedMatches(
	t *testing.T,
	group string,
	patterns []*compiledPattern,
	pf *dlpPreFilter,
	rnd *rand.Rand,
) {
	t.Helper()
	always := map[int]bool{}
	for _, i := range pf.alwaysRun {
		always[i] = true
	}

	for i, p := range patterns {
		tree, err := syntax.Parse(p.re.String(), syntax.Perl)
		if err != nil {
			t.Fatalf("%s/%s: parse: %v", group, p.name, err)
		}
		tree = tree.Simplify()
		matched := 0
		for attempt := 0; attempt < 40000 && matched < 400; attempt++ {
			cand := genMatch(tree, rnd, 0)
			if cand == "" {
				continue
			}
			// Model production faithfully: the scanner feeds the prefilter AND
			// the regex the SAME normalize.ForDLP text.
			text := normalize.ForDLP(cand)
			if !p.re.MatchString(text) {
				continue
			}
			matched++
			selected := false
			for _, idx := range pf.patternsToCheck(text) {
				if idx == i {
					selected = true
					break
				}
			}
			if !selected {
				t.Fatalf("%s/%s: regex matches normalized %q but prefilter did not select it (fail-open)",
					group, p.name, text)
			}
		}
		if matched == 0 {
			if always[i] {
				t.Logf("%s/%s: generator produced no matching sample (always-run pattern)", group, p.name)
				continue
			}
			t.Errorf("%s/%s: anchor-gated pattern got no generated sample; fail-open property is untested",
				group, p.name)
		}
	}
}

// TestASCIIAnchorFoldClosure proves the foundational assumption behind allowing
// only ASCII anchors: for every ASCII letter L, every character C that Go's (?i)
// folds together with L must, after the scanner's ForDLP normalization plus the
// prefilter's ToLower, reduce to L. If any fold-sibling survived normalization
// without reducing to L, an input using C would match the regex while the
// prefilter's ToLower+Contains missed the anchor -- a skipped-scan fail-open.
// This is what makes the ASCII-only anchor guard sufficient for arbitrary
// patterns, not just the built-in defaults.
func TestASCIIAnchorFoldClosure(t *testing.T) {
	for L := 'a'; L <= 'z'; L++ {
		// Walk the full SimpleFold orbit of L (what (?i)L matches).
		for C := unicode.SimpleFold(L); C != L; C = unicode.SimpleFold(C) {
			normalized := normalize.ForDLP(string(C))
			got := strings.ToLower(normalized)
			if !strings.Contains(got, string(L)) {
				t.Errorf("fold sibling %q (U+%04X) of ASCII %q survives ForDLP+ToLower as %q; "+
					"an input using it would evade the %q anchor", string(C), C, string(L), got, string(L))
			}
		}
	}
}

func mustCompilePattern(t *testing.T, name, regex string) *compiledPattern {
	t.Helper()
	re, err := regexp.Compile(regex)
	if err != nil {
		t.Fatalf("compile test pattern: %v", err)
	}
	return &compiledPattern{name: name, re: re, severity: "high"}
}
