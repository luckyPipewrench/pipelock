// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
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

func TestRequiredEqualsProofBranches(t *testing.T) {
	for _, tt := range []struct {
		regex string
		want  bool
	}{
		{`label=value`, true},
		{`(?:label=value|memo=ordinary)`, true},
		{`(?:label=value|ordinary)`, false},
		{`(?:label=)?ordinary`, false},
		{`(?:label=)+ordinary`, true},
		{`(?:label=)*ordinary`, false},
		{`(?:label=){1,3}ordinary`, true},
		{`(?:label=){0,3}ordinary`, false},
		{`(?:label=){0}ordinary`, false},
		{`(?:|label=value)`, false},
		{`(?:label=value|)`, false},
		{`(?:=|[A-Z]+)`, false},
		{`[=]`, true},
		{`[=-]`, false},
		{`[^=]`, false},
		{`(?i:label)=(?-i:VALUE)`, true},
		{`(?i:K)=value`, true},
		{`(?i:K)`, false},
		{`(?:^|;)label=value`, true},
		{`(?m)^\s*(?:label|memo)\s*=\s*value$`, true},
		{`(?:label(?:=value)?|ordinary)`, false},
		{``, false},
		{`^$`, false},
		{`(`, false},
	} {
		t.Run(tt.regex, func(t *testing.T) {
			if got := regexpRequiresEquals(tt.regex); got != tt.want {
				t.Fatalf("required equals proof for %q = %v, want %v", tt.regex, got, tt.want)
			}
		})
	}
	if unicode.SimpleFold('=') != '=' {
		t.Fatal("the literal equals proof requires a singleton Unicode fold orbit")
	}
}

func TestRequiredEqualsProofUnknownShapes(t *testing.T) {
	for _, tree := range []*syntax.Regexp{
		nil,
		{Op: syntax.OpCapture},
		{Op: syntax.OpPlus},
		{Op: syntax.OpRepeat, Min: 1},
		{Op: syntax.OpConcat},
		{Op: syntax.OpAlternate},
		{Op: syntax.OpEmptyMatch},
		{Op: syntax.OpNoMatch},
		{Op: syntax.OpLiteral},
		{Op: syntax.OpAnyChar},
	} {
		if regexpTreeRequiresEquals(tree) {
			t.Fatalf("uncertain syntax node established proof: %#v", tree)
		}
	}
}

func TestRequiredEqualsProofEffectiveGrammar(t *testing.T) {
	equals := regexp.MustCompile(`label=value`)
	plain := regexp.MustCompile(`value`)
	for _, tt := range []struct {
		name string
		re   *regexp.Regexp
		body *regexp.Regexp
		want bool
	}{
		{name: "no regex"},
		{name: "ordinary equals", re: equals, want: true},
		{name: "ordinary no proof", re: plain},
		{name: "both effective grammars require equals", re: equals, body: equals, want: true},
		{name: "boundary-free grammar has no proof", re: equals, body: plain},
		{name: "outer grammar has no proof", re: plain, body: equals},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := patternRequiresEquals(tt.re, tt.body); got != tt.want {
				t.Fatalf("effective proof = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequiredEqualsProofGeneratedInertMatches(t *testing.T) {
	patterns := []string{
		`label=value`, `(?:label=value|memo=ordinary)`, `(?:label=value|ordinary)`,
		`(?:label=)?ordinary`, `(?:label=)+ordinary`, `(?:label=)*ordinary`,
		`(?:label=){1,3}ordinary`, `(?:label=){0,3}ordinary`, `(?:|label=value)`,
		`(?i:label)=(?-i:VALUE)`, `(?i:k)=value`, `(?:label(?:=value)?|ordinary)`,
	}
	rnd := rand.New(rand.NewSource(73519)) // #nosec G404 -- deterministic inert grammar corpus.
	for _, expression := range patterns {
		re := regexp.MustCompile(expression)
		tree, err := syntax.Parse(re.String(), syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		proved := patternRequiresEquals(re, nil)
		matched := 0
		for range 128 {
			raw := genMatch(tree.Simplify(), rnd, 0)
			for _, view := range []string{raw, normalize.ForDLP(raw), normalize.ForDLP(strings.ReplaceAll(raw, "=", "\uFF1D"))} {
				if !re.MatchString(view) {
					continue
				}
				matched++
				if proved && !strings.ContainsRune(view, '=') {
					t.Fatalf("required byte absent from a matching inert view: regex=%q view=%q", expression, view)
				}
			}
		}
		if matched == 0 {
			t.Fatalf("no matching samples exercised %q", expression)
		}
	}
}

func TestRequiredEqualsCompiledSpanReferenceParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{Name: "ordinary equals", Regex: `(?:label|memo)=value`, Severity: config.SeverityHigh},
		config.DLPPattern{Name: "ordinary optional", Regex: `(?:label=)?value`, Severity: config.SeverityHigh},
		config.DLPPattern{Name: "ordinary empty", Regex: `(?:label=|)`, Severity: config.SeverityHigh},
		config.DLPPattern{Name: "ordinary fold", Regex: `(?i:k)=value`, Severity: config.SeverityHigh},
	)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	inputs := []string{
		"", "ordinary text", "label=value", "memo=value", "value", "label=", "K=value",
		"K=value", "label\uFF1Dvalue", "la\u200Bbel=value", "label = value", "label=\u00e9",
		"\xff\x00ordinary", "\xfflabel=value", "label=value memo=value", "new\nlabel=value",
	}
	proved, unproved, matched, missed, genericProofs := 0, 0, 0, 0, 0
	for _, patterns := range [][]*compiledPattern{sc.dlpPatterns, sc.core.dlpPatterns} {
		for _, p := range patterns {
			if p.requiresEquals != patternRequiresEquals(p.re, p.withoutLeftBoundary) {
				t.Fatalf("constructor proof differs for %s", p.name)
			}
			if p.requiresEquals {
				proved++
			} else {
				unproved++
			}
			if p.name == "Credential in URL" || p.name == "Environment Variable Secret" {
				if !p.requiresEquals {
					t.Fatalf("canonical generic rule %s lost its required equals proof", p.name)
				}
				genericProofs++
			}
			for _, raw := range inputs {
				cleaned := normalize.ForDLP(raw)
				compacted, offsets := compactTextDLPWhitespaceWithOffsets(cleaned)
				for _, view := range [][2]string{{raw, raw}, {cleaned, raw}, {compacted, cleaned}} {
					gotStart, gotEnd, gotOK := p.matchSpanInView(view[0], view[1])
					wantStart, wantEnd, wantOK := referenceRequiredEqualsMatchSpanInView(p, view[0], view[1])
					if gotStart != wantStart || gotEnd != wantEnd || gotOK != wantOK {
						t.Fatalf("span differs for %s on %q: got (%d,%d,%v), want (%d,%d,%v)", p.name, view[0], gotStart, gotEnd, gotOK, wantStart, wantEnd, wantOK)
					}
					if gotOK {
						matched++
					} else {
						missed++
					}
				}
				gotStart, gotEnd, gotOK := p.matchSpanInJoinedView(compacted, cleaned, offsets)
				wantStart, wantEnd, wantOK := referenceRequiredEqualsMatchSpanInJoinedView(p, compacted, cleaned, offsets)
				if gotStart != wantStart || gotEnd != wantEnd || gotOK != wantOK {
					t.Fatalf("joined span differs for %s on %q", p.name, compacted)
				}
			}
		}
	}
	if proved == 0 || unproved == 0 || matched == 0 || missed == 0 || genericProofs < 2 {
		t.Fatalf("vacuous parity: proved=%d unproved=%d matched=%d missed=%d generic=%d", proved, unproved, matched, missed, genericProofs)
	}
}

func TestRequiredEqualsValidatorsKeepLaterAcceptedSpan(t *testing.T) {
	p := &compiledPattern{re: regexp.MustCompile(`item=(skip|reject|keep)`)}
	p.requiresEquals = patternRequiresEquals(p.re, p.withoutLeftBoundary)
	p.validate = func(candidate string) bool { return candidate != "item=skip" }
	p.validateAt = func(view string, start, end int) bool { return view[start:end] != "item=reject" }
	p.validateJoined = func(joined string, start, end int, _ string, _ []int) bool {
		return joined[start:end] == "item=keep"
	}
	matched, missed := 0, 0
	for _, source := range []string{"ordinary text", "item=skip item=reject item=keep", "item = skip item = reject item = keep", "item=skip"} {
		compacted, offsets := compactTextDLPWhitespaceWithOffsets(source)
		for _, joined := range []bool{false, true} {
			gotStart, gotEnd, gotOK := p.matchSpanInView(compacted, source)
			wantStart, wantEnd, wantOK := referenceRequiredEqualsMatchSpanInView(p, compacted, source)
			if joined {
				gotStart, gotEnd, gotOK = p.matchSpanInJoinedView(compacted, source, offsets)
				wantStart, wantEnd, wantOK = referenceRequiredEqualsMatchSpanInJoinedView(p, compacted, source, offsets)
			}
			if gotStart != wantStart || gotEnd != wantEnd || gotOK != wantOK {
				t.Fatalf("validator parity differs on %q (joined=%v)", source, joined)
			}
			if gotOK {
				matched++
				if compacted[gotStart:gotEnd] != "item=keep" {
					t.Fatalf("validator returned rejected span %q", compacted[gotStart:gotEnd])
				}
			} else {
				missed++
			}
		}
	}
	if matched == 0 || missed == 0 {
		t.Fatalf("vacuous validator parity: matched=%d missed=%d", matched, missed)
	}
}

func TestRequiredEqualsConfiguredOrderCompleteResultParity(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "ordinary field", Regex: `memo=value`, Severity: config.SeverityHigh},
		{Name: "ordinary warning", Regex: `(?:label=value|ordinary)`, Severity: config.SeverityHigh, Action: config.ActionWarn},
		{Name: "ordinary optional field", Regex: `(?:note=)?readable`, Severity: config.SeverityHigh},
	}
	for shift := range len(patterns) {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		cfg.DLP.Patterns = append(append([]config.DLPPattern(nil), patterns[shift:]...), patterns[:shift]...)
		guarded, reference := MustNew(cfg), MustNew(cfg)
		t.Cleanup(guarded.Close)
		t.Cleanup(reference.Close)
		for _, group := range [][]*compiledPattern{reference.dlpPatterns, reference.core.dlpPatterns} {
			for _, p := range group {
				p.requiresEquals = false
			}
		}
		var gotWarns, wantWarns []string
		guarded.SetDLPWarnHook(func(_ context.Context, name, severity string) { gotWarns = append(gotWarns, name+":"+severity) })
		reference.SetDLPWarnHook(func(_ context.Context, name, severity string) { wantWarns = append(wantWarns, name+":"+severity) })
		clean, enforced, warned := 0, 0, 0
		for _, input := range []string{"", "plain text", "ordinary", "memo=value", "label=value", "note=readable", "readable", "memo=value label=value", "memo\uFF1Dvalue", "\xff\x00plain text"} {
			gotWarns, wantWarns = nil, nil
			got := guarded.ScanTextForDLP(context.Background(), input)
			want := reference.ScanTextForDLP(context.Background(), input)
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotWarns, wantWarns) {
				t.Fatalf("full result differs at permutation %d on %q: got %#v, want %#v; warns %v/%v", shift, input, got, want, gotWarns, wantWarns)
			}
			if got.Clean {
				clean++
			}
			enforced += len(got.Matches)
			warned += len(got.InformationalMatches)
		}
		if clean == 0 || enforced == 0 || warned == 0 {
			t.Fatalf("vacuous result parity: clean=%d enforced=%d warned=%d", clean, enforced, warned)
		}
	}
}

// Frozen span matchers before the necessary-condition guards.
// Keep the full original matching and validator paths independent of the guard.
func referenceRequiredEqualsMatchSpanInView(p *compiledPattern, text, source string) (start, end int, ok bool) {
	if p.withoutLeftBoundary == nil {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			if p.accepts(text, loc[0], loc[1]) {
				return loc[0], loc[1], true
			}
		}
		return 0, 0, false
	}
	if source == text {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			bodyLoc := p.withoutLeftBoundary.FindStringIndex(text[loc[0]:loc[1]])
			if bodyLoc == nil {
				continue
			}
			start = loc[0] + bodyLoc[0]
			end = loc[0] + bodyLoc[1]
			if p.accepts(text, start, end) {
				return start, end, true
			}
		}
		return 0, 0, false
	}

	invalidSourceCandidates := p.invalidLeadingCandidates(source)
	invalidIndex := 0
	for _, loc := range p.providerCandidateSpans(text) {
		start, end = loc[0], loc[1]
		candidate := strings.ToLower(text[start:end])
		if invalidIndex < len(invalidSourceCandidates) && sameProviderCandidate(candidate, invalidSourceCandidates[invalidIndex]) {
			invalidIndex++
			continue
		}
		if p.accepts(text, start, end) {
			return start, end, true
		}
	}
	return 0, 0, false
}

func referenceRequiredEqualsMatchSpanInJoinedView(p *compiledPattern, text, source string, offsets []int) (start, end int, ok bool) {
	if p.validateJoined == nil || p.withoutLeftBoundary != nil {
		return referenceRequiredEqualsMatchSpanInView(p, text, source)
	}
	for _, loc := range p.re.FindAllStringIndex(text, -1) {
		if p.accepts(text, loc[0], loc[1]) && p.validateJoined(text, loc[0], loc[1], source, offsets) {
			return loc[0], loc[1], true
		}
	}
	return 0, 0, false
}
