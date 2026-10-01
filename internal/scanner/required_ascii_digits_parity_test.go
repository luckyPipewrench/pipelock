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

func TestRequiredASCIIDigitProofBranches(t *testing.T) {
	for _, tt := range []struct {
		expression string
		want       uint8
	}{
		{`batch7item42`, 3},
		{`(?i)batch7`, 1},
		{`\b\d{3}-\d{2}-\d{4}\b`, 9},
		{`\b\d{4}(?:[- ]?\d){11,15}\b`, 15},
		{`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`, 2},
		{`[01][3-7]`, 2},
		{`[0-9A]`, 0},
		{`[0-9０]`, 0},
		{`\p{Nd}`, 0},
		{`\p{N}`, 0},
		{`(?:\d|\p{Nd})`, 0},
		{`１２`, 0},
		{`١٢`, 0},
		{`(?i:K)7`, 1},
		{`(?:a7|b88)`, 1},
		{`(?:a7|ordinary)`, 0},
		{`(?:x[0-9]{2}){0,5}`, 0},
		{`(?:x[0-9]{2}){3,5}`, 6},
		{`(?:x[0-9]{2})+`, 2},
		{`(?:x[0-9]{2})*`, 0},
		{`(?:x[0-9]{2})?`, 0},
		{`(?:|[0-9]{2})`, 0},
		{`[^\D]`, 1},
		{`(?i)[[:digit:]]`, 1},
		{`(?:[0-9]{200}){2}`, maxRequiredASCIIDigits},
		{`[0-9]{1000}`, maxRequiredASCIIDigits},
		{``, 0},
		{`^$`, 0},
		{`[`, 0},
	} {
		t.Run(tt.expression, func(t *testing.T) {
			if got := regexpMinASCIIDigits(tt.expression); got != tt.want {
				t.Fatalf("digit proof for %q = %d, want %d", tt.expression, got, tt.want)
			}
		})
	}
	for r := '0'; r <= '9'; r++ {
		if unicode.SimpleFold(r) != r {
			t.Fatalf("ASCII digit %q has a nontrivial Unicode fold orbit", r)
		}
	}
}

func TestRequiredASCIIDigitProofUnknownShapes(t *testing.T) {
	digit := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{'1'}}
	for _, tree := range []*syntax.Regexp{
		nil,
		{Op: syntax.OpCapture},
		{Op: syntax.OpPlus},
		{Op: syntax.OpRepeat, Min: 1, Max: 1},
		{Op: syntax.OpRepeat, Min: 2, Max: 1, Sub: []*syntax.Regexp{digit}},
		{Op: syntax.OpConcat},
		{Op: syntax.OpAlternate},
		{Op: syntax.OpLiteral},
		{Op: syntax.OpEmptyMatch},
		{Op: syntax.OpNoMatch},
		{Op: syntax.OpAnyChar},
		{Op: syntax.OpCharClass},
		{Op: syntax.OpCharClass, Rune: []rune{'1'}},
		{Op: syntax.OpCharClass, Rune: []rune{'9', '0'}},
		{Op: syntax.OpCharClass, Rune: []rune{'0', '9', 'A', 'Z'}},
		{Op: syntax.OpCharClass, Rune: []rune{'/', '9'}},
	} {
		if got := regexpTreeMinASCIIDigits(tree); got != 0 {
			t.Fatalf("uncertain syntax node established digit proof %d: %#v", got, tree)
		}
	}
	if got := regexpTreeMinASCIIDigits(&syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune(strings.Repeat("1", 300))}); got != maxRequiredASCIIDigits {
		t.Fatalf("literal count did not saturate downward: %d", got)
	}
}

func TestRequiredASCIIDigitProofSaturation(t *testing.T) {
	for _, tt := range []struct {
		left, right, want uint8
	}{
		{0, 0, 0}, {3, 4, 7}, {200, 55, 255}, {200, 56, 255}, {255, 255, 255},
	} {
		if got := addASCIIDigitMinimum(tt.left, tt.right); got != tt.want {
			t.Fatalf("saturating sum %d+%d = %d, want %d", tt.left, tt.right, got, tt.want)
		}
	}
	for _, tt := range []struct {
		minimum uint8
		count   int
		want    uint8
	}{
		{0, 1000, 0},
		{3, 0, 0},
		{3, -1, 0},
		{3, 4, 12},
		{3, 85, 255},
		{3, 86, 255},
		{255, int(^uint(0) >> 1), 255},
	} {
		if got := multiplyASCIIDigitMinimum(tt.minimum, tt.count); got != tt.want {
			t.Fatalf("saturating product %d*%d = %d, want %d", tt.minimum, tt.count, got, tt.want)
		}
	}
	for _, tt := range []struct {
		text    string
		minimum uint8
		want    bool
	}{
		{"", 0, true},
		{"", 1, false},
		{"ordinary", 2, false},
		{"v1", 1, true},
		{"batch12", 2, true},
		{"batch1", 2, false},
		{"１２١٢", 1, false},
		{strings.Repeat("1", 254), 255, false},
		{strings.Repeat("1", 255), 255, true},
		{strings.Repeat("1", 300), 255, true},
		{"\xff1\x002", 2, true},
	} {
		if got := hasMinimumASCIIDigits(tt.text, tt.minimum); got != tt.want {
			t.Fatalf("count for %q at minimum %d = %v, want %v", tt.text, tt.minimum, got, tt.want)
		}
	}
}

func TestRequiredASCIIDigitEffectiveGrammar(t *testing.T) {
	three := regexp.MustCompile(`batch[0-9]{3}`)
	one := regexp.MustCompile(`batch[0-9]`)
	unicodeDigits := regexp.MustCompile(`number\p{Nd}+`)
	for _, tt := range []struct {
		re, body *regexp.Regexp
		want     uint8
	}{
		{nil, nil, 0},
		{three, nil, 3},
		{three, one, 1},
		{one, three, 1},
		{three, unicodeDigits, 0},
		{unicodeDigits, three, 0},
	} {
		if got := patternMinASCIIDigits(tt.re, tt.body); got != tt.want {
			t.Fatalf("effective grammar minimum = %d, want %d", got, tt.want)
		}
	}
}

func TestRequiredASCIIDigitCompiledDefaults(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	wanted := map[string]uint8{
		"Social Security Number": 9, "Credit Card Number": 15, "IBAN": 2, "Ethereum Private Key": 1,
		"Discord Bot Token": 0, "Twilio API Key": 0, "Bitcoin WIF Private Key": 0,
		"Credential in URL": 0, "Environment Variable Secret": 0,
	}
	seen := 0
	for _, p := range sc.dlpPatterns {
		if p.minASCIIDigits != patternMinASCIIDigits(p.re, p.withoutLeftBoundary) {
			t.Fatalf("constructor digit proof differs for %s", p.name)
		}
		if want, ok := wanted[p.name]; ok {
			seen++
			if p.minASCIIDigits != want {
				t.Fatalf("%s digit minimum = %d, want %d", p.name, p.minASCIIDigits, want)
			}
		}
	}
	if seen != len(wanted) {
		t.Fatalf("checked %d of %d named default digit proofs", seen, len(wanted))
	}
	for _, p := range sc.core.dlpPatterns {
		if p.minASCIIDigits != patternMinASCIIDigits(p.re, p.withoutLeftBoundary) {
			t.Fatalf("core constructor digit proof differs for %s", p.name)
		}
	}
}

func TestRequiredASCIIDigitFrozenSpanParity(t *testing.T) {
	expressions := []string{
		`batch[0-9]{2}`, `(?:v[0-9])?ordinary`, `number\p{Nd}+`, `serial１２`, `serial١٢`,
		`(?:batch[0-9]{2}|ordinary)`, `(?:item[0-9]{2}){0,3}`, `(?i:k)[0-9]{2}`,
		`mark[0-9]{300}`, `(?:|[0-9]{2})`,
	}
	inputs := []string{
		"", "ordinary", "batch12", "batch1", "batch１２", "batch١٢", "v7ordinary",
		"number١٢", "number१२", "number１２", "serial１２", "serial١٢", "K12", "K12",
		"item12", "item１２", "batch1 2", "batch1\n2", "batch1\u200B2", "\xffbatch12",
		"mark" + strings.Repeat("1", 254), "mark" + strings.Repeat("1", 255), "mark" + strings.Repeat("1", 300),
	}
	rnd := rand.New(rand.NewSource(98231)) // #nosec G404 -- deterministic inert grammar corpus.
	matched, missed, proved, unproved := 0, 0, 0, 0
	for _, expression := range expressions {
		p := &compiledPattern{re: regexp.MustCompile(expression)}
		p.minASCIIDigits = patternMinASCIIDigits(p.re, nil)
		if p.minASCIIDigits > 0 {
			proved++
		} else {
			unproved++
		}
		tree, err := syntax.Parse(expression, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		corpus := append([]string(nil), inputs...)
		for range 64 {
			generated := genMatch(tree.Simplify(), rnd, 0)
			corpus = append(corpus, generated, strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' {
					return -1
				}
				return r
			}, generated))
		}
		for _, raw := range corpus {
			cleaned := normalize.ForDLP(raw)
			compacted, offsets := compactTextDLPWhitespaceWithOffsets(cleaned)
			for _, view := range [][2]string{{raw, raw}, {cleaned, raw}, {compacted, cleaned}} {
				gotStart, gotEnd, gotOK := p.matchSpanInView(view[0], view[1])
				wantStart, wantEnd, wantOK := referenceRequiredEqualsMatchSpanInView(p, view[0], view[1])
				if gotStart != wantStart || gotEnd != wantEnd || gotOK != wantOK {
					t.Fatalf("digit span differs for %q on %q: got (%d,%d,%v), want (%d,%d,%v)", expression, view[0], gotStart, gotEnd, gotOK, wantStart, wantEnd, wantOK)
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
				t.Fatalf("digit joined span differs for %q on %q", expression, compacted)
			}
		}
	}
	if matched == 0 || missed == 0 || proved == 0 || unproved == 0 {
		t.Fatalf("vacuous digit parity: matched=%d missed=%d proved=%d unproved=%d", matched, missed, proved, unproved)
	}
}

func TestRequiredASCIIDigitValidatorsKeepLaterAcceptedSpan(t *testing.T) {
	p := &compiledPattern{re: regexp.MustCompile(`batch[0-9]{2}`)}
	p.minASCIIDigits = patternMinASCIIDigits(p.re, nil)
	p.validate = func(candidate string) bool { return candidate != "batch00" }
	p.validateAt = func(view string, start, end int) bool { return view[start:end] != "batch11" }
	p.validateJoined = func(joined string, start, end int, _ string, _ []int) bool {
		return joined[start:end] != "batch22"
	}
	matched, missed := 0, 0
	for _, source := range []string{"ordinary", "batch1", "batch00 batch11 batch22 batch33", "batch0 0 batch1 1 batch2 2 batch3 3"} {
		compacted, offsets := compactTextDLPWhitespaceWithOffsets(source)
		gotStart, gotEnd, gotOK := p.matchSpanInJoinedView(compacted, source, offsets)
		wantStart, wantEnd, wantOK := referenceRequiredEqualsMatchSpanInJoinedView(p, compacted, source, offsets)
		if gotStart != wantStart || gotEnd != wantEnd || gotOK != wantOK {
			t.Fatalf("digit validator parity differs for %q", source)
		}
		if gotOK {
			matched++
			if compacted[gotStart:gotEnd] != "batch33" {
				t.Fatalf("digit validator accepted rejected candidate %q", compacted[gotStart:gotEnd])
			}
		} else {
			missed++
		}
	}
	if matched == 0 || missed == 0 {
		t.Fatalf("vacuous digit validator parity: matched=%d missed=%d", matched, missed)
	}
}

func TestRequiredASCIIDigitConfiguredOrderCompleteResultParity(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "digit pair", Regex: `batch[0-9]{2}`, Severity: config.SeverityHigh},
		{Name: "unicode digit", Regex: `number\p{Nd}+`, Severity: config.SeverityHigh, Action: config.ActionWarn},
		{Name: "optional digit", Regex: `(?:v[0-9])?ordinary`, Severity: config.SeverityHigh},
	}
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		cfg.DLP.Patterns = nil
		for _, index := range order {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, patterns[index])
		}
		guarded, reference := MustNew(cfg), MustNew(cfg)
		t.Cleanup(guarded.Close)
		t.Cleanup(reference.Close)
		for _, group := range [][]*compiledPattern{reference.dlpPatterns, reference.core.dlpPatterns} {
			for _, p := range group {
				p.requiresEquals = false
				p.minASCIIDigits = 0
			}
		}
		var gotWarns, wantWarns []string
		guarded.SetDLPWarnHook(func(_ context.Context, name, severity string) { gotWarns = append(gotWarns, name+":"+severity) })
		reference.SetDLPWarnHook(func(_ context.Context, name, severity string) { wantWarns = append(wantWarns, name+":"+severity) })
		clean, enforced, warned := 0, 0, 0
		for _, input := range []string{"", "plain text", "ordinary", "v7ordinary", "batch12", "batch1", "batch１２", "batch١٢", "number١٢", "number１２", "number१२", "batch12 number١٢", "\xff\x00plain text"} {
			gotWarns, wantWarns = nil, nil
			got := guarded.ScanTextForDLP(context.Background(), input)
			want := reference.ScanTextForDLP(context.Background(), input)
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotWarns, wantWarns) {
				t.Fatalf("full digit result differs in order %v on %q: got %#v, want %#v; warns %v/%v", order, input, got, want, gotWarns, wantWarns)
			}
			if got.Clean {
				clean++
			}
			enforced += len(got.Matches)
			warned += len(got.InformationalMatches)
		}
		if clean == 0 || enforced == 0 || warned == 0 {
			t.Fatalf("vacuous full digit parity: clean=%d enforced=%d warned=%d", clean, enforced, warned)
		}
	}
}
