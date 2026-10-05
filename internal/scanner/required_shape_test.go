// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// testRand is a deterministic splitmix64 sequence, so every generated corpus
// is repeatable from its seed.
type testRand struct{ state uint64 }

func newTestRand(seed uint64) *testRand { return &testRand{state: seed} }

func (r *testRand) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// IntN returns a value in [0, n) for n > 0. Modulo bias is irrelevant for
// test corpus generation.
func (r *testRand) IntN(n int) int {
	if n <= 0 {
		panic("testRand.IntN: n must be positive")
	}
	for {
		if v := int(r.next() >> 1); v >= 0 {
			return v % n
		}
	}
}

// runeIn returns a rune in [lo, hi].
func (r *testRand) runeIn(lo, hi rune) rune {
	offset := r.IntN(int(hi-lo) + 1)
	for candidate := lo; candidate < hi; candidate++ {
		if offset == 0 {
			return candidate
		}
		offset--
	}
	return hi
}

// shapeGateSubject is one compiled grammar with the gate derived from it.
type shapeGateSubject struct {
	name string
	re   *regexp.Regexp
	tree *syntax.Regexp
	gate *regexShapeGate
}

// Extra grammars widen the analyzer's coverage beyond the shipped patterns:
// operator-configured patterns go through the same analysis.
var shapeGateExtraGrammars = []string{
	`\b[a-z]{3,5}\b`,
	`\bab(?:cd|ef)[0-9]{2}\b`,
	`x(?:ab|cd)+y`,
	`[0-9]{4}`,
	`\b(?:sk|ks)[a-f]{4}\b`,
	`c{2,}(?-i:ab)`,
	`k{3}s{2}`,
	`\b\d{2}(?:[-.]\d{2}){2}\b`,
	`(?:q[0-9]{3}|z_[a-z]{2})!`,
	`\bAKIA[0-9A-Z]{16}\b`,
	`(?:ab){2,3}`,
	`\b_[a-z_]{2,4}\b`,
}

func shapeGateSubjects(t testing.TB) []shapeGateSubject {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var subjects []shapeGateSubject
	add := func(name string, re *regexp.Regexp, gate *regexShapeGate) {
		tree, err := syntax.Parse(re.String(), syntax.Perl)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		subjects = append(subjects, shapeGateSubject{name: name, re: re, tree: tree, gate: gate})
	}
	for _, p := range s.dlpPatterns {
		if p.shapeGate != nil {
			add(p.name, p.re, p.shapeGate)
		}
	}
	for _, p := range s.core.dlpPatterns {
		if p.shapeGate != nil {
			add("core "+p.name, p.re, p.shapeGate)
		}
	}
	for _, expr := range shapeGateExtraGrammars {
		re := regexp.MustCompile("(?i)" + expr)
		gate := analyzePatternMatchRequirements(re, nil).shape
		if gate == nil {
			t.Fatalf("extra grammar %q produced no gate", expr)
		}
		add(expr, re, gate)
	}
	return subjects
}

// generateShapeMatch walks the grammar and emits a string the grammar's
// consuming parts accept. Empty-width assertions are not enforced here; the
// caller checks the real regex, so a non-matching sample is still a valid
// differential input.
func generateShapeMatch(rng *testRand, tree *syntax.Regexp, b *strings.Builder) {
	switch tree.Op {
	case syntax.OpLiteral:
		for _, r := range tree.Rune {
			if tree.Flags&syntax.FoldCase != 0 {
				orbit := []rune{r}
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					orbit = append(orbit, f)
				}
				r = orbit[rng.IntN(len(orbit))]
			}
			b.WriteRune(r)
		}
	case syntax.OpCharClass:
		if len(tree.Rune) == 0 {
			return
		}
		i := rng.IntN(len(tree.Rune)/2) * 2
		b.WriteRune(rng.runeIn(tree.Rune[i], tree.Rune[i+1]))
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		b.WriteByte('a')
	case syntax.OpCapture, syntax.OpConcat:
		for _, sub := range tree.Sub {
			generateShapeMatch(rng, sub, b)
		}
	case syntax.OpAlternate:
		generateShapeMatch(rng, tree.Sub[rng.IntN(len(tree.Sub))], b)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		lo, hi := 0, 3
		switch tree.Op {
		case syntax.OpPlus:
			lo = 1
		case syntax.OpQuest:
			hi = 1
		case syntax.OpRepeat:
			lo, hi = tree.Min, tree.Max
			if hi < 0 {
				hi = lo + 6
			}
		}
		for range lo + rng.IntN(hi-lo+1) {
			generateShapeMatch(rng, tree.Sub[0], b)
		}
	}
}

// Contexts around a generated match: word and non-word ASCII neighbors, the
// case-fold runes, other non-ASCII runes and invalid UTF-8.
var shapeGateContexts = []string{
	"", " ", "a", "Z", "0", "9", "_", "-", ".", "=", "\"", ":", "/",
	"\u00e9", "\u017f", "\u212a", "\xff", "\xc5", "\u200b", "\ufffd", "ab12", "x\n",
}

// shapeGateDifferential checks admits against the real regex. It returns the
// number of texts the regex matched but admits rejected, and the number of
// texts the regex matched at all.
func shapeGateDifferential(t *testing.T, subjects []shapeGateSubject, rounds int, admits func(shapeGateSubject, string) bool) (violations, positives map[string]int) {
	t.Helper()
	violations, positives = make(map[string]int), make(map[string]int)
	rng := newTestRand(20261004)
	check := func(subject shapeGateSubject, text string) {
		if !subject.re.MatchString(text) {
			return
		}
		positives[subject.name]++
		if !admits(subject, text) {
			if violations[subject.name] == 0 {
				t.Logf("gate rejected a match: %s on %q", subject.name, text)
			}
			violations[subject.name]++
		}
	}
	for _, subject := range subjects {
		for range rounds {
			var b strings.Builder
			generateShapeMatch(rng, subject.tree, &b)
			match := b.String()
			left := shapeGateContexts[rng.IntN(len(shapeGateContexts))]
			right := shapeGateContexts[rng.IntN(len(shapeGateContexts))]
			check(subject, left+match+right)
			// Adversarial mutations of a real match: truncate, extend with
			// a class neighbor, split with a separator, and inject a fold rune.
			if len(match) > 1 {
				cut := 1 + rng.IntN(len(match)-1)
				check(subject, left+match[:cut]+right)
				check(subject, match[:cut]+shapeGateContexts[rng.IntN(len(shapeGateContexts))]+match[cut:])
				check(subject, match[:cut]+"\u017f"+match[cut:])
			}
			check(subject, match+match)
			check(subject, strings.ToUpper(match))
			check(subject, strings.ToLower(match))
			check(subject, "x"+match+"0"+match)
		}
	}
	return violations, positives
}

func realShapeGate(subject shapeGateSubject, text string) bool {
	return subject.gate.admits(text)
}

func TestRegexShapeGateNeverRejectsAMatch(t *testing.T) {
	subjects := shapeGateSubjects(t)
	violations, positives := shapeGateDifferential(t, subjects, 400, realShapeGate)
	for _, subject := range subjects {
		if violations[subject.name] != 0 {
			t.Errorf("%s: gate rejected %d matching texts", subject.name, violations[subject.name])
		}
		// A differential that never produced a match proves nothing.
		if positives[subject.name] < 50 {
			t.Errorf("%s: only %d matching samples; generator does not exercise the gate", subject.name, positives[subject.name])
		}
	}
}

// TestRegexShapeGateDifferentialCatchesWrongGates proves the differential is
// not vacuous: deliberately wrong gates, including single-component off-by-one
// errors, must be caught.
func TestRegexShapeGateDifferentialCatchesWrongGates(t *testing.T) {
	subjects := shapeGateSubjects(t)
	wrong := map[string]func(shapeGateSubject, string) bool{
		"reject everything": func(shapeGateSubject, string) bool { return false },
		"minimum length one too high": func(subject shapeGateSubject, text string) bool {
			g := *subject.gate
			g.minLen++
			return g.admits(text)
		},
		"fold runes ignored": func(subject shapeGateSubject, text string) bool {
			g := *subject.gate
			g.nonASCII = nil
			return g.admits(text)
		},
		"digit floor one too high": func(subject shapeGateSubject, text string) bool {
			g := *subject.gate
			if g.minDigits == 0 {
				return g.admits(text)
			}
			g.minDigits++
			return g.admits(text)
		},
		"whole-word maximum one too low": func(subject shapeGateSubject, text string) bool {
			g := *subject.gate
			if g.wholeWord && g.maxLen > 0 {
				g.maxLen--
			}
			return g.admits(text)
		},
		"first position class dropped a byte": func(subject shapeGateSubject, text string) bool {
			g := *subject.gate
			if len(g.positions) > 0 {
				g.positions = append([]asciiByteSet(nil), g.positions...)
				for b := byte(0); b < 128; b++ {
					if g.positions[0].has(b) {
						g.positions[0][b/64] &^= uint64(1) << (b % 64)
						break
					}
				}
			}
			return g.admits(text)
		},
		"literal requirement replaced": func(subject shapeGateSubject, text string) bool {
			g := *subject.gate
			if len(g.literals) > 0 {
				g.literals = []string{"\x01never\x01"}
			}
			return g.admits(text)
		},
	}
	for name, admits := range wrong {
		t.Run(name, func(t *testing.T) {
			violations, _ := shapeGateDifferential(t, subjects, 200, admits)
			total := 0
			for _, count := range violations {
				total += count
			}
			if total == 0 {
				t.Fatalf("differential accepted a deliberately wrong gate (%s)", name)
			}
		})
	}
}

func TestRegexShapeGateRejectsUngatableGrammars(t *testing.T) {
	for _, expr := range []string{
		`.+`, `\S{5}`, `\pL{3}`, `[^a]{3}`, `a*`, `\x{FFFD}abc`, `[\x{100}-\x{200}]{4}`, `(?:)`, `\b`,
	} {
		re := regexp.MustCompile("(?i)" + expr)
		if gate := analyzePatternMatchRequirements(re, nil).shape; gate != nil {
			t.Errorf("%q: expected no gate, got %+v", expr, gate)
		}
	}
	// A boundary-free twin grammar disables the gate.
	re := regexp.MustCompile(`(?i)\bab[0-9]{4}\b`)
	if gate := analyzePatternMatchRequirements(re, regexp.MustCompile(`(?i)ab[0-9]{4}`)).shape; gate != nil {
		t.Errorf("gate kept despite boundary-free grammar")
	}
	// A literal prefix leaves skipping to the regexp engine.
	if gate := analyzePatternMatchRequirements(regexp.MustCompile(`0x[0-9a-f]{8}`), nil).shape; gate != nil {
		t.Errorf("gate kept despite literal prefix")
	}
}

// TestRegexShapeGateSkipsReceiptPatterns pins the speed claim: the costly
// prefix-less patterns are gated and the gate rules them out on a receipt.
func TestRegexShapeGateSkipsReceiptPatterns(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"IBAN": true, "Credit Card Number": true, "Social Security Number": true,
		"Twilio API Key": true, "Bitcoin WIF Private Key": true, "Discord Bot Token": true,
		"Stripe Key": true, "Vercel Token": true,
	}
	for _, p := range s.dlpPatterns {
		if !want[p.name] {
			continue
		}
		delete(want, p.name)
		if p.shapeGate == nil {
			t.Errorf("%s: no shape gate", p.name)
			continue
		}
		if p.shapeGate.admits(benchReceipt) {
			t.Errorf("%s: gate admits the receipt", p.name)
		}
		if p.re.MatchString(benchReceipt) {
			t.Errorf("%s: regex matches the receipt fixture", p.name)
		}
	}
	for name := range want {
		t.Errorf("pattern %s not found in defaults", name)
	}
}

func FuzzRegexShapeGate(f *testing.F) {
	f.Add(benchReceipt)
	f.Add("SK0123456789abcde" + "f0123456789abcdef") // split so secret scanners skip the fake value
	f.Add("GB82WEST123" + "45698765432")             // split so secret scanners skip the fake value
	f.Add("4111 1111" + " 1111 1111")                // split so secret scanners skip the fake value
	f.Add("123-4" + "5-6789")                        // split so secret scanners skip the fake value
	f.Add("\u017fk_live_abcdefghijklmnopqrstuvwx")
	subjects := shapeGateSubjects(f)
	f.Fuzz(func(t *testing.T, text string) {
		for _, subject := range subjects {
			if !subject.gate.admits(text) && subject.re.MatchString(text) {
				t.Fatalf("%s: gate rejected matching text %q", subject.name, text)
			}
		}
	})
}

func TestIndexASCIIFold(t *testing.T) {
	cases := []struct {
		haystack, needle string
		want             int
	}{
		{"abcLIVEx", "live", 3},
		{"abc", "abcd", -1},
		{"", "a", -1},
		{"xx", "", 0},
		{"TeSt", "test", 0},
		{"te\u017ft", "test", -1},
	}
	for _, c := range cases {
		if got := indexASCIIFold(c.haystack, c.needle); got != c.want {
			t.Errorf("indexASCIIFold(%q, %q) = %d, want %d", c.haystack, c.needle, got, c.want)
		}
	}
}
