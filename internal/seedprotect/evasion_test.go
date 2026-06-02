// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	"strings"
	"testing"
)

// These are red-team regression tests for named seed-phrase evasion vectors.
// Each constructs a phrase that is a valid BIP-39 12-word mnemonic (so the
// checksum holds once the evasion is normalized away) but disguised with a
// Unicode trick the detector historically ignored. Before the normalization +
// separator hardening these all evaded detection; each must now be caught with
// a valid checksum, proving the evasion was peeled rather than merely tokenized.

// homoglyphFold replaces Latin letters in s with visually identical Cyrillic
// code points that the normalize package maps back to ASCII. Only letters that
// have a confirmed lowercase Cyrillic confusable are swapped.
func homoglyphFold(s string) string {
	repl := strings.NewReplacer(
		"a", "а", // а
		"o", "о", // о
		"e", "е", // е
		"c", "с", // с
		"p", "р", // р
		"t", "т", // т
		"x", "х", // х
		"k", "к", // к
		"m", "м", // м
		"y", "у", // у
	)
	return repl.Replace(s)
}

// fullwidthFold maps ASCII letters to their fullwidth (U+FF21..) equivalents,
// which NFKC folds back to ASCII.
func fullwidthFold(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 0xFF41)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r - 'A' + 0xFF21)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// zwsp is a zero-width space (U+200B), built via rune to avoid an invisible
// literal in source (staticcheck ST1018).
var zwsp = string(rune(0x200B))

// injectZeroWidth inserts a zero-width space inside every word (after the first
// rune) without touching separators.
func injectZeroWidth(phrase string) string {
	words := strings.Split(phrase, " ")
	for i, w := range words {
		rs := []rune(w)
		if len(rs) > 1 {
			words[i] = string(rs[:1]) + zwsp + string(rs[1:])
		}
	}
	return strings.Join(words, " ")
}

func assertDetectedValid(t *testing.T, phrase, vector string) {
	t.Helper()
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatalf("%s: evaded detection entirely (expected a checksum-valid 12-word match)", vector)
	}
	for _, m := range matches {
		if m.WordCount == 12 && m.ChecksumValid {
			return
		}
	}
	t.Fatalf("%s: detected but no checksum-valid 12-word match: %+v", vector, matches)
}

func TestEvasion_CyrillicHomoglyph(t *testing.T) {
	assertDetectedValid(t, homoglyphFold(valid12), "cyrillic-homoglyph")
}

func TestEvasion_FullwidthChars(t *testing.T) {
	assertDetectedValid(t, fullwidthFold(valid12), "fullwidth-nfkc")
}

func TestEvasion_ZeroWidthInsideWords(t *testing.T) {
	assertDetectedValid(t, injectZeroWidth(valid12), "zero-width-in-word")
}

func TestEvasion_SeparatorVariants(t *testing.T) {
	cases := []struct {
		name string
		sep  string
	}{
		{"non-breaking-space", " "},
		{"ideographic-space", "　"},
		{"en-dash", "–"},
		{"em-dash", "—"},
		{"figure-dash", "‒"},
		{"slash", "/"},
		{"underscore", "_"},
		{"bullet", "•"},
		{"middle-dot", "·"},
		{"narrow-nbsp", " "},
		{"line-separator", "\u2028"},
		{"paragraph-separator", "\u2029"},
		{"next-line", "\u0085"},
		{"vertical-tab", "\u000B"},
		{"mongolian-vowel-separator", "\u180E"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			phrase := strings.ReplaceAll(valid12, " ", tc.sep)
			assertDetectedValid(t, phrase, "separator:"+tc.name)
		})
	}
}

// TestEvasion_CombinedHomoglyphAndSeparator stacks two evasions at once: a
// homoglyph-folded phrase delimited by non-breaking spaces.
func TestEvasion_CombinedHomoglyphAndSeparator(t *testing.T) {
	phrase := strings.ReplaceAll(homoglyphFold(valid12), " ", " ")
	assertDetectedValid(t, phrase, "combined-homoglyph+nbsp")
}

// TestEvasionSpans_HomoglyphPreservesOriginalOffsets confirms that normalization
// is applied to the match decision only — the returned span still indexes the
// ORIGINAL (evaded) bytes so redaction removes the real characters on the wire.
func TestEvasionSpans_HomoglyphPreservesOriginalOffsets(t *testing.T) {
	evaded := homoglyphFold(valid12)
	text := "leak: " + evaded + " <-"
	spans := DetectSpans(text, 12, true)
	if len(spans) == 0 {
		t.Fatal("expected a span for homoglyph-folded phrase")
	}
	got := text[spans[0].Start:spans[0].End]
	if got != evaded {
		t.Fatalf("span = %q, want the original evaded phrase %q", got, evaded)
	}
}

// TestEvasion_StandaloneInvisibleTokenDropped covers a token that is non-empty
// in the raw text but normalizes to nothing (a lone zero-width character used
// as a fake "word" to break the consecutive-BIP-39 run). It must be dropped so
// the surrounding real words stay contiguous and the phrase is still detected.
func TestEvasion_StandaloneInvisibleTokenDropped(t *testing.T) {
	words := strings.Split(valid12, " ")
	// Splice a standalone zero-width token between word 6 and word 7.
	injected := strings.Join(words[:6], " ") + " " + zwsp + " " + strings.Join(words[6:], " ")
	assertDetectedValid(t, injected, "standalone-invisible-token")
}

// TestEvasion_DotIsNotASeparator pins "." as a field boundary, NOT an
// intra-phrase separator. The request-body scanner joins distinct JSON field
// values with "." (proxy.bodyDLPJoinSeparator) so cross-field DLP works without
// merging tokens; if seedprotect treated "." as a separator it would synthesize
// a mnemonic across separate fields. A full valid 12-word phrase joined by "."
// must therefore NOT be detected as one phrase.
func TestEvasion_DotIsNotASeparator(t *testing.T) {
	dotted := strings.ReplaceAll(valid12, " ", ".")
	if matches := Detect(dotted, 12, true); len(matches) != 0 {
		t.Errorf(`"." must be a field boundary, not a separator; got cross-field match: %+v`, matches)
	}
}
