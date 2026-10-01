// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Keep the original separate maps as an independent output oracle.
func referenceDLPControlStrip(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) || unicode.Is(InvisibleRanges, r) {
			return -1
		}
		return r
	}, s)
}

func referenceExoticWhitespaceStrip(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u00A0', '\u1680', '\u180E',
			'\u2000', '\u2001', '\u2002', '\u2003', '\u2004',
			'\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200A',
			'\u2028', '\u2029', '\u202F', '\u205F', '\u3000':
			return -1
		}
		return r
	}, s)
}

func referenceConfusableToASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if mapped, ok := confusableMap[r]; ok {
			return mapped
		}
		return r
	}, s)
}

func referenceForDLPSeparateMaps(s string) string {
	s = referenceDLPControlStrip(s)
	s = referenceExoticWhitespaceStrip(s)
	s = norm.NFKC.String(s)
	s = referenceConfusableToASCII(s)
	s = norm.NFD.String(s)
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, s)
}

func TestDLPFusedMapsReferenceParity(t *testing.T) {
	check := func(input string) {
		t.Helper()
		if got, want := ForDLP(input), referenceForDLPSeparateMaps(input); got != want {
			t.Fatalf("DLP output differs for %x: got %x, want %x", input, got, want)
		}
		if got, want := StripControlChars(input), referenceDLPControlStrip(input); got != want {
			t.Fatalf("control-strip output differs for %x", input)
		}
		if got, want := StripExoticWhitespace(input), referenceExoticWhitespaceStrip(input); got != want {
			t.Fatalf("whitespace-strip output differs for %x", input)
		}
		if got, want := ConfusableToASCII(input), referenceConfusableToASCII(input); got != want {
			t.Fatalf("confusable output differs for %x", input)
		}
	}
	for r := range confusableMap {
		if r < utf8.RuneSelf {
			t.Fatalf("ASCII identity guard no longer holds for U+%04X", r)
		}
	}
	for _, input := range []string{"", "ordinary first body", "different body", "e\u0301", "Ａ\u00a0Ｂ", "\u212a\u0301", "\u1100\u1161", "a\xff\xfe\xc0\xafz"} {
		check(input)
	}
	for first := range 256 {
		for second := range 256 {
			check("a" + string([]byte{byte(first), byte(second)}) + "\u0301z")
		}
	}
	var batch strings.Builder
	scalars := 0
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		batch.WriteByte('A')
		batch.WriteRune(r)
		batch.WriteString("\u0301\x00z")
		scalars++
		if scalars%2048 == 0 {
			check(batch.String())
			batch.Reset()
		}
	}
	check(batch.String())
	t.Logf("compared all %d Unicode scalars and 65536 raw byte pairs", scalars)
}
