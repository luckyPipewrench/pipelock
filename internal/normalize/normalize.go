// Package normalize provides Unicode normalization pipelines for security scanning.
// All scanning paths (DLP, response injection, tool poisoning, policy matching)
// use these functions to strip evasion techniques before pattern matching.
//
// This package is the single source of truth for normalization. Changes here
// propagate to all scanning paths automatically.
package normalize

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// InvisibleRanges defines Unicode ranges stripped from all scanning paths.
// Consolidates zero-width characters, Tags block (Pliny steganography vector),
// and variation selectors (emoji steganography vector) into a single source of
// truth. Ranges cover:
//   - Soft hyphen, zero-width space through RTL mark, word joiner group, BOM
//   - Variation selectors 1-16 (U+FE00-FE0F): emoji glyph modifiers
//   - Tags block (U+E0000-E007F): deprecated language tags, steganography vector
//   - Variation selectors supplement (U+E0100-E01EF): extended glyph modifiers
var InvisibleRanges = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x00AD, Hi: 0x00AD, Stride: 1}, // soft hyphen
		{Lo: 0x200B, Hi: 0x200F, Stride: 1}, // zero-width space through RTL mark
		{Lo: 0x202A, Hi: 0x202E, Stride: 1}, // bidi embedding controls (LRE/RLE/PDF/LRO/RLO)
		{Lo: 0x2060, Hi: 0x2064, Stride: 1}, // word joiner through invisible plus
		{Lo: 0x2066, Hi: 0x2069, Stride: 1}, // bidi isolate controls (LRI/RLI/FSI/PDI)
		{Lo: 0xFE00, Hi: 0xFE0F, Stride: 1}, // variation selectors 1-16
		{Lo: 0xFEFF, Hi: 0xFEFF, Stride: 1}, // BOM / ZWNBSP
		{Lo: 0xFFF9, Hi: 0xFFFB, Stride: 1}, // interlinear annotation anchors
	},
	R32: []unicode.Range32{
		{Lo: 0xE0000, Hi: 0xE007F, Stride: 1}, // Tags block
		{Lo: 0xE0100, Hi: 0xE01EF, Stride: 1}, // variation selectors supplement
	},
}

// confusableMap maps Unicode characters from non-Latin scripts that are visually
// identical to Latin letters. NFKC normalization does NOT handle cross-script
// confusables — Cyrillic а (U+0430) stays as а, not Latin a.
//
// Covers Cyrillic, Greek, Armenian, Cherokee, and Latin Extended (small caps/IPA)
// lookalikes commonly used in homoglyph attacks. Not exhaustive — focused on
// characters that appear in English-language injection phrases and DLP key prefixes.
var confusableMap = map[rune]rune{
	// Cyrillic uppercase → Latin
	'\u0410': 'A', // А
	'\u0412': 'B', // В
	'\u0421': 'C', // С
	'\u0415': 'E', // Е
	'\u041D': 'H', // Н
	'\u0406': 'I', // І (Ukrainian)
	'\u0408': 'J', // Ј (Serbian)
	'\u041A': 'K', // К
	'\u041C': 'M', // М
	'\u041E': 'O', // О
	'\u0420': 'P', // Р
	'\u0405': 'S', // Ѕ (Macedonian)
	'\u0422': 'T', // Т
	'\u0425': 'X', // Х

	// Cyrillic lowercase → Latin
	'\u0430': 'a', // а
	'\u0432': 'v', // в
	'\u0435': 'e', // е
	'\u043D': 'h', // н
	'\u0456': 'i', // і (Ukrainian)
	'\u043A': 'k', // к
	'\u043C': 'm', // м
	'\u043E': 'o', // о
	'\u0440': 'p', // р
	'\u0441': 'c', // с
	'\u0442': 't', // т
	'\u0443': 'y', // у
	'\u0445': 'x', // х
	'\u0458': 'j', // ј (Serbian)
	'\u0455': 's', // ѕ (Macedonian)

	// Greek uppercase → Latin
	'\u0391': 'A', // Α
	'\u0392': 'B', // Β
	'\u0395': 'E', // Ε
	'\u0396': 'Z', // Ζ
	'\u0397': 'H', // Η
	'\u0399': 'I', // Ι
	'\u039A': 'K', // Κ
	'\u039C': 'M', // Μ
	'\u039D': 'N', // Ν
	'\u039F': 'O', // Ο
	'\u03A1': 'P', // Ρ
	'\u03A4': 'T', // Τ
	'\u03A5': 'Y', // Υ
	'\u03A7': 'X', // Χ

	// Greek lowercase → Latin
	'\u03B1': 'a', // α
	'\u03B5': 'e', // ε
	'\u03B9': 'i', // ι
	'\u03BA': 'k', // κ
	'\u03BD': 'v', // ν (nu)
	'\u03BF': 'o', // ο

	// Armenian → Latin (visually identical in most fonts)
	'\u0555': 'O', // Օ (Armenian Capital Letter Oh)
	'\u0585': 'o', // օ (Armenian Small Letter Oh)
	'\u054D': 'S', // Ս (Armenian Capital Letter Seh)
	'\u057D': 's', // ս (Armenian Small Letter Seh)
	'\u054C': 'L', // Լ — not perfect but close in sans-serif
	'\u0570': 'h', // հ (Armenian Small Letter Ho)
	'\u0578': 'n', // ո (Armenian Small Letter Vo — looks like n)
	'\u057C': 'n', // ռ (Armenian Small Letter Ra — looks like n in some fonts)
	'\u0561': 'a', // ա (Armenian Small Letter Ayb — similar to a in some fonts)

	// Cherokee → Latin (uppercase only)
	'\u13AA': 'A', // Ꭺ (Cherokee Letter GA — looks like A)
	'\u13A2': 'I', // Ꭲ (Cherokee Letter I — looks like I)
	'\u13D2': 'P', // Ꮲ
	'\u13DA': 'S', // Ꮪ
	'\u13A1': 'E', // Ꭱ — visually close to E
	'\u13B3': 'W', // Ꮃ
	'\u13D4': 'T', // Ꮤ

	// Latin Extended / IPA (small caps that survive NFKC)
	'\u1D00': 'A', // ᴀ (Latin Letter Small Capital A)
	'\u1D04': 'C', // ᴄ (Latin Letter Small Capital C)
	'\u1D07': 'E', // ᴇ (Latin Letter Small Capital E)
	'\u1D0F': 'O', // ᴏ (Latin Letter Small Capital O)
	'\u026A': 'I', // ɪ (Latin Letter Small Capital I)
	'\u0299': 'B', // ʙ (Latin Letter Small Capital B)
}

// NormalizeWhitespace replaces Unicode whitespace characters that Go's RE2 \s
// does not match with ASCII space.
func NormalizeWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u1680', '\u180E', '\u2028', '\u2029':
			return ' '
		}
		return r
	}, s)
}

// NormalizeLeetspeak maps common digit-for-letter substitutions used in
// L1B3RT4S-style injection evasion.
func NormalizeLeetspeak(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '0':
			return 'o'
		case '1':
			return 'i'
		case '3':
			return 'e'
		case '4':
			return 'a'
		case '5':
			return 's'
		case '7':
			return 't'
		case '@':
			return 'a'
		case '$':
			return 's'
		}
		return r
	}, s)
}

// StripZeroWidth removes ASCII control characters (except \t, \n, \r) and
// Unicode zero-width/invisible characters. Preserves whitespace control chars
// because injection patterns use \s+ to match them.
// Used in response/injection scanning paths.
func StripZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1F && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		if r == 0x7F {
			return -1
		}
		if r >= 0x80 && r <= 0x9F {
			return -1
		}
		if unicode.Is(InvisibleRanges, r) {
			return -1
		}
		return r
	}, s)
}

// ReplaceInvisibleWithSpace replaces invisible/control characters with spaces
// instead of dropping them. Preserves word boundaries at invisible character
// positions: "ignore\u200ball" becomes "ignore all" (detectable) instead of
// "ignoreall" (bypass). Used in policy matching where word boundaries matter.
func ReplaceInvisibleWithSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1F && r != '\t' && r != '\n' && r != '\r' {
			return ' '
		}
		if r == 0x7F {
			return ' '
		}
		if r >= 0x80 && r <= 0x9F {
			return ' '
		}
		if unicode.Is(InvisibleRanges, r) {
			return ' '
		}
		return r
	}, s)
}

// ConfusableToASCII maps visually identical non-Latin characters to their Latin
// equivalents. Applied after NFKC normalization to catch cross-script homoglyph
// attacks that NFKC does not handle (Cyrillic, Greek lookalikes).
func ConfusableToASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if mapped, ok := confusableMap[r]; ok {
			return mapped
		}
		return r
	}, s)
}

// StripCombiningMarks removes Unicode combining marks (category Mn) that survive
// NFKC normalization. NFD decomposition reverses NFKC composition so combining
// marks can be stripped. Applied after NFKC + confusable mapping.
func StripCombiningMarks(s string) string {
	s = norm.NFD.String(s)
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, s)
}

// StripControlChars removes ALL C0 (0x00-0x1F), C1 (0x80-0x9F), DEL (0x7F),
// and Unicode zero-width/invisible characters. Unlike StripZeroWidth, this also
// strips whitespace control chars (\t, \n, \r) because DLP patterns match
// specific character sequences where ANY control char is evasion, not content.
// Used in DLP scanning paths.
func StripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return -1
		}
		if unicode.Is(InvisibleRanges, r) {
			return -1
		}
		return r
	}, s)
}

// ForDLP applies the standard DLP normalization pipeline: strip all control/invisible
// characters, NFKC decomposition, confusable-to-ASCII mapping, combining mark removal.
// Used across all DLP scanning paths (URL segments, MCP text, env leak detection).
func ForDLP(s string) string {
	s = StripControlChars(s)
	s = norm.NFKC.String(s)
	s = ConfusableToASCII(s)
	s = StripCombiningMarks(s)
	return s
}

// ForMatching applies the standard normalization pipeline for response/injection
// scanning: strip invisible chars (preserve whitespace), NFKC, confusable mapping,
// combining mark removal, whitespace normalization.
func ForMatching(s string) string {
	s = StripZeroWidth(s)
	s = norm.NFKC.String(s)
	s = ConfusableToASCII(s)
	s = StripCombiningMarks(s)
	s = NormalizeWhitespace(s)
	return s
}

// ForPolicy applies the same pipeline as ForMatching, but replaces invisible
// characters with spaces instead of dropping them. This preserves word boundaries
// critical for tool-policy regex: "rm\u200b-rf" → "rm -rf" (matchable).
func ForPolicy(s string) string {
	s = ReplaceInvisibleWithSpace(s)
	s = norm.NFKC.String(s)
	s = ConfusableToASCII(s)
	s = StripCombiningMarks(s)
	s = NormalizeWhitespace(s)
	return s
}

// ForToolText applies normalization for MCP tool description scanning. Strips ALL
// control chars and invisibles, then NFKC + confusable + marks + leetspeak +
// whitespace. More aggressive than ForMatching because tool descriptions have no
// legitimate control chars — any present are evasion attempts.
func ForToolText(s string) string {
	s = StripControlChars(s)
	s = norm.NFKC.String(s)
	s = ConfusableToASCII(s)
	s = StripCombiningMarks(s)
	s = NormalizeLeetspeak(s)
	s = NormalizeWhitespace(s)
	return s
}
