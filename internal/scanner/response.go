package scanner

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// ResponseScanResult describes the outcome of scanning response content.
type ResponseScanResult struct {
	Clean              bool
	Matches            []ResponseMatch
	TransformedContent string // set for strip and ask actions
}

// ResponseMatch describes a single pattern match in response content.
type ResponseMatch struct {
	PatternName string `json:"pattern_name"`
	MatchText   string `json:"match_text"` // truncated to 100 chars
	Position    int    `json:"position"`
}

// normalizeWhitespace replaces Unicode whitespace characters that Go's RE2 \s
// does not match with ASCII space. NFKC handles some (em space U+2003 → space)
// but not all (Ogham space U+1680, Mongolian vowel separator U+180E).
func normalizeWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u1680', // Ogham space mark
			'\u180E', // Mongolian vowel separator
			'\u2028', // line separator
			'\u2029': // paragraph separator
			return ' '
		}
		return r
	}, s)
}

// InvisibleRanges defines Unicode ranges stripped from all scanning paths.
// Consolidates zero-width characters, Tags block (Pliny steganography vector),
// and variation selectors (emoji steganography vector) into a single source of
// truth used by stripZeroWidth, stripControlChars, and normalizeToolText
// (in mcp/tools.go). Ranges cover:
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

// NormalizeLeetspeak maps common digit-for-letter substitutions used in
// L1B3RT4S-style injection evasion. Applied as a second-pass only when
// primary scanning finds no matches, to avoid false positives on legitimate
// content with digits (e.g., "API v3.0", array indices, numbers).
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

// stripZeroWidth removes ASCII control characters and Unicode zero-width/invisible
// characters that could be used to evade regex pattern matching. Preserves
// whitespace control chars (\t, \n, \r) because injection patterns use \s+ to
// match them. Used in response/injection scanning paths.
func stripZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		// Drop non-whitespace C0 control characters and DEL.
		if r <= 0x1F && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		if r == 0x7F {
			return -1
		}
		// Drop C1 control characters (U+0080-U+009F). These include NEL (U+0085),
		// reverse line feed, device control strings, etc. Attackers insert them
		// mid-word to split keywords (e.g., "igno\u0085re") without visible effect.
		if r >= 0x80 && r <= 0x9F {
			return -1
		}
		if unicode.Is(InvisibleRanges, r) {
			return -1
		}
		return r
	}, s)
}

// confusableMap maps Unicode characters from non-Latin scripts that are visually
// identical to Latin letters. NFKC normalization does NOT handle cross-script
// confusables — Cyrillic а (U+0430) stays as а, not Latin a. Attackers exploit
// this to bypass keyword-based injection detection (e.g., "ignоre" with Cyrillic о).
//
// Covers Cyrillic and Greek lookalikes commonly used in homoglyph attacks.
// Not exhaustive — focused on characters that appear in English-language
// injection phrases ("ignore", "instructions", "system", "execute", etc.).
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

// StripCombiningMarks removes Unicode combining marks (category Mn — Mark, nonspacing)
// that survive NFKC normalization. Attackers insert combining marks between letters
// to break keyword matching (e.g., "i\u0307gnore" → "i̇gnore" evades "ignore" regex).
// NFKC composes where precomposed forms exist (n\u0303 → ñ), making the mark
// invisible to strings.Map. NFD decomposition reverses this (ñ → n + \u0303) so
// the combining mark can be stripped. Applied after NFKC + confusable mapping.
func StripCombiningMarks(s string) string {
	// NFD decomposes precomposed chars: é → e + combining acute, ñ → n + combining tilde.
	// Without this, NFKC-composed characters like ñ would survive mark stripping.
	s = norm.NFD.String(s)
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, s)
}

// stripControlChars removes ALL ASCII control characters (0x00-0x1F, 0x7F) and
// Unicode zero-width/invisible characters. Unlike stripZeroWidth, this also
// strips whitespace control chars (\t, \n, \r) because DLP patterns match
// specific character sequences where ANY control char is evasion, not content.
// Used in DLP scanning paths (fetch proxy URLs, MCP text, env leak detection).
func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		// Drop C0 controls (U+0000-001F), DEL (U+007F), and C1 controls (U+0080-009F).
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return -1
		}
		if unicode.Is(InvisibleRanges, r) {
			return -1
		}
		return r
	}, s)
}

// ScanResponse checks fetched content for prompt injection patterns.
// If scanning is disabled, returns Clean=true immediately.
// Zero-width Unicode characters are stripped before scanning to prevent
// evasion via invisible character insertion.
// For "strip" action, replaces matches with [REDACTED: PatternName].
func (s *Scanner) ScanResponse(content string) ResponseScanResult {
	if !s.responseEnabled {
		return ResponseScanResult{Clean: true}
	}

	// Normalize: strip invisibles, NFKC, confusables, combining marks, whitespace.
	content = stripZeroWidth(content)
	content = norm.NFKC.String(content)
	content = ConfusableToASCII(content)
	content = StripCombiningMarks(content)
	content = normalizeWhitespace(content)

	// Primary scan on normalized content.
	matches := s.matchResponsePatterns(content)

	// Dual-pass: if primary scan is clean, re-scan with leetspeak normalization.
	// Only fires when primary found nothing, avoiding FPs on digit-heavy text
	// (e.g., "API v3.0" → "API ve.o" would not match any injection pattern, but
	// "1gn0r3 pr3v10us 1nstruct10ns" → "ignore previous instructions" does).
	if len(matches) == 0 {
		leeted := NormalizeLeetspeak(content)
		if leeted != content {
			matches = s.matchResponsePatterns(leeted)
		}
	}

	if len(matches) == 0 {
		return ResponseScanResult{Clean: true}
	}

	result := ResponseScanResult{
		Clean:   false,
		Matches: matches,
	}

	if s.responseAction == "strip" || s.responseAction == "ask" { //nolint:goconst // action string used as-is from config
		transformed := content
		for _, p := range s.responsePatterns {
			replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
			transformed = p.re.ReplaceAllString(transformed, replacement)
		}
		result.TransformedContent = transformed
	}

	return result
}

// matchResponsePatterns runs all response patterns against content and returns matches.
func (s *Scanner) matchResponsePatterns(content string) []ResponseMatch {
	var matches []ResponseMatch
	for _, p := range s.responsePatterns {
		locs := p.re.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matchText := content[loc[0]:loc[1]]
			if runes := []rune(matchText); len(runes) > 100 {
				matchText = string(runes[:100])
			}
			matches = append(matches, ResponseMatch{
				PatternName: p.name,
				MatchText:   matchText,
				Position:    loc[0],
			})
		}
	}
	return matches
}

// ResponseScanningEnabled returns whether response scanning is active.
func (s *Scanner) ResponseScanningEnabled() bool {
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
func (s *Scanner) ResponseAction() string {
	return s.responseAction
}
