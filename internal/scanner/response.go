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

// stripZeroWidth removes ASCII control characters and Unicode zero-width/invisible
// characters that could be used to evade regex pattern matching. Preserves
// whitespace control chars (\t, \n, \r) because injection patterns use \s+ to
// match them. Used in response/injection scanning paths.
func stripZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		// Drop non-whitespace C0 control characters and DEL.
		// These break regex matching when injected (e.g., \x08 backspace)
		// without contributing visible content.
		if r <= 0x1F && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		if r == 0x7F { // DEL
			return -1
		}
		switch r {
		case '\u200B', // zero-width space
			'\u200C', // zero-width non-joiner
			'\u200D', // zero-width joiner
			'\u2060', // word joiner
			'\u2061', // function application
			'\u2062', // invisible times
			'\u2063', // invisible separator
			'\u2064', // invisible plus
			'\u00AD', // soft hyphen
			'\u200E', // left-to-right mark
			'\u200F', // right-to-left mark
			'\uFEFF': // byte order mark / zero-width no-break space
			return -1 // drop
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
		// Drop ALL C0 control characters and DEL.
		if r <= 0x1F || r == 0x7F {
			return -1
		}
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u2060',
			'\u2061', '\u2062', '\u2063', '\u2064',
			'\u00AD', '\u200E', '\u200F', '\uFEFF':
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

	// Strip zero-width characters before pattern matching to prevent bypass.
	content = stripZeroWidth(content)
	// NFKC normalization handles compatibility decompositions (fullwidth → ASCII).
	content = norm.NFKC.String(content)
	// Map cross-script confusables (Cyrillic/Greek lookalikes) to Latin equivalents.
	// NFKC does NOT handle these — Cyrillic о (U+043E) stays as о without this step.
	content = ConfusableToASCII(content)
	// Strip combining marks that survive NFKC (e.g., i+\u0307 has no precomposed form,
	// leaving "i̇" which breaks "ignore" matching). Must run after NFKC so that
	// composable sequences are composed first, not blindly stripped.
	content = StripCombiningMarks(content)
	// Normalize Unicode whitespace to ASCII space so \s+ in regex patterns
	// catches exotic spaces (e.g., Ogham space U+1680, Mongolian vowel separator U+180E).
	content = normalizeWhitespace(content)

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

// ResponseScanningEnabled returns whether response scanning is active.
func (s *Scanner) ResponseScanningEnabled() bool {
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
func (s *Scanner) ResponseAction() string {
	return s.responseAction
}
