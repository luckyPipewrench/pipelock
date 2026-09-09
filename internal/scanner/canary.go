// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// compiledCanaryToken stores normalized canary values for fast matching.
type compiledCanaryToken struct {
	name                    string
	normalizedLower         string
	canonicalLower          string
	partialWindows          map[string][]int
	canonicalPartialWindows map[string][]int
	// decimalCodes holds the token spelled out as decimal character codes
	// (comma and space separated), built from the original-case value. The
	// known value is encoded and searched for, never the other way round:
	// decoding arbitrary numeric runs in prose would fire on JSON arrays,
	// CSV telemetry and pixel data.
	decimalCodes []string
}

func compileCanaryTokens(cfg config.CanaryTokens) []compiledCanaryToken {
	if !cfg.Enabled || len(cfg.Tokens) == 0 {
		return nil
	}
	out := make([]compiledCanaryToken, 0, len(cfg.Tokens))
	normalizedValues := make([]string, 0, len(cfg.Tokens))
	for _, token := range cfg.Tokens {
		normalized := strings.ToLower(normalize.ForDLP(token.Value))
		if normalized == "" {
			continue
		}
		normalizedValues = append(normalizedValues, normalized)
		original := normalize.ForDLP(token.Value)
		out = append(out, compiledCanaryToken{
			name:            token.Name,
			normalizedLower: normalized,
			canonicalLower:  strings.ToLower(canonicalizeCanaryText(normalized)),
			decimalCodes:    []string{decimalCharacterCodes(original, ","), decimalCharacterCodes(original, " ")},
		})
	}
	// Windows shared between two canaries are a common stem, not a disclosure
	// of either; they are excluded the same way as for environment secrets.
	windows := buildKnownValueWindows(normalizedValues)
	canonicalCount := make(map[string]int, len(out))
	for i := range out {
		out[i].partialWindows = windows[out[i].normalizedLower]
		// URL-shaped originals stay whole-value-only after canonicalization.
		// canonicalizeCanaryText strips "://", and knownValueWindows would
		// then emit partial windows for the public scheme/host/path stem.
		if strings.Contains(out[i].normalizedLower, "://") || out[i].canonicalLower == "" {
			continue
		}
		canonicalCount[out[i].canonicalLower]++
	}
	canonicalValues := make([]string, 0, len(canonicalCount))
	for value, n := range canonicalCount {
		if n == 1 {
			canonicalValues = append(canonicalValues, value)
		}
	}
	canonicalWindows := buildKnownValueWindows(canonicalValues)
	for i := range out {
		if strings.Contains(out[i].normalizedLower, "://") || out[i].canonicalLower == "" {
			continue
		}
		if canonicalCount[out[i].canonicalLower] != 1 {
			continue
		}
		out[i].canonicalPartialWindows = canonicalWindows[out[i].canonicalLower]
	}
	return out
}

// scanCanaryText scans text for configured canary tokens. It owns DLP
// normalization, then checks URL-decoded, encoded, and separator-canonicalized
// views. Span labels name the lowercased/canonicalized view that was indexed.
func (s *Scanner) scanCanaryText(text string) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}

	cleaned := normalize.ForDLP(text)
	if cleaned == "" {
		return nil
	}

	var matches []TextDLPMatch
	matches = append(matches, s.matchCanaryTokens(cleaned, "", false, ViewDLPNormalized)...)
	matches = append(matches, s.matchCanaryDecimalCodes(cleaned, "", ViewDLPNormalized)...)

	if decoded := IterativeDecode(cleaned); decoded != cleaned {
		label := spanViewLabel("url_decoded", ViewDLPNormalized)
		matches = append(matches, s.matchCanaryTokens(decoded, "url", false, label)...)
		matches = append(matches, s.matchCanaryDecimalCodes(decoded, "url", label)...)
	}
	if decoded := decodeHTMLEntities(cleaned); decoded != cleaned {
		label := spanViewLabel("html_decoded", ViewDLPNormalized)
		matches = append(matches, s.matchCanaryTokens(decoded, encodingHTML, false, label)...)
		matches = append(matches, s.matchCanaryDecimalCodes(decoded, encodingHTML, label)...)
	}
	if strings.Contains(cleaned, ".") {
		dotless := removeHostnameDots(cleaned)
		if dotless != cleaned {
			matches = append(matches, s.matchCanaryTokens(dotless, "subdomain", false, spanViewLabel("dotless_hostname", ViewDLPNormalized))...)
		}
	}
	if collapsed := canonicalizeCanaryText(cleaned); collapsed != "" && collapsed != cleaned {
		matches = append(matches, s.matchCanaryTokens(cleaned, "split", true, ViewDLPNormalized)...)
	}

	// Walk the bounded recursive decode fixpoint, not a single pass. Ordinary
	// text DLP and the core response scanner already use this decoder in the
	// same shape; a canary matcher that stopped at one layer meant a single
	// extra wrapper hid the one token whose whole purpose is to prove an
	// exfiltration path. The fixpoint's candidate and byte bounds terminate it,
	// and the candidates are already generated for DLP, so this adds substring
	// checks rather than decode work.
	for _, d := range decodeEncodingsRecursiveWithURL(cleaned) {
		label := spanViewLabel(d.encoding+"_decoded", ViewDLPNormalized)
		matches = append(matches, s.matchCanaryTokens(d.text, d.encoding, false, label)...)
		// A decimal-code spelling can itself arrive wrapped in another
		// encoding; the known-value search runs on every decoded view, not
		// only the first, for the same reason ordinary token matching does.
		matches = append(matches, s.matchCanaryDecimalCodes(d.text, d.encoding, label)...)
	}

	for _, view := range textDLPEncodingSegmentViews(cleaned) {
		segments := strings.FieldsFunc(view.text, isTextDLPEncodingDelimiter)
		for _, seg := range segments {
			if len(seg) < 8 {
				continue
			}
			// Same recursion for the per-segment view: the whole-text and
			// segment loops are separate call sites, so leaving this one
			// single-pass would keep a query-value bypass open.
			for _, d := range decodeEncodingsRecursiveWithURL(seg) {
				label := spanViewLabel(d.encoding+"_decoded", view.viewLabel)
				matches = append(matches, s.matchCanaryTokens(d.text, d.encoding, false, label)...)
				matches = append(matches, s.matchCanaryDecimalCodes(d.text, d.encoding, label)...)
			}
			if collapsed := canonicalizeCanaryText(seg); collapsed != "" && collapsed != seg {
				matches = append(matches, s.matchCanaryTokens(seg, "split", true, view.viewLabel)...)
			}
		}
	}

	return deduplicateMatches(matches)
}

// matchCanaryTokens checks a pre-built view for canary token matches. It always
// indexes a lowercased view and, for split matches, a canonicalized lowercased
// view, so the span label must include those final transforms.
func (s *Scanner) matchCanaryTokens(text, encoding string, canonical bool, inputViewLabel string) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}

	haystack := strings.ToLower(text)
	viewLabel := lowerViewLabel(inputViewLabel)
	if canonical {
		haystack = strings.ToLower(canonicalizeCanaryText(haystack))
		if haystack == "" {
			return nil
		}
		viewLabel = canonicalLowerViewLabel(inputViewLabel)
	}

	var matches []TextDLPMatch
	for _, token := range s.canaryTokens {
		needle := token.normalizedLower
		if canonical {
			needle = token.canonicalLower
		}
		if needle == "" {
			continue
		}
		if start := strings.Index(haystack, needle); start >= 0 {
			end := start + len(needle)
			patternName := "Canary Token (" + token.name + ")"
			matches = append(matches, TextDLPMatch{
				PatternName: patternName,
				Severity:    "critical",
				Encoded:     encoding,
				span:        newMatchSpan(start, end, viewLabel, patternName, "", ""),
			})
			continue
		}
		windows := token.partialWindows
		if canonical {
			windows = token.canonicalPartialWindows
		}
		if start, end, length, _, ok := indexKnownValueSubstring(needle, windows, []spanTextView{{text: haystack, viewLabel: viewLabel}}); ok {
			patternName := "Canary Token (" + token.name + ")"
			matches = append(matches, TextDLPMatch{
				PatternName: patternName,
				Severity:    "critical",
				Encoded:     encoding,
				PartialLen:  length,
				span:        newMatchSpan(start, end, viewLabel, patternName, "", ""),
			})
		}
	}

	return matches
}

// canonicalizeCanaryText collapses separators commonly used to split tokens
// across URL/path/query boundaries.
//
//pipelock:provenance-transform canary_canonicalize
func canonicalizeCanaryText(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '/', '\\', '?', '&', '=', ' ', '\t', '\n', '\r',
			':', ';', ',', '-', '_', '@', '%', '+', '#':
			return -1
		}
		return r
	}, s)
}

// matchCanaryDecimalCodes finds a canary token spelled out as decimal character
// codes ("65,75,73,65,...") in text. Ordinary DLP already catches configured
// secrets in this form through matchSecretEncodingSpan; a canary exists to
// prove an exfiltration path, so it must not be the one known value this
// spelling hides. Only whole tokens match: the encoded needle is the exact
// code sequence of the exact value, so a match is that value and nothing else.
func (s *Scanner) matchCanaryDecimalCodes(text, outerEncoding, inputViewLabel string) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}
	encoded := encodingDecimal
	if outerEncoding != "" {
		// The value arrived wrapped: report both layers so an operator reading
		// the finding knows which decoding surfaced it, not only that it was
		// spelled in decimal.
		encoded = outerEncoding + "+" + encodingDecimal
	}
	var matches []TextDLPMatch
	for _, token := range s.canaryTokens {
		for _, needle := range token.decimalCodes {
			if needle == "" {
				continue
			}
			start, end, ok := indexDecimalCodeRun(text, needle)
			if !ok {
				continue
			}
			patternName := "Canary Token (" + token.name + ")"
			matches = append(matches, TextDLPMatch{
				PatternName: patternName,
				Severity:    "critical",
				Encoded:     encoded,
				span:        newMatchSpan(start, end, inputViewLabel, patternName, "", ""),
			})
			break
		}
	}
	return matches
}

// indexDecimalCodeRun finds needle in text only where both ends sit on a
// numeric-token boundary. Without it, a plain substring search matched a code
// sequence inside a LARGER number, so "1"+codes reported a critical canary
// finding for a value the text never carried. The rejected characters are the
// ones that would make an adjacent digit run part of one number: digits
// themselves, a decimal point, an exponent marker, and a sign. Everything else,
// including the commas, spaces and brackets of a JSON array, is a boundary.
func indexDecimalCodeRun(text, needle string) (int, int, bool) {
	for offset := 0; offset+len(needle) <= len(text); {
		rel := strings.Index(text[offset:], needle)
		if rel < 0 {
			return 0, 0, false
		}
		start := offset + rel
		end := start + len(needle)
		if decimalCodeTextBoundary(text, start-1) && decimalCodeTextBoundary(text, end) {
			return start, end, true
		}
		offset = start + 1
	}
	return 0, 0, false
}

// decimalCodeTextBoundary reports whether index is outside text or holds a byte
// that cannot continue a number.
func decimalCodeTextBoundary(text string, index int) bool {
	if index < 0 || index >= len(text) {
		return true
	}
	switch c := text[index]; {
	case c >= '0' && c <= '9':
		return false
	case c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+':
		return false
	default:
		return true
	}
}
