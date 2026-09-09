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
		out = append(out, compiledCanaryToken{
			name:            token.Name,
			normalizedLower: normalized,
			canonicalLower:  strings.ToLower(canonicalizeCanaryText(normalized)),
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
	matches = append(matches, s.matchCanaryDecimalView(cleaned, ViewDLPNormalized)...)

	if decoded := IterativeDecode(cleaned); decoded != cleaned {
		label := spanViewLabel("url_decoded", ViewDLPNormalized)
		matches = append(matches, s.matchCanaryTokens(decoded, "url", false, label)...)
		matches = append(matches, s.matchCanaryDecimalView(decoded, label)...)
	}
	if decoded := decodeHTMLEntities(cleaned); decoded != cleaned {
		label := spanViewLabel("html_decoded", ViewDLPNormalized)
		matches = append(matches, s.matchCanaryTokens(decoded, encodingHTML, false, label)...)
		matches = append(matches, s.matchCanaryDecimalView(decoded, label)...)
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
		matches = append(matches, s.matchCanaryDecimalView(d.text, label)...)
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
				matches = append(matches, s.matchCanaryDecimalView(d.text, label)...)
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

// matchCanaryDecimalView runs the ORDINARY canary matcher over the text a
// decimal character-code run spells. The earlier shape encoded each token into
// one exact spelling and searched for that, which missed every variation the
// wire actually carries: "65, 75" with comma-and-space separators, a
// lower-cased token, and the integral float and exponent forms JSON permits.
// Decoding once and reusing the existing matcher gets separator, case and
// number-form handling from code that already had it, and leaves one place to
// fix instead of four.
//
// This does NOT reopen the false-positive risk that made encode-and-search the
// rule for pattern DLP. The decoded text is compared only against KNOWN values,
// so it matches only when a numeric run literally spells a token the operator
// planted; it never reaches the pattern set. The decoder's own run floor also
// means ordinary short numeric telemetry decodes to nothing at all.
func (s *Scanner) matchCanaryDecimalView(text, inputViewLabel string) []TextDLPMatch {
	if len(s.canaryTokens) == 0 || text == "" {
		return nil
	}
	decoded := decodeDecimalCharacterCodes(text)
	if decoded == "" {
		return nil
	}
	return s.matchCanaryTokens(decoded, encodingDecimal, false, spanViewLabel("decimal_decoded", inputViewLabel))
}
