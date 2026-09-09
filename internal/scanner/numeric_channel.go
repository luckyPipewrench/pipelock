// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ViewNumericChannel labels spans matched in the numeric channel: the comma
// joined numeric leaves of a structured response, kept apart from its text.
const ViewNumericChannel = "numeric_channel"

// minDecimalCodeRun is the shortest run of consecutive numeric leaves that is
// decoded as decimal character codes. Shorter runs are ordinary numbers; the
// known values this channel looks for are never that short.
const minDecimalCodeRun = 8

// ScanNumericChannelForKnownValues checks the numeric leaves of a structured
// response for values the proxy already knows: registered canary tokens and
// configured environment and file secrets. It is deliberately NOT the general
// inbound text scan. Numbers never reach the prompt-injection cascade or the
// pattern DLP view, because joining ordinary telemetry, pixel data or metric
// samples into one digit string manufactures credential-shaped tokens out of
// nothing. Only whole known values match here, so a match is a disclosure of
// something the operator planted or holds, never a shape guess.
//
// Canary tokens match both as plain digits (a numeric canary returned as a
// number) and spelled out as decimal character codes. Configured secrets match
// only in the character-code form: an agent-owned value legitimately received
// as a plain number is not exfiltration, which is the same reason the inbound
// text scan skips secret-leak matching, while a secret disguised as character
// codes is not legitimate receipt.
//
// Failure direction: an empty channel, no known values, or an undecodable run
// all yield no match, and nothing here can suppress a match another scanner
// already produced; the channel only ever adds findings.
func (s *Scanner) ScanNumericChannelForKnownValues(numeric string) []TextDLPMatch {
	if numeric == "" || (len(s.canaryTokens) == 0 && len(s.envSecrets) == 0 && len(s.fileSecrets) == 0) {
		return nil
	}
	texts := []spanTextView{{text: numeric, viewLabel: ViewNumericChannel}}
	var matches []TextDLPMatch

	// Decode the run ONCE and look for the known values in what it spells,
	// rather than encoding each secret into one exact spelling and searching
	// for that. The encoding approach could only see the spelling it happened
	// to build, so a comma-and-space separated run and the integral float and
	// exponent forms JSON permits both slipped past it while the canary path,
	// which already decoded, caught them. Secrets keep their exact case: a
	// different case is a different secret.
	decoded := decodeDecimalCharacterCodes(numeric)
	decodedView := []spanTextView{{text: decoded, viewLabel: spanViewLabel("decimal_decoded", ViewNumericChannel)}}
	if decoded != "" {
		for _, known := range []struct {
			secrets     []string
			patternName string
			encoded     string
		}{
			{s.envSecrets, "Environment Variable Leak", "env"},
			{s.fileSecrets, "Known Secret Leak", encodingDecimal},
		} {
			for _, secret := range known.secrets {
				if secret == "" {
					continue
				}
				if start, end, viewLabel, ok := indexAnyView(secret, decodedView); ok {
					matches = append(matches, TextDLPMatch{
						PatternName: known.patternName,
						Severity:    "critical",
						Encoded:     known.encoded,
						span:        newMatchSpan(start, end, viewLabel, known.patternName, "", ""),
					})
				}
			}
		}
	}

	if len(s.canaryTokens) > 0 {
		decodedLower := strings.ToLower(decoded)
		for _, token := range s.canaryTokens {
			needle := token.normalizedLower
			if needle == "" {
				continue
			}
			patternName := "Canary Token (" + token.name + ")"
			if start, end, _, ok := indexWholeNumericSequence(needle, texts); ok {
				matches = append(matches, TextDLPMatch{
					PatternName: patternName,
					Severity:    "critical",
					span:        newMatchSpan(start, end, ViewNumericChannel, patternName, "", ""),
				})
				continue
			}
			if start := strings.Index(decodedLower, needle); start >= 0 {
				matches = append(matches, TextDLPMatch{
					PatternName: patternName,
					Severity:    "critical",
					Encoded:     encodingDecimal,
					span:        newMatchSpan(start, start+len(needle), spanViewLabel("decimal_decoded", ViewNumericChannel), patternName, "", ""),
				})
			}
		}
	}

	return deduplicateMatches(matches)
}

// indexWholeNumericSequence finds candidate in a numeric-leaf view without
// treating digits inside a larger JSON number as a separate value. Numeric
// leaves arrive comma-separated from ExtractNumericLeaves; space is accepted
// too so direct callers retain the documented decimal-code spelling.
func indexWholeNumericSequence(candidate string, views []spanTextView) (int, int, string, bool) {
	if candidate == "" {
		return 0, 0, "", false
	}
	for _, view := range views {
		for offset := 0; offset <= len(view.text)-len(candidate); {
			start := strings.Index(view.text[offset:], candidate)
			if start < 0 {
				break
			}
			start += offset
			end := start + len(candidate)
			if numericLeafBoundary(view.text, start) && numericLeafBoundary(view.text, end) {
				return start, end, view.viewLabel, true
			}
			offset = start + 1
		}
	}
	return 0, 0, "", false
}

func numericLeafBoundary(text string, index int) bool {
	return index == 0 || index == len(text) || text[index-1] == ',' || text[index-1] == ' ' || text[index] == ',' || text[index] == ' '
}

// decodeDecimalCharacterCodes turns runs of comma or space separated integers
// that are valid Unicode code points into the text they spell. Integral JSON
// number forms such as 57.0 and 5.7e1 are equivalent to the code point 57 and
// therefore remain in the run; fractional, negative, non-finite, or
// out-of-range values end it. Runs shorter than minDecimalCodeRun are dropped,
// so ordinary numeric data decodes to nothing rather than to noise. Runs are
// joined with newlines so a needle cannot straddle two of them.
func decodeDecimalCharacterCodes(numeric string) string {
	var out strings.Builder
	var run strings.Builder
	runLen := 0
	flush := func() {
		if runLen >= minDecimalCodeRun {
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.WriteString(run.String())
		}
		run.Reset()
		runLen = 0
	}
	fields := strings.FieldsFunc(numeric, isDecimalCodeSeparator)
	for _, field := range fields {
		code, ok := parseDecimalCharacterCode(field)
		if !ok {
			flush()
			continue
		}
		run.WriteRune(code)
		runLen++
	}
	flush()
	return out.String()
}

// isDecimalCodeSeparator reports whether r separates two numbers rather than
// continuing one. The rule is inverted deliberately: anything that is not part
// of a number token IS a separator. Enumerating delimiters instead kept losing
// characters off the ends of a run, because whatever punctuation was not on the
// list fused to the first or last number and made it unparseable, so `[65,75]`
// and `payload=65,75` each silently dropped a character.
//
// A digit, decimal point, sign and exponent letter are excluded on purpose:
// they continue a number, so `1.65` breaks the run rather than decoding as 65.
func isDecimalCodeSeparator(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return false
	case r == '.' || r == '-' || r == '+' || r == 'e' || r == 'E':
		return false
	default:
		return true
	}
}

// parseDecimalCharacterCode accepts only an exact non-negative JSON number
// value that is a valid Unicode code point. It fast-paths integer spellings and
// permits equivalent decimal/exponent forms without ever rounding a value into
// a code point: every accepted value is bounded by utf8.MaxRune, which float64
// represents exactly.
func parseDecimalCharacterCode(field string) (rune, bool) {
	if code, err := strconv.ParseInt(field, 10, 32); err == nil {
		return validDecimalCharacterCode(code)
	}
	value, err := strconv.ParseFloat(field, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value {
		return 0, false
	}
	return validDecimalCharacterCode(int64(value))
}

func validDecimalCharacterCode(code int64) (rune, bool) {
	if code < 0 || code > utf8.MaxRune || !utf8.ValidRune(rune(code)) {
		return 0, false
	}
	return rune(code), true
}
