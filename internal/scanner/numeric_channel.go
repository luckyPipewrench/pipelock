// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
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

	for _, known := range []struct {
		secrets     []string
		patternName string
		encoded     string
	}{
		{s.envSecrets, "Environment Variable Leak", "env"},
		{s.fileSecrets, "Known Secret Leak", encodingDecimal},
	} {
		for _, secret := range known.secrets {
			for _, candidate := range []string{decimalCharacterCodes(secret, ","), decimalCharacterCodes(secret, " ")} {
				if start, end, viewLabel, ok := indexAnyView(candidate, texts); ok {
					matches = append(matches, TextDLPMatch{
						PatternName: known.patternName,
						Severity:    "critical",
						Encoded:     known.encoded,
						span:        newMatchSpan(start, end, viewLabel, known.patternName, "", ""),
					})
					break
				}
			}
		}
	}

	if len(s.canaryTokens) > 0 {
		decodedLower := strings.ToLower(decodeDecimalCharacterCodes(numeric))
		for _, token := range s.canaryTokens {
			needle := token.normalizedLower
			if needle == "" {
				continue
			}
			patternName := "Canary Token (" + token.name + ")"
			if start := strings.Index(numeric, needle); start >= 0 {
				matches = append(matches, TextDLPMatch{
					PatternName: patternName,
					Severity:    "critical",
					span:        newMatchSpan(start, start+len(needle), ViewNumericChannel, patternName, "", ""),
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

// decodeDecimalCharacterCodes turns runs of comma or space separated integers
// that are valid Unicode code points into the text they spell. A leaf that is
// not such a code point (a float, a negative number, a value past the Unicode
// range) ends the current run, and runs shorter than minDecimalCodeRun are
// dropped, so ordinary numeric data decodes to nothing rather than to noise.
// Runs are joined with newlines so a needle cannot straddle two of them.
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
	fields := strings.FieldsFunc(numeric, func(r rune) bool { return r == ',' || r == ' ' })
	for _, field := range fields {
		code, err := strconv.Atoi(field)
		if err != nil || code < 0 || code > utf8.MaxRune || !utf8.ValidRune(rune(code)) {
			flush()
			continue
		}
		run.WriteRune(rune(code))
		runLen++
	}
	flush()
	return out.String()
}
