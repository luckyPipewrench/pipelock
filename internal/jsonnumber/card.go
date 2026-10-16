// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// NumberBoundary marks a typed scalar join in the card-only view. It is not
// forwarded content. A comma remains the ordinary view's number barrier;
// this marker lets the separate candidate pass recover only typed joins.
const NumberBoundary = ",\x1f,"

var boundaryRun = regexp.MustCompile(`[0-9]+(?:,+\x1f,[0-9]+)+`)

// These are the existing validateLuhn length bounds. Run enumeration uses
// them only to cap work; the configured regex and validator decide findings.
const (
	cardRunMinDigits = 15
	cardRunMaxDigits = 19
)

// ValidCardNumber applies the card issuer ranges and Luhn checksum used by
// the scanner's luhn validator. The JSON run pass and redactor share it.
func ValidCardNumber(s string) bool {
	var digits [cardRunMaxDigits]byte
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		if n >= len(digits) {
			return false
		}
		digits[n] = s[i] - '0'
		n++
	}
	if n < cardRunMinDigits || !ValidCardIssuer(digits[:n], n) {
		return false
	}
	sum := 0
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i])
		if (n-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// ValidCardIssuer checks the established card network prefixes and lengths.
func ValidCardIssuer(digits []byte, n int) bool {
	prefix4 := int(digits[0])*1000 + int(digits[1])*100 + int(digits[2])*10 + int(digits[3])
	prefix6 := prefix4*100 + int(digits[4])*10 + int(digits[5])
	switch digits[0] {
	case 4:
		return n == 16 || n == 19
	case 5:
		return digits[1] >= 1 && digits[1] <= 5 && n == 16
	case 3:
		if digits[1] == 4 || digits[1] == 7 {
			return n == 15
		}
		return prefix4 >= 3528 && prefix4 <= 3589 && n >= 16 && n <= 19
	case 6:
		if prefix4 == 6011 || (prefix4 >= 6440 && prefix4 <= 6499) ||
			(prefix6 >= 622126 && prefix6 <= 622925) || digits[1] == 5 {
			return n == 16 || n == 19
		}
	case 2:
		return prefix4 >= 2221 && prefix4 <= 2720 && n == 16
	}
	return false
}

func appendCardSubruns(runs []string, pieces []string) []string {
	for start := range pieces {
		var candidate strings.Builder
		for end := start; end < len(pieces); end++ {
			candidate.WriteString(pieces[end])
			size := candidate.Len()
			if size > cardRunMaxDigits {
				break
			}
			if end > start && size >= cardRunMinDigits {
				if value := candidate.String(); ValidCardNumber(value) {
					runs = append(runs, value)
				}
			}
		}
	}
	return runs
}

// BoundaryCardRuns returns runs made by joining typed scalar atoms. A run
// needs a typed boundary, so ordinary comma-separated prose is not promoted.
func BoundaryCardRuns(view string) []string {
	var runs []string
	for _, match := range boundaryRun.FindAllString(view, -1) {
		parts := strings.Split(match, "\x1f,")
		pieces := make([]string, 0, len(parts))
		for _, part := range parts {
			pieces = append(pieces, strings.TrimRight(part, ","))
		}
		runs = appendCardSubruns(runs, pieces)
	}
	return runs
}

// CardRuns returns runs of adjacent JSON scalar values with at least two
// digit-bearing pieces. Object keys are skipped; arrays, object siblings and
// nesting do not break a run. A non-digit value does. Each number contributes
// only its written integer component, preserving the single-number fraction
// policy while still examining separate numbers together. Callers apply their
// existing card rule to these candidates. Invalid, over-depth or over-budget
// documents have no typed run and retain the caller's conservative raw scan.
func CardRuns(text string, maxDepth int) []string {
	runs, _ := CardRunsWithLimit(text, maxDepth)
	return runs
}

// CardRunLimit identifies why a valid JSON document could not be inspected.
type CardRunLimit uint8

const (
	CardRunWithinBudget CardRunLimit = iota
	CardRunDepthLimit
	CardRunNumberLimit
)

// CardRunsWithLimit also reports a valid document whose number or nesting
// exceeds the typed inspection budget. Callers must refuse that document.
// Invalid JSON is left to the transport parser or the ordinary text scan.
func CardRunsWithLimit(text string, maxDepth int) ([]string, CardRunLimit) {
	if !json.Valid([]byte(text)) {
		return nil, CardRunWithinBudget
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
	}
	var stack []frame
	var runs []string
	var pieces []string
	flush := func() {
		runs = appendCardSubruns(runs, pieces)
		pieces = nil
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			flush()
			return runs, CardRunWithinBudget
		}
		if err != nil {
			return nil, CardRunNumberLimit
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				stack = append(stack, frame{object: v == '{', expectKey: v == '{'})
				if len(stack) > maxDepth {
					return nil, CardRunDepthLimit
				}
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				stack[len(stack)-1].expectKey = false
				continue
			}
			if !allDigits(v) {
				flush()
				continue
			}
			pieces = append(pieces, v)
		case json.Number:
			if _, ok := boundedComponents(v.String()); !ok {
				return nil, CardRunNumberLimit
			}
			integer, _, _ := strings.Cut(v.String(), ".")
			integer, _, _ = strings.Cut(integer, "e")
			integer, _, _ = strings.Cut(integer, "E")
			if !allDigits(integer) {
				flush()
				continue
			}
			pieces = append(pieces, integer)
		default:
			flush()
		}
		if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
			stack[len(stack)-1].expectKey = true
		}
	}
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// IntegralView retains the written integer component of a bounded RFC 8259
// number. Pipelock's card policy excludes fraction and exponent syntax; it
// neither evaluates exponents nor rounds numbers. Invalid or over-budget
// spellings retain their original conservative scan view.
//
// Commas preserve byte coordinates and the numeric-leaf channel's value
// separation convention (jsonrpc.ExtractNumericLeaves). Unlike whitespace,
// they survive DLP compaction, so masked numbers cannot fabricate a card by
// joining their integer components. This internal scan view is never parsed
// as JSON or forwarded; known values and other detectors use the original.
func IntegralView(n json.Number) string {
	s := n.String()
	if _, ok := boundedComponents(s); !ok {
		return s
	}
	end := strings.IndexAny(s, ".eE")
	if end < 0 {
		return s
	}
	return s[:end] + strings.Repeat(",", len(s)-end)
}

// CardView applies IntegralView only to numeric tokens in one complete JSON
// document. Strings and keys keep their original spelling; JSON-looking string
// values are never parsed recursively. Malformed or over-depth documents retain
// the original view. maxDepth comes from the consuming JSON extractor's contract.
func CardView(text string, maxDepth int) string {
	if !strings.ContainsAny(text, ".eE") || !json.Valid([]byte(text)) {
		return text
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var view []byte
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return text
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				if depth > maxDepth {
					return text
				}
			} else {
				depth--
			}
		case json.Number:
			if _, ok := boundedComponents(v.String()); !ok {
				return text
			}
			projected := IntegralView(v)
			if projected != v.String() {
				if view == nil {
					view = []byte(text)
				}
				end := int(dec.InputOffset())
				copy(view[end-len(projected):end], projected)
			}
		}
	}
	if view == nil {
		return text
	}
	return string(view)
}

// StructuredCardView applies the numeric policy only to complete JSON objects
// and arrays. Text transports retain ordinary card scanning for scalar payloads.
func StructuredCardView(text string, maxDepth int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return text
	}
	return CardView(text, maxDepth)
}
