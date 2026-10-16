// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"encoding/json"
	"io"
	"strings"
)

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
