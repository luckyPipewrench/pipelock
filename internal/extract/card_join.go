// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

// DLPAtom keeps the card spelling and JSON number type alongside extracted text.
// Integers retain their original spelling but still have Number set.
type DLPAtom struct {
	Text   string
	Card   string
	Number bool
}

// JSONNumberStreamViews returns the number-only views of one complete JSON
// event. Object keys and string-valued envelope metadata do not interrupt
// numeric evidence at a stream seam. A non-JSON event has no typed view.
func JSONNumberStreamViews(raw []byte) (string, string) {
	if !json.Valid(raw) {
		return "", ""
	}
	extracted := AllStringsFromJSONResult(json.RawMessage(raw))
	if extracted.Truncated {
		return "", ""
	}
	var numbers []DLPAtom
	var texts []string
	for _, atom := range extracted.Atoms {
		if atom.Number {
			numbers = append(numbers, atom)
			texts = append(texts, atom.Text)
		}
	}
	return strings.Join(texts, ""), JoinCardAtoms(numbers, "")
}

// JoinCardAtoms separates JSON numbers with a typed barrier. The primary card
// scan cannot join across it; the candidate pass can inspect only such joins.
// String boundaries retain the caller's join.
func JoinCardAtoms(atoms []DLPAtom, stringSep string) string {
	var b strings.Builder
	for i, atom := range atoms {
		if i > 0 {
			if atoms[i-1].Number || atom.Number {
				b.WriteString(jsonnumber.CardBoundary(atoms[i-1].Number, atom.Number))
			} else {
				b.WriteString(stringSep)
			}
		}
		if atom.Number {
			b.WriteString(atom.Card)
		} else {
			// Untrusted strings cannot manufacture typed number boundaries.
			b.WriteString(jsonnumber.EscapeCardBoundaries(atom.Card))
		}
	}
	return b.String()
}
