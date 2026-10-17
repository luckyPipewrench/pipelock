// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

// DLPAtom keeps card spelling, number type and key provenance alongside text.
// Integers retain their original spelling but still have Number set.
type DLPAtom struct {
	Text   string
	Card   string
	Number bool
	Key    bool // object member name: scanned ordinarily, omitted from card joins
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

// JoinCardAtoms preserves every value boundary in the card-only view.
// Object keys are omitted, without interrupting adjacent values.
// Other detectors keep the caller's original text join; card candidates retain
// both the piece boundaries and number types through subsequent scan passes.
func JoinCardAtoms(atoms []DLPAtom, _ string) string {
	var b strings.Builder
	var previousNumber, haveValue bool
	for _, atom := range atoms {
		if atom.Key {
			continue
		}
		if haveValue {
			b.WriteString(jsonnumber.CardBoundary(previousNumber, atom.Number))
		}
		previousNumber, haveValue = atom.Number, true
		if atom.Number {
			b.WriteString(atom.Card)
		} else {
			// Untrusted strings cannot manufacture typed number boundaries.
			b.WriteString(jsonnumber.EscapeCardBoundaries(atom.Card))
		}
	}
	return b.String()
}
