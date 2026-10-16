// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"testing"
)

func TestJoinCardAtoms(t *testing.T) {
	for _, tt := range []struct {
		name, separator, want string
		atoms                 []DLPAtom
	}{
		{"empty", " ", "", nil},
		{"string neighbors", " ", "a b", []DLPAtom{{Text: "a", Card: "a"}, {Text: "b", Card: "b"}}},
		{"dot string neighbors", ".", "a.b", []DLPAtom{{Card: "a"}, {Card: "b"}}},
		{"number boundaries", " ", "a,\x1fn,1234,\x1f,5678,\x1fs,b", []DLPAtom{{Card: "a"}, {Text: "1234", Card: "1234", Number: true}, {Text: "5678", Card: "5678", Number: true}, {Card: "b"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := JoinCardAtoms(tt.atoms, tt.separator); got != tt.want {
				t.Fatalf("join = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCardAtomsPreserveNumberType(t *testing.T) {
	got := AllStringsFromJSONResult(json.RawMessage(`{"key":"1234","integer":1234,"fraction":0.1234,"exponent":1e4}`))
	if len(got.Atoms) != len(got.Strings) || len(got.Atoms) != len(got.CardStrings) {
		t.Fatalf("parallel views differ in length: %+v", got)
	}
	var sawInteger, sawFraction, sawExponent, sawString bool
	for _, atom := range got.Atoms {
		switch atom.Text {
		case "1234":
			if atom.Number {
				sawInteger = atom.Card == atom.Text
			} else {
				sawString = atom.Card == atom.Text
			}
		case "0.1234":
			sawFraction = atom.Number && atom.Card != atom.Text
		case "1e4":
			sawExponent = atom.Number && atom.Card != atom.Text
		}
	}
	if !sawInteger || !sawFraction || !sawExponent || !sawString {
		t.Fatalf("number provenance lost: %+v", got.Atoms)
	}
}
