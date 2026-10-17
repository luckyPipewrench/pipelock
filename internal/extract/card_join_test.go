// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestJoinCardAtoms(t *testing.T) {
	for _, tt := range []struct {
		name, separator, want string
		atoms                 []DLPAtom
	}{
		{"empty", " ", "", nil},
		{"string neighbors", " ", "a,\x1ft,b", []DLPAtom{{Text: "a", Card: "a"}, {Text: "b", Card: "b"}}},
		{"dot string neighbors", ".", "a,\x1ft,b", []DLPAtom{{Card: "a"}, {Card: "b"}}},
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

func TestCardAtomKeyProvenance(t *testing.T) {
	raw := json.RawMessage(`{"outer":{"4111":1111,"items":[{"label":"1111"},1111]},"tail":null,"last":true}`)
	for _, extracted := range []JSONStringsResult{AllStringsFromJSONResult(raw), AllStringsFromJSONOrderedResult(raw)} {
		var keys, values []string
		for _, atom := range extracted.Atoms {
			if atom.Key {
				keys = append(keys, atom.Text)
			} else {
				values = append(values, atom.Text)
			}
		}
		if !slices.Equal(keys, []string{"outer", "4111", "items", "label", "tail", "last"}) || !slices.Equal(values, []string{"1111", "1111", "1111", "null", "true"}) {
			t.Fatalf("key/value provenance lost: keys=%q values=%q", keys, values)
		}
		for _, key := range keys {
			if !slices.Contains(extracted.Strings, key) {
				t.Fatalf("ordinary scan lost key %q", key)
			}
		}
	}
}

func TestJoinCardAtomsSkipsOnlyKeys(t *testing.T) {
	for _, tt := range []struct {
		name  string
		atoms []DLPAtom
		want  string
	}{
		{"keys only", []DLPAtom{{Card: "4111", Key: true}, {Card: "1111", Key: true}}, ""},
		{"labels between numbers", []DLPAtom{{Card: "a", Key: true}, {Card: "4111", Number: true}, {Card: "b", Key: true}, {Card: "1111", Number: true}}, "4111" + jsonnumber.NumberBoundary + "1111"},
		{"digit key is not string provenance", []DLPAtom{{Card: "4111", Number: true}, {Card: "1111", Key: true}, {Card: "1111", Number: true}}, "4111" + jsonnumber.NumberBoundary + "1111"},
		{"string value remains a barrier", []DLPAtom{{Card: "4111", Number: true}, {Card: "label", Key: true}, {Card: "break"}, {Card: "1111", Number: true}}, "4111" + jsonnumber.NumberStringBoundary + "break" + jsonnumber.StringNumberBoundary + "1111"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := JoinCardAtoms(tt.atoms, " "); got != tt.want {
				t.Fatalf("join=%q want=%q", got, tt.want)
			}
		})
	}
	// Marker escaping applies to values, even after leading keys were skipped.
	input := jsonnumber.NumberBoundary
	got := JoinCardAtoms([]DLPAtom{{Card: "key", Key: true}, {Card: input}}, " ")
	if strings.Contains(got, jsonnumber.NumberBoundary) {
		t.Fatal("value forged a typed number boundary")
	}
}
