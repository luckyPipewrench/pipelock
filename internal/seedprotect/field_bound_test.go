// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// referenceRawFields counts non-empty fields with an independent split.
func referenceRawFields(text string) int {
	fields := 0
	inField := false
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if isSeedSeparator(r) {
			inField = false
		} else if !inField {
			inField = true
			fields++
		}
		i += size
	}
	return fields
}

func checkFieldBound(t *testing.T, text string) {
	t.Helper()
	fields := referenceRawFields(text)
	tokens := tokenizeWithSpans(text)
	if len(tokens) > fields {
		t.Fatalf("%d tokens exceed %d raw fields for %q", len(tokens), fields, text)
	}
	for _, want := range []int{-1, 0, 1, 2, 11, 12, 13, 15, 24, 25} {
		if got := hasRawFields(text, want); got != (fields >= want) {
			t.Fatalf("hasRawFields(%q, %d) = %v with %d fields", text, want, got, fields)
		}
	}
	for _, minWords := range []int{0, 1, 12, 15, 18, 24, 30} {
		for _, verify := range []bool{true, false} {
			got := DetectSpans(text, minWords, verify)
			want := detectSpansInTokens(tokens, minWords, verify)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("DetectSpans(%q, %d, %v) = %+v, unbounded reference %+v", text, minWords, verify, got, want)
			}
		}
	}
}

func TestRawFieldBoundMatchesUnboundedDetector(t *testing.T) {
	words := strings.Fields(valid12)
	separators := []string{" ", ",", "\n", "-", "\u2013", "\u00a0", "\u200b", "\"", "'", "(", ")", "|", ".", "", "  ", "\xff", "\u3000", ", "}
	inputs := []string{"", " ", "abandon", valid12, valid24, strings.Repeat("abandon ", 11), strings.Repeat("abandon ", 11) + "about ", `{"seed":"` + valid12 + `"}`}
	for _, sep := range separators {
		inputs = append(inputs, strings.Join(words, sep), sep+strings.Join(words, sep)+sep, strings.Join(words[:11], sep), strings.Join(words, sep)+sep+"x")
		inputs = append(inputs, strings.Join(strings.Fields(valid24), sep))
	}
	for _, input := range inputs {
		checkFieldBound(t, input)
	}
	rng := &testBytes{state: 3004}
	alphabet := []string{"abandon", "about", "art", "zoo", " ", ",", "\t", "\u2014", "\u00a0", "\xff", "\u200b", "\"", "[", "x", "\u0430bandon", "ABANDON", "\u3000", ":"}
	raw := make([]byte, 96)
	for range 4000 {
		var b strings.Builder
		for range rng.IntN(40) {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		checkFieldBound(t, b.String())
		n := 1 + rng.IntN(len(raw))
		rng.fill(raw[:n])
		data := raw[:n]
		checkFieldBound(t, string(data))
		if decoded, err := hex.DecodeString(hex.EncodeToString(data)); err == nil {
			checkFieldBound(t, string(decoded))
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(hex.EncodeToString(data)); err == nil {
			checkFieldBound(t, string(decoded))
		}
	}
}

func FuzzRawFieldBound(f *testing.F) {
	for _, seed := range []string{"", valid12, valid24, "abandon,\xffabandon", "\"" + valid12 + "\""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		checkFieldBound(t, text)
	})
}

func TestSeedSeparatorFastMatchesReference(t *testing.T) {
	for r := rune(-1); r <= utf8.MaxRune+1; r++ {
		if got, want := isSeedSeparatorFast(r), isSeedSeparator(r); got != want {
			t.Fatalf("isSeedSeparatorFast(U+%04X) = %v, want %v", r, got, want)
		}
	}
}

// testBytes is a deterministic splitmix64 byte source for differential tests.
type testBytes struct{ state uint64 }

func (r *testBytes) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// IntN returns a value in [0, n) for n > 0; modulo bias does not matter here.
func (r *testBytes) IntN(n int) int {
	if n <= 0 {
		panic("testBytes.IntN: n must be positive")
	}
	return int(r.next()>>1) % n
}

func (r *testBytes) fill(b []byte) {
	for i := range b {
		b[i] = byte(r.next() & 0xff)
	}
}
