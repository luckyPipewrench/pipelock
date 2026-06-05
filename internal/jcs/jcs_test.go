// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jcs

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestFormatNumber covers the RFC 8785 / ES6 number serialization boundary
// vectors. These are the cases where a naive strconv.FormatFloat diverges from
// the canonical form, so getting them exactly right is what proves parity with
// a third-party JCS signer.
func TestFormatNumber(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{math.Copysign(0, -1), "0"}, // negative zero normalizes to "0"
		{1, "1"},
		{-1, "-1"},
		{1.5, "1.5"},
		{-1.5, "-1.5"},
		{0.5, "0.5"},
		{10, "10"},
		{100, "100"},
		{100000, "100000"},
		{0.1, "0.1"},
		{2, "2"},
		{2.5, "2.5"},
		// Fixed/exponential threshold: [1e-6, 1e21) is fixed, else exponential.
		{1e-6, "0.000001"},
		{1e-7, "1e-7"}, // below 1e-6 -> exponential, padded exponent zero stripped
		{4.5e-6, "0.0000045"},
		{1e20, "100000000000000000000"}, // below 1e21 -> fixed
		{1e21, "1e+21"},                 // at threshold -> exponential
		{1e22, "1e+22"},
		// Integer precision at the IEEE754 boundary.
		{9007199254740992, "9007199254740992"}, // 2^53
		{9007199254740994, "9007199254740994"}, // 2^53 + 2
		// Extremes.
		{5e-324, "5e-324"}, // smallest positive subnormal
		{1.7976931348623157e308, "1.7976931348623157e+308"}, // max float64
		{-1.7976931348623157e308, "-1.7976931348623157e+308"},
		// Exponent leading-zero strip (Go emits 1e-09, ES6 wants 1e-9).
		{1e-9, "1e-9"},
		{1e23, "1e+23"},
		// RFC 8785 Appendix-B-style ES6 edge vectors.
		{-5e-324, "-5e-324"},
		{333333333.33333329, "333333333.3333333"},
		{1e30, "1e+30"},
		{4.5, "4.5"},
		{2e-3, "0.002"},
		{1e-27, "1e-27"},
		{9.999999999999997e-7, "9.999999999999997e-7"},
		{999999999999999700000, "999999999999999700000"},
		{295147905179352830000, "295147905179352830000"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got, err := formatNumber(tc.in)
			if err != nil {
				t.Fatalf("formatNumber(%v) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("formatNumber(%v) = %q, want %q", tc.in, got, tc.want)
			}
			// Round-trip property: the canonical string must parse back to the
			// exact same float64 bit pattern (skip the -0 normalization case,
			// whose canonical form "0" intentionally changes the sign bit).
			if tc.want != "0" {
				rt, perr := strconv.ParseFloat(got, 64)
				if perr != nil {
					t.Fatalf("canonical %q does not parse: %v", got, perr)
				}
				if math.Float64bits(rt) != math.Float64bits(tc.in) {
					t.Fatalf("round-trip %q -> bits %x != input bits %x", got, math.Float64bits(rt), math.Float64bits(tc.in))
				}
			}
		})
	}
}

func TestFormatNumberRejectsNonFinite(t *testing.T) {
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := formatNumber(f); err == nil {
			t.Fatalf("formatNumber(%v) should reject non-finite", f)
		}
	}
}

// TestCanonicalizeStringPreservation proves we do NOT NFC-normalize strings.
// An NFD-composed key/value must survive byte-for-byte (decoded), unlike the
// contract package canonicalizer which NFC-folds.
func TestCanonicalizeStringPreservation(t *testing.T) {
	// U+00E9 (precomposed) vs U+0065 U+0301 (e + combining acute). These are
	// distinct Unicode strings; JCS must keep them distinct.
	precomposed := "é"
	decomposed := "é"
	in := `{"` + decomposed + `":1,"` + precomposed + `":2}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}
	if !strings.Contains(string(got), decomposed) {
		t.Fatalf("decomposed form was altered (NFC applied?): %q", got)
	}
	if !strings.Contains(string(got), precomposed) {
		t.Fatalf("precomposed form was altered: %q", got)
	}
}

// TestCanonicalizeKeyOrderingUTF16 proves keys are ordered by UTF-16 code units
// (RFC 8785 §3.2.3), NOT by Unicode code point. An astral character (U+1F600,
// high surrogate 0xD83D) must sort BEFORE U+FFFF (single code unit 0xFFFF),
// which is the opposite of code-point ordering.
func TestCanonicalizeKeyOrderingUTF16(t *testing.T) {
	emoji := "\U0001F600"
	bmp := "￿"
	in := `{"` + bmp + `":1,"` + emoji + `":2}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}
	iEmoji := strings.Index(string(got), emoji)
	iBMP := strings.Index(string(got), bmp)
	if iEmoji < 0 || iBMP < 0 {
		t.Fatalf("keys missing from output: %q", got)
	}
	if iEmoji > iBMP {
		t.Fatalf("UTF-16 ordering violated: emoji should precede U+FFFF, got %q", got)
	}
}

// TestCanonicalizeBasicOrdering covers ASCII key sorting and value passthrough.
func TestCanonicalizeBasicOrdering(t *testing.T) {
	in := `{"b":1,"a":2,"c":{"z":true,"y":null}}`
	want := `{"a":2,"b":1,"c":{"y":null,"z":true}}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("Canonicalize = %q, want %q", got, want)
	}
}

// TestCanonicalizeNumbersInStructure verifies numbers are re-serialized per ES6
// inside a structure (1.0 -> 1, 1e2 -> 100).
func TestCanonicalizeNumbersInStructure(t *testing.T) {
	in := `{"a":1.0,"b":1e2,"c":[0.1,1e-7]}`
	want := `{"a":1,"b":100,"c":[0.1,1e-7]}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("Canonicalize = %q, want %q", got, want)
	}
}

// TestCanonicalizeControlCharEscaping verifies RFC 8785 §3.2.2.2 escaping: tab
// uses the short \t escape, U+0001 uses , quote and backslash are escaped.
func TestCanonicalizeControlCharEscaping(t *testing.T) {
	// in (interpreted) is the JSON  {"k":"a\tbc\"d\\e"}
	in := "{\"k\":\"a\\tb\\u0001c\\\"d\\\\e\"}"
	// want (interpreted) is the canonical {"k":"a\tbc\"d\\e"}
	want := "{\"k\":\"a\\tb\\u0001c\\\"d\\\\e\"}"
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("Canonicalize = %q, want %q", got, want)
	}
}

func TestParseRejectsDuplicateKeys(t *testing.T) {
	_, err := Canonicalize([]byte(`{"a":1,"a":2}`))
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("expected ErrDuplicateKey, got %v", err)
	}
}

func TestParseRejectsTrailingTokens(t *testing.T) {
	_, err := Canonicalize([]byte(`{"a":1} {"b":2}`))
	if !errors.Is(err, ErrTrailingTokens) {
		t.Fatalf("expected ErrTrailingTokens, got %v", err)
	}
}

func TestParseRejectsNestedDuplicateKeys(t *testing.T) {
	_, err := Canonicalize([]byte(`{"a":{"x":1,"x":2}}`))
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("expected ErrDuplicateKey for nested dup, got %v", err)
	}
}

func TestParseRejectsInvalidUnicode(t *testing.T) {
	cases := map[string][]byte{
		"invalid utf8":         {'"', 0xff, '"'},
		"unpaired high":        []byte(`"\uD834"`),
		"unpaired low":         []byte(`"\uDD1E"`),
		"high followed by x":   []byte(`"\uD834\u0041"`),
		"high followed by eof": []byte(`"\uD834\u"`),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Canonicalize(input)
			if !errors.Is(err, ErrInvalidUnicode) {
				t.Fatalf("expected ErrInvalidUnicode, got %v", err)
			}
		})
	}
}

func TestParseAllowsValidSurrogatePair(t *testing.T) {
	got, err := Canonicalize([]byte(`{"music":"\uD834\uDD1E"}`))
	if err != nil {
		t.Fatalf("valid surrogate pair should be accepted: %v", err)
	}
	if string(got) != `{"music":"𝄞"}` {
		t.Fatalf("Canonicalize = %q, want musical symbol", got)
	}
}

func TestMarshalRejectsInvalidUTF8Strings(t *testing.T) {
	_, err := Marshal(string([]byte{0xff}))
	if !errors.Is(err, ErrInvalidUnicode) {
		t.Fatalf("invalid UTF-8 string should return ErrInvalidUnicode, got %v", err)
	}
	_, err = Marshal(map[string]any{string([]byte{0xff}): 1})
	if !errors.Is(err, ErrInvalidUnicode) {
		t.Fatalf("invalid UTF-8 key should return ErrInvalidUnicode, got %v", err)
	}
}

func TestParseAllowsTrailingWhitespace(t *testing.T) {
	got, err := Canonicalize([]byte("{\"a\":1}\n  \t"))
	if err != nil {
		t.Fatalf("trailing whitespace should be allowed: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Fatalf("got %q", got)
	}
}

// TestMarshalAfterSignatureRemoval is the verifier's core need: parse a card,
// drop the top-level "signatures" member, canonicalize the rest deterministically.
func TestMarshalAfterSignatureRemoval(t *testing.T) {
	raw := `{"name":"agent","signatures":[{"protected":"x","signature":"y"}],"version":"1.0"}`
	v, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", v)
	}
	delete(m, "signatures")
	got, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	want := `{"name":"agent","version":"1.0"}`
	if string(got) != want {
		t.Fatalf("Marshal after removal = %q, want %q", got, want)
	}
}

// TestCanonicalizeTopLevelScalar verifies non-object top-level values work.
func TestCanonicalizeTopLevelScalar(t *testing.T) {
	for in, want := range map[string]string{
		`"hi"`:  `"hi"`,
		`true`:  `true`,
		`null`:  `null`,
		`42`:    `42`,
		`[3,1]`: `[3,1]`,
	} {
		got, err := Canonicalize([]byte(in))
		if err != nil {
			t.Fatalf("Canonicalize(%s) error: %v", in, err)
		}
		if string(got) != want {
			t.Fatalf("Canonicalize(%s) = %q, want %q", in, got, want)
		}
	}
}

// TestCanonicalizeIdempotent: canonicalizing canonical output is a no-op.
func TestCanonicalizeIdempotent(t *testing.T) {
	in := `{"z":{"b":[1,2,3],"a":"x"},"a":1.50}`
	once, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	twice, err := Canonicalize(once)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(once) != string(twice) {
		t.Fatalf("not idempotent: %q vs %q", once, twice)
	}
	var a, b any
	_ = json.Unmarshal(once, &a)
	_ = json.Unmarshal(twice, &b)
}
