// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// jsonNumberOf is a test helper that constructs a json.Number from a string.
func jsonNumberOf(s string) json.Number {
	return json.Number(s)
}

func TestCanonicalize_SortsObjectKeys(t *testing.T) {
	t.Parallel()
	in := map[string]any{"b": 2, "a": 1}
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := []byte(`{"a":1,"b":2}`)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalize_NoWhitespace(t *testing.T) {
	t.Parallel()
	in := map[string]any{"a": []any{1, 2, 3}}
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := []byte(`{"a":[1,2,3]}`)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalize_RFC8785NumberRepresentation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"zero", 0, "0"},
		{"int", 42, "42"},
		{"negative", -7, "-7"},
		{"max safe int", int64(9007199254740992), "9007199254740992"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize(tc.in)
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCanonicalize_RejectsFloats(t *testing.T) {
	t.Parallel()
	_, err := Canonicalize(3.14)
	if err == nil {
		t.Error("expected error for raw float, got nil")
	}
}

func TestCanonicalize_StringsNFCNormalized(t *testing.T) {
	t.Parallel()
	// "Å" can be represented as U+00C5 (NFC) or U+0041 U+030A (NFD).
	// JCS sees both as different bytes; we require NFC pre-normalization.
	nfc := "Å"  // 1 codepoint NFC
	nfd := "Å" // 2 codepoints, decomposed
	got1, err := Canonicalize(nfc)
	if err != nil {
		t.Fatalf("Canonicalize NFC: %v", err)
	}
	got2, err := Canonicalize(nfd)
	if err != nil {
		t.Fatalf("Canonicalize NFD: %v", err)
	}
	if !bytes.Equal(got1, got2) {
		t.Errorf("NFC and NFD inputs produced different canonical bytes; want NFC normalization to make them equal. got1=%q got2=%q", got1, got2)
	}
}

func TestCanonicalize_RejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	// Duplicate-key rejection happens at parse boundary; Canonicalize over
	// a Go map cannot encounter duplicates by construction. This test
	// verifies the parse-time API path: ParseJSONStrict rejects {"a":1,"a":2}.
	_, err := ParseJSONStrict([]byte(`{"a":1,"a":2}`))
	if err == nil {
		t.Error("expected duplicate-key rejection, got nil")
	}
}

func TestCanonicalize_NFCKeyLookupDoesNotMissValue(t *testing.T) {
	t.Parallel()
	// Build a map keyed with NFD bytes; the canonicalizer must look up the
	// value using the original (NFD) key, not the NFC-normalized form, or
	// the value would silently become its zero value.
	nfd := "Å" // "Å" decomposed
	in := map[string]any{nfd: 42}
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	// NFC form in output ("Å"), value preserved
	want := []byte("{\"Å\":42}")
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalize_NFCKeyCollisionRejected(t *testing.T) {
	t.Parallel()
	// Distinct original keys (NFC vs NFD form of "Å") collide once normalized.
	// Must error rather than silently overwrite the lexically-later value.
	in := map[string]any{
		"Å":  1, // NFC "Å"
		"Å": 2, // NFD "Å"
	}
	if len(in) != 2 {
		t.Fatalf("test setup: map collapsed to %d keys; need 2 distinct byte sequences", len(in))
	}
	_, err := Canonicalize(in)
	if err == nil {
		t.Error("expected NFC collision error, got nil")
	}
}

func TestCanonicalize_BoolBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   bool
		want string
	}{
		{"true", true, "true"},
		{"false", false, "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize(tc.in)
			if err != nil {
				t.Fatalf("Canonicalize(%v): %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCanonicalize_NullBranch(t *testing.T) {
	t.Parallel()
	got, err := Canonicalize(nil)
	if err != nil {
		t.Fatalf("Canonicalize(nil): %v", err)
	}
	if string(got) != "null" {
		t.Errorf("got %q, want %q", got, "null")
	}
}

func TestCanonicalize_UInt64(t *testing.T) {
	t.Parallel()
	got, err := Canonicalize(uint64(42))
	if err != nil {
		t.Fatalf("Canonicalize(uint64(42)): %v", err)
	}
	if string(got) != "42" {
		t.Errorf("got %q, want %q", got, "42")
	}
}

func TestCanonicalize_JSONNumberInteger(t *testing.T) {
	t.Parallel()
	got, err := Canonicalize(jsonNumberOf("99"))
	if err != nil {
		t.Fatalf("Canonicalize(json.Number(99)): %v", err)
	}
	if string(got) != "99" {
		t.Errorf("got %q, want %q", got, "99")
	}
}

func TestCanonicalize_JSONNumberRejectsFractional(t *testing.T) {
	t.Parallel()
	_, err := Canonicalize(jsonNumberOf("3.14"))
	if err == nil {
		t.Error("expected error for fractional json.Number, got nil")
	}
}

func TestCanonicalize_UnsupportedTypeErrors(t *testing.T) {
	t.Parallel()
	_, err := Canonicalize(struct{ X int }{X: 1})
	if err == nil {
		t.Error("expected error for unsupported struct type, got nil")
	}
}

func TestParseJSONStrict_Array(t *testing.T) {
	t.Parallel()
	// Exercise the '[' branch in parseStrictFrom.
	got, err := ParseJSONStrict([]byte(`[1,2,3]`))
	if err != nil {
		t.Fatalf("ParseJSONStrict: %v", err)
	}
	arr, ok := got.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T", got)
	}
	if len(arr) != 3 {
		t.Errorf("expected 3 elements, got %d", len(arr))
	}
}

func TestParseJSONStrict_RejectsBadJSON(t *testing.T) {
	t.Parallel()
	// Exercises the parser error path via io.EOF on truncated input.
	_, err := ParseJSONStrict([]byte(`{ "a": `))
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestParseJSONStrict_ArrayElementError(t *testing.T) {
	t.Parallel()
	// "[null," triggers dec.More()=true after reading null, but then EOF on next element.
	// This exercises the parseStrictValue error branch inside the array case.
	_, err := ParseJSONStrict([]byte(`[null,`))
	if err == nil {
		t.Error("expected error for truncated array (element read), got nil")
	}
}

func TestParseJSONStrict_ArrayClosingTokenError(t *testing.T) {
	t.Parallel()
	// "[[" has an outer array containing an inner array that's missing its closing ']'.
	// The inner array empties immediately (dec.More()=false), then dec.Token() for ']'
	// returns EOF, hitting the closing-token error branch.
	_, err := ParseJSONStrict([]byte(`[[`))
	if err == nil {
		t.Error("expected error for truncated nested array (closing token), got nil")
	}
}

func TestParseJSONStrict_ObjectClosingTokenError(t *testing.T) {
	t.Parallel()
	// `{"a":1` is missing the closing `}`. After reading the value, dec.More() returns
	// false, but dec.Token() for `}` returns EOF, hitting the object closing-token error.
	_, err := ParseJSONStrict([]byte(`{"a":1`))
	if err == nil {
		t.Error("expected error for truncated object (closing token), got nil")
	}
}

func TestCanonicalize_RejectsInvalidUTF8Key(t *testing.T) {
	t.Parallel()
	// In Go, a map[string]any key can contain invalid UTF-8 bytes by construction.
	// Canonicalize must reject such keys rather than producing invalid JSON.
	invalidKey := string([]byte{0xff, 0xfe, 0x41}) // invalid UTF-8 bytes
	in := map[string]any{invalidKey: 1}
	_, err := Canonicalize(in)
	if err == nil {
		t.Error("expected error for invalid UTF-8 map key, got nil")
	}
}

func TestCanonicalize_ArrayContainsUnsupportedType(t *testing.T) {
	t.Parallel()
	// An array containing an unsupported type (struct) must propagate the error
	// through the canonicalizeInto recursion for the array case.
	in := []any{struct{ X int }{X: 1}}
	_, err := Canonicalize(in)
	if err == nil {
		t.Error("expected error for unsupported type inside array, got nil")
	}
}

func TestCanonicalize_MapContainsUnsupportedValue(t *testing.T) {
	t.Parallel()
	// A map value that is an unsupported type must propagate the error through
	// the map branch of canonicalizeInto.
	in := map[string]any{"key": struct{ X int }{X: 1}}
	_, err := Canonicalize(in)
	if err == nil {
		t.Error("expected error for unsupported type as map value, got nil")
	}
}

func TestParseStrictFrom_UnexpectedDelimiter(t *testing.T) {
	t.Parallel()
	// parseStrictFrom dispatches on json.Delim — only '{' and '[' are valid.
	// Passing ']' exercises the default: branch inside the Delim switch (line 187-189).
	// The decoder is not used for this token so any reader works.
	dec := json.NewDecoder(bytes.NewReader([]byte(`null`)))
	_, err := parseStrictFrom(dec, json.Delim(']'))
	if err == nil {
		t.Error("expected error for unexpected delimiter ']', got nil")
	}
}

func TestParseStrictFrom_UnexpectedTokenType(t *testing.T) {
	t.Parallel()
	// json.Token is interface{}. Passing a type that is not json.Delim, json.Number,
	// string, bool, or nil hits the outer default: branch (line 194-196).
	dec := json.NewDecoder(bytes.NewReader([]byte(`null`)))
	_, err := parseStrictFrom(dec, 42) // int is not a recognized json.Token type
	if err == nil {
		t.Error("expected error for unrecognized token type int, got nil")
	}
}

func TestParseStrictFrom_ObjectKeyTokenError(t *testing.T) {
	t.Parallel()
	// A truncated object stream (`{"`) makes dec.Token() error while reading
	// the object key, exercising the err != nil return inside the '{' branch.
	dec := json.NewDecoder(bytes.NewReader([]byte(`{"`)))
	tok, err := dec.Token() // reads '{'
	if err != nil {
		t.Fatalf("expected '{' token, got err: %v", err)
	}
	_, err = parseStrictFrom(dec, tok) // tok == json.Delim('{')
	if err == nil {
		t.Error("expected error from truncated object key read, got nil")
	}
}

func TestParseJSONStrict_RejectsTrailingTokens(t *testing.T) {
	t.Parallel()
	_, err := ParseJSONStrict([]byte(`{"a":1} junk`))
	if !errors.Is(err, ErrTrailingTokens) {
		t.Errorf("got %v, want ErrTrailingTokens", err)
	}
}

func TestParseJSONStrict_AcceptsTrailingWhitespace(t *testing.T) {
	t.Parallel()
	// Trailing whitespace (e.g., newline) is OK — it is not a token.
	_, err := ParseJSONStrict([]byte("{\"a\":1}" + "\n"))
	if err != nil {
		t.Errorf("trailing whitespace rejected: %v", err)
	}
}
