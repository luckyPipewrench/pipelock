// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jcs

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestParseRejectsMalformed covers the parser error branches: truncated input,
// a stray closing delimiter, and an incomplete value.
func TestParseRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		`}`,            // stray delimiter as first token
		`{`,            // unterminated object
		`{"a":}`,       // missing value
		`{"a":1,}`,     // trailing comma
		`[1,2`,         // unterminated array
		``,             // empty input
		`nul`,          // invalid literal
		`{"a" 1}`,      // missing colon
		`[1 2]`,        // missing comma
		`{"a":[1,]}`,   // trailing comma in nested array
		`{"a":1} @bad`, // trailing non-whitespace that fails to tokenize
	} {
		t.Run(in, func(t *testing.T) {
			if _, err := Canonicalize([]byte(in)); err == nil {
				t.Fatalf("Canonicalize(%q) should error", in)
			}
		})
	}
}

// TestMarshalUnsupportedType covers the marshalInto default branch.
func TestMarshalUnsupportedType(t *testing.T) {
	if _, err := Marshal(struct{ X int }{X: 1}); err == nil {
		t.Fatal("Marshal of unsupported type should error")
	}
	// Unsupported value nested in a container also errors.
	if _, err := Marshal([]any{struct{}{}}); err == nil {
		t.Fatal("Marshal of unsupported nested type should error")
	}
	if _, err := Marshal(map[string]any{"k": struct{}{}}); err == nil {
		t.Fatal("Marshal of unsupported map value should error")
	}
}

// TestMarshalFloat64 covers the float64 marshalInto branch (Parse yields
// json.Number, but Marshal accepts raw float64 too).
func TestMarshalFloat64(t *testing.T) {
	got, err := Marshal(map[string]any{"a": float64(1.5), "b": float64(100)})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(got) != `{"a":1.5,"b":100}` {
		t.Fatalf("got %q", got)
	}
}

// TestMarshalInvalidNumber covers the json.Number ParseFloat error branch.
func TestMarshalInvalidNumber(t *testing.T) {
	if _, err := Marshal(json.Number("not-a-number")); !errors.Is(err, ErrInvalidNumber) {
		t.Fatalf("expected ErrInvalidNumber, got %v", err)
	}
	// Non-finite values cannot be represented in JSON.
	if _, err := Marshal(json.Number("1e999")); !errors.Is(err, ErrInvalidNumber) {
		t.Fatalf("expected ErrInvalidNumber for overflow, got %v", err)
	}
}

// TestStringAllEscapes exercises every short-escape branch and a high code point.
func TestStringAllEscapes(t *testing.T) {
	in := "{\"k\":\"\\b\\f\\r\\n\\t\\\"\\\\\\u0000\\u001f\"}"
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := "{\"k\":\"\\b\\f\\r\\n\\t\\\"\\\\\\u0000\\u001f\"}"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// A high (non-ASCII, non-control) code point passes through literally.
	g2, err := Canonicalize([]byte(`{"k":"日本語"}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(string(g2), "日本語") {
		t.Fatalf("non-ASCII should pass through literally: %q", g2)
	}
}

// TestParseAcceptsEscapedBackslashThenU covers the escaped-backslash path in the
// surrogate scanner (\\u is a literal backslash + 'u', not an escape sequence,
// so the high-surrogate bytes here are plain data and must NOT be rejected).
func TestParseAcceptsEscapedBackslashThenU(t *testing.T) {
	got, err := Canonicalize([]byte(`{"k":"\\uD83D"}`))
	if err != nil {
		t.Fatalf("escaped backslash before u must be fine: %v", err)
	}
	if string(got) != `{"k":"\\uD83D"}` {
		t.Fatalf("got %q", got)
	}
}

// TestParseRejectsDeepNesting proves recursion is bounded: a payload nested past
// maxParseDepth returns ErrMaxDepth instead of overflowing the stack.
func TestParseRejectsDeepNesting(t *testing.T) {
	deep := strings.Repeat("[", 600) + strings.Repeat("]", 600)
	if _, err := Canonicalize([]byte(deep)); !errors.Is(err, ErrMaxDepth) {
		t.Fatalf("expected ErrMaxDepth, got %v", err)
	}
	// A nesting depth within the bound still parses.
	ok := strings.Repeat("[", 100) + strings.Repeat("]", 100)
	if _, err := Canonicalize([]byte(ok)); err != nil {
		t.Fatalf("within-bound nesting should parse: %v", err)
	}
}

// TestKeyOrderingPrefix covers the lessUTF16 length tiebreak ("a" < "ab").
func TestKeyOrderingPrefix(t *testing.T) {
	got, err := Canonicalize([]byte(`{"ab":1,"a":2}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(got) != `{"a":2,"ab":1}` {
		t.Fatalf("prefix ordering wrong: %q", got)
	}
}
