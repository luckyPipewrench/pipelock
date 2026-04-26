// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"testing"
)

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
	nfc := "Å" // 1 codepoint
	nfd := "Å" // 2 codepoints, decomposed
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
	want := []byte("{\"Å\":42}") // NFC form in output, value preserved
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
