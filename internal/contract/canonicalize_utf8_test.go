// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// TestCanonicalizeInvalidUTF8StringMatchesReparse pins that a string value
// holding invalid UTF-8 canonicalizes to the same bytes a verifier produces
// after parsing those bytes and canonicalizing again, on every Go release.
// Go 1.26 and earlier escape the replacement character, Go 1.27 writes it
// raw, and every verifier re-encodes it raw.
func TestCanonicalizeInvalidUTF8StringMatchesReparse(t *testing.T) {
	t.Parallel()

	in := map[string]any{"target": "a" + string([]byte{0xff}) + "b"}
	signed, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if bytes.Contains(signed, []byte("\\ufffd")) {
		t.Fatalf("canonical bytes kept the escaped replacement character: %q", signed)
	}
	parsed, err := ParseJSONStrict(signed)
	if err != nil {
		t.Fatalf("ParseJSONStrict: %v", err)
	}
	again, err := Canonicalize(parsed)
	if err != nil {
		t.Fatalf("Canonicalize after reparse: %v", err)
	}
	if !bytes.Equal(signed, again) {
		t.Fatalf("canonical bytes %q != reparsed canonical bytes %q", signed, again)
	}
}

// TestParseJSONStrictDepthBound pins the nesting bound to the shared
// cross-language limit on every Go release. Go 1.27's json.Decoder stops at
// 10000 levels and earlier releases have no limit, so the bound must not
// depend on the decoder.
func TestParseJSONStrictDepthBound(t *testing.T) {
	t.Parallel()

	nested := func(depth int) []byte {
		return []byte(strings.Repeat("[", depth) + "1" + strings.Repeat("]", depth))
	}
	if _, err := ParseJSONStrict(nested(jsonscan.MaxNestingDepth)); err != nil {
		t.Fatalf("depth %d rejected: %v", jsonscan.MaxNestingDepth, err)
	}
	for _, depth := range []int{jsonscan.MaxNestingDepth + 1, 12000} {
		_, err := ParseJSONStrict(nested(depth))
		if err == nil || !strings.Contains(err.Error(), "nesting exceeds maximum depth") {
			t.Fatalf("depth %d: err = %v, want nesting bound", depth, err)
		}
	}
	obj := []byte(strings.Repeat(`{"a":`, jsonscan.MaxNestingDepth+1) + "1" + strings.Repeat("}", jsonscan.MaxNestingDepth+1))
	if _, err := ParseJSONStrict(obj); err == nil || !strings.Contains(err.Error(), "nesting exceeds maximum depth") {
		t.Fatalf("object depth %d: err = %v, want nesting bound", jsonscan.MaxNestingDepth+1, err)
	}
}
