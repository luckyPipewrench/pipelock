// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"encoding/json"
	"testing"
)

// esc is the six-byte escape encoding/json writes for an invalid UTF-8 byte
// on Go 1.26 and earlier. It is spelled out so no tool rewrites it.
const esc = "\\ufffd"

func TestNormalizeReplacementEscapes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		in, want string
	}{
		"no escape":             {in: `{"a":"b"}`, want: `{"a":"b"}`},
		"escape":                {in: `"x` + esc + `y"`, want: "\"x\uFFFDy\""},
		"two escapes":           {in: `"` + esc + esc + `"`, want: "\"\uFFFD\uFFFD\""},
		"escaped backslash":     {in: `"\\ufffd"`, want: `"\\ufffd"`},
		"backslash then escape": {in: `"\\` + esc + `"`, want: "\"\\\\\uFFFD\""},
		"other escapes kept":    {in: `"\u003c\n` + esc + `"`, want: "\"\\u003c\\n\uFFFD\""},
		"trailing backslash":    {in: `\`, want: `\`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := string(NormalizeReplacementEscapes([]byte(tc.in))); got != tc.want {
				t.Fatalf("NormalizeReplacementEscapes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeReplacementEscapesMatchesReencode pins the property signing
// relies on: normalized json.Marshal output of a string with invalid UTF-8
// equals json.Marshal of that value after a JSON round trip, on every Go
// release, because the round trip turns each invalid byte into a valid
// U+FFFD that every release writes raw.
func TestNormalizeReplacementEscapesMatchesReencode(t *testing.T) {
	t.Parallel()

	in := map[string]string{"k": "a" + string([]byte{0xff, 0xfe}) + "b\uFFFD<" + esc}
	signed, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	signed = NormalizeReplacementEscapes(signed)

	var parsed map[string]string
	if err := json.Unmarshal(signed, &parsed); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(signed) != string(reencoded) {
		t.Fatalf("signed %q != re-encoded %q", signed, reencoded)
	}
	if want := "a\uFFFD\uFFFDb\uFFFD<" + esc; parsed["k"] != want {
		t.Fatalf("parsed = %q, want %q", parsed["k"], want)
	}
}
