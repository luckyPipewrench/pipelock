// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"errors"
	"strings"
	"testing"
)

func TestRejectDuplicateKeys(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		wantDup bool
	}{
		{"clean object", `{"a":1,"b":2}`, false},
		{"clean nested + array", `{"a":1,"b":{"c":2},"d":[{"e":3},{"e":4}]}`, false},
		{"top-level duplicate", `{"a":1,"a":2}`, true},
		{"nested object duplicate", `{"x":{"a":1,"a":2}}`, true},
		{"duplicate in array element", `{"arr":[{"a":1},{"a":1,"a":2}]}`, true},
		{"duplicate after nested value", `{"a":1,"nested":{"b":2},"a":3}`, true},
		{"delimiters inside string value", `{"a":"}{:,","b":2}`, false},
		{"duplicate string-valued keys", `{"a":"x","a":"y"}`, true},
		// json.Decoder decodes \u escapes, so a unicode-escaped key that decodes
		// to the same name MUST be caught — otherwise it is a cross-language
		// smuggling vector. "a" decodes to "a".
		{"unicode-escaped duplicate key", `{"a":1,"\u0061":2}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := RejectDuplicateKeys([]byte(tc.input))
			if tc.wantDup {
				if !errors.Is(err, ErrDuplicateKey) {
					t.Errorf("RejectDuplicateKeys(%s) = %v, want errors.Is ErrDuplicateKey", tc.input, err)
				}
				return
			}
			if err != nil {
				t.Errorf("RejectDuplicateKeys(%s) = %v, want nil", tc.input, err)
			}
		})
	}
}

// TestRejectDuplicateKeys_DepthBounded proves the scanner errors (rather than
// panicking via stack overflow) on maliciously deep nesting. The scan runs
// before json.Unmarshal, which would otherwise be the depth backstop.
func TestRejectDuplicateKeys_DepthBounded(t *testing.T) {
	t.Parallel()

	// Exactly MaxNestingDepth levels are accepted.
	maxDepth := strings.Repeat("[", MaxNestingDepth) + "1" + strings.Repeat("]", MaxNestingDepth)
	if err := RejectDuplicateKeys([]byte(maxDepth)); err != nil {
		t.Errorf("max-depth nesting rejected: %v", err)
	}

	// Over-deep nesting must produce an error, not a panic.
	depth := MaxNestingDepth + 1
	deep := strings.Repeat("[", depth) + "1" + strings.Repeat("]", depth)
	if err := RejectDuplicateKeys([]byte(deep)); err == nil {
		t.Fatal("expected error on over-deep nesting, got nil")
	}
}

// TestRejectDuplicateKeys_EmptyAndScalar defers malformed/empty input to the
// caller's json.Unmarshal (returns nil) and accepts bare scalars.
func TestRejectDuplicateKeys_EmptyAndScalar(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "   ", "123", `"x"`, "true", "null"} {
		if err := RejectDuplicateKeys([]byte(in)); err != nil {
			t.Errorf("RejectDuplicateKeys(%q) = %v, want nil (defer to json.Unmarshal)", in, err)
		}
	}
}

func TestRejectDuplicateKeys_MalformedAfterStart(t *testing.T) {
	t.Parallel()
	for _, in := range []string{`{"a":`, `{"a":1`, `[1,`, `{"a":{"b":`} {
		if err := RejectDuplicateKeys([]byte(in)); err == nil {
			t.Errorf("RejectDuplicateKeys(%q) = nil, want malformed JSON error", in)
		}
	}
}
