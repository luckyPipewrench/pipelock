// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import "testing"

func TestQueryUnescapePartial(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ""},
		{"plain", "plain"},
		{"a+b", "a b"},
		{"%41%ZZ%42", "A%ZZB"},
		{"%ZZ%41", "%ZZA"},
		{"%41%", "A%"},
		{"%41%4", "A%4"},
		{"%aF%fF", "\xaf\xff"},
		{"%00+%20", "\x00  "},
		{"%2B", "+"},
		{"%252B", "%2B"},
		{"%4Z%41", "%4ZA"},
		{"%%41", "%A"},
		{"café%41%ZZ", "caféA%ZZ"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := QueryUnescapePartial(tc.input); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
