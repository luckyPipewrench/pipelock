// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// Go's regexp decodes every invalid UTF-8 byte as U+FFFD, so a pattern holding a
// literal U+FFFD matches malformed input. A raw-byte literal gate cannot see that
// match; the gate has to read the simple-folded text, which carries U+FFFD for
// each malformed byte.
func TestResponseGateReplacementRuneMatchesMalformedBytes(t *testing.T) {
	for _, expr := range []string{"fixture-marker�", "(?s)fixture-marker�", "fixture-marker[�]"} {
		t.Run(expr, func(t *testing.T) {
			p := &compiledPattern{name: "fixture", re: regexp.MustCompile(expr)}
			pf := newResponsePreFilter([]*compiledPattern{p})
			content := strings.Repeat("ordinary; ", 420) + "fixture-marker\xff"
			want := matchPatternsAgainst([]*compiledPattern{p}, content)
			if len(want) != 1 {
				t.Fatalf("positive control did not match: %d", len(want))
			}
			if got := matchPatternsPreFiltered(pf, []*compiledPattern{p}, content); len(got) != len(want) {
				t.Fatalf("gate skipped a malformed-byte match: got %d want %d", len(got), len(want))
			}
			short := "fixture-marker\xff"
			if got := matchPatternsPreFiltered(pf, []*compiledPattern{p}, short); len(got) != 1 {
				t.Fatalf("short body lost the match: %d", len(got))
			}
		})
	}
}
