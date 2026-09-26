// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"
	"testing"
)

func TestQueryValueEntropyTokens(t *testing.T) {
	cfg := testConfig()
	s := MustNew(cfg)
	defer s.Close()
	blob := syntheticEntropyToken()
	cases := []struct {
		name, value string
		block       bool
	}{
		// Both score above the threshold as one string, so they pass only
		// because each word is scored on its own.
		{"search syntax", `from:ExampleCo (sandbox OR "prompt injection") lang:en -is:retweet`, false},
		{"grouped search syntax", `("Landlock" OR "seccomp") (agent OR sandbox) -filter:replies`, false},
		{"plain English", "find the latest report about prompt injection research", false},
		{"embedded blob", "foo " + blob + " bar", true},
		{"split blob", blob[:24] + " " + blob[24:], true},
		// Random chunks below the minimum still block: the value is also scored
		// with punctuation and spacing removed.
		{"short chunks", strings.Join([]string{blob[:12], blob[12:24], blob[24:36], blob[36:]}, " "), true},
		{"tiny chunks", strings.Join([]string{blob[:5], blob[5:10], blob[10:15], blob[15:20], blob[20:25]}, " "), true},
		{"search with dates", "#rustlang OR #golang min_faves:100 since:2026-09-01 until:2026-09-25", false},
		{"compact blob", blob, true},
	}
	// Positive control: the search cases must trip the whole-value gate, or
	// they would pass whether or not the value is split into words.
	for _, v := range []string{cases[0].value, cases[1].value} {
		if e := payloadEntropy(v); e <= s.entropyThreshold {
			t.Fatalf("search control %q scores %.3f, not above threshold %.2f", v, e, s.entropyThreshold)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, separator := range []string{"+", "%20"} {
				raw := strings.ReplaceAll(url.QueryEscape(tc.value), "+", separator)
				u, err := url.Parse("https://api.vendor.example/search?q=" + raw)
				if err != nil {
					t.Fatal(err)
				}
				r := s.checkEntropy(u)
				if got := !r.Allowed; got != tc.block {
					t.Errorf("separator %q: blocked=%v, want %v (reason %q)", separator, got, tc.block, r.Reason)
				}
			}
		})
	}
}

// syntheticEntropyToken returns a synthetic 40-character high-entropy token,
// assembled from short pieces so no single source literal reads as a secret.
func syntheticEntropyToken() string {
	return strings.Join([]string{"aB3xK9mZ", "2wQ7rL5y", "N8vC4jF6", "hD1eG0tP", "9sU2qW5z"}, "")
}
