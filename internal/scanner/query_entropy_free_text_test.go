// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// Free text such as a search query is scored one whitespace token at a time,
// under the same 20-character / 4.50 gate as every other value, with no
// exemption keyed to a parameter name. Words pass; random text does not, even
// when it is split into pieces shorter than the length floor.
func TestScan_QueryEntropyFreeTextIsScoredPerToken(t *testing.T) {
	cfg := queryEntropyParamExclusionTestConfig()
	cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = nil
	s := MustNew(cfg)
	defer s.Close()

	random := "Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl"
	tests := []struct {
		name      string
		param     string
		value     string
		wantAllow bool
	}{
		{"ordinary words", "query", "best vegetarian restaurants near the old town square with outdoor seating", true},
		{"ordinary words under another name", "q", "how to reset a forgotten password on the customer dashboard", true},
		{"search syntax punctuation", "query", `"project plan" AND (status:open OR status:blocked) -label:archived sort:updated`, true},
		{"random token beside words", "query", "reset my password " + random, false},
		{"random text split below the length floor", "query", strings.Join(splitEvery(random, 8), " "), false},
		{"random text joined by spaces and punctuation", "search", strings.Join(splitEvery(random, 6), ", "), false},
		{"single random token", "query", random, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Scan(context.Background(), "https://api.vendor.example/v1/search/recent?"+tt.param+"="+url.QueryEscape(tt.value))
			if got.Allowed != tt.wantAllow {
				t.Fatalf("Allowed = %v (%s), want %v", got.Allowed, got.Reason, tt.wantAllow)
			}
		})
	}
}

func splitEvery(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}
