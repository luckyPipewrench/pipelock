// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

func TestIsCoreCriticalMatch(t *testing.T) {
	tests := []struct {
		name  string
		match TextDLPMatch
		want  bool
	}{
		{
			name:  "core credential pattern",
			match: TextDLPMatch{PatternName: "GitHub Token"},
			want:  true,
		},
		{
			name:  "core pattern name case-insensitive",
			match: TextDLPMatch{PatternName: "aws secret key"},
			want:  true,
		},
		{
			name:  "warn tag cannot downgrade core pattern",
			match: TextDLPMatch{PatternName: "GitHub Token", Warn: true},
			want:  true,
		},
		{
			name:  "non-core pattern",
			match: TextDLPMatch{PatternName: "Stripe Key"},
			want:  false,
		},
		{
			name:  "empty pattern name",
			match: TextDLPMatch{},
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCoreCriticalMatch(tt.match); got != tt.want {
				t.Fatalf("IsCoreCriticalMatch(%+v) = %v, want %v", tt.match, got, tt.want)
			}
		})
	}
}

func TestContainsCoreCriticalMatch(t *testing.T) {
	tests := []struct {
		name    string
		matches []TextDLPMatch
		want    bool
	}{
		{name: "nil", matches: nil, want: false},
		{
			name:    "only non-core",
			matches: []TextDLPMatch{{PatternName: "Stripe Key"}, {PatternName: "Email Address"}},
			want:    false,
		},
		{
			name:    "contains one core",
			matches: []TextDLPMatch{{PatternName: "Stripe Key"}, {PatternName: "AWS Secret Key"}},
			want:    true,
		},
		{
			name:    "warn-tagged core remains immutable",
			matches: []TextDLPMatch{{PatternName: "AWS Secret Key", Warn: true}},
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsCoreCriticalMatch(tt.matches); got != tt.want {
				t.Fatalf("ContainsCoreCriticalMatch = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCoreCriticalResult(t *testing.T) {
	tests := []struct {
		name string
		r    Result
		want bool
	}{
		{
			name: "allowed result is never core-critical",
			r:    Result{Allowed: true, Scanner: ScannerCoreDLP},
			want: false,
		},
		{
			name: "core DLP scanner result",
			r:    Result{Allowed: false, Scanner: ScannerCoreDLP},
			want: true,
		},
		{
			name: "non-core DLP scanner, no spans",
			r:    Result{Allowed: false, Scanner: ScannerDLP},
			want: false,
		},
		{
			name: "non-core scanner but span carries a core pattern name",
			r: Result{
				Allowed: false,
				Scanner: ScannerDLP,
				spans:   []MatchSpan{newMatchSpan(0, 4, "dlp_normalized:url_query", "GitHub Token", "", "")},
			},
			want: true,
		},
		{
			name: "non-core scanner with a non-core span",
			r: Result{
				Allowed: false,
				Scanner: ScannerDLP,
				spans:   []MatchSpan{newMatchSpan(0, 4, "dlp_normalized:url_query", "Stripe Key", "", "")},
			},
			want: false,
		},
		{
			name: "blocked but non-DLP scanner (SSRF) is not core-critical",
			r:    Result{Allowed: false, Scanner: ScannerSSRF},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCoreCriticalResult(tt.r); got != tt.want {
				t.Fatalf("IsCoreCriticalResult(%+v) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}
