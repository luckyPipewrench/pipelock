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
			name:  "warn-tagged core pattern is excluded",
			match: TextDLPMatch{PatternName: "GitHub Token", Warn: true},
			want:  false,
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
			name:    "core but warn-tagged",
			matches: []TextDLPMatch{{PatternName: "AWS Secret Key", Warn: true}},
			want:    false,
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
