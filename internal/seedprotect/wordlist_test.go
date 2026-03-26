// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import "testing"

const (
	testWordAbandon = "abandon"
	testWordZoo     = "zoo"
)

func TestIndexOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		word string
		want int
	}{
		{"first word abandon", testWordAbandon, 0},
		{"second word ability", "ability", 1},
		{"last word zoo", testWordZoo, 2047},
		{"not found", "zzzznotaword", -1},
		{"empty string", "", -1},
		{"uppercase not found", "ABANDON", -1},
		{"mixed case not found", "Abandon", -1},
		{"partial word", "aban", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IndexOf(tt.word)
			if got != tt.want {
				t.Errorf("IndexOf(%q) = %d, want %d", tt.word, got, tt.want)
			}
		})
	}
}

func TestIsWordConsistency(t *testing.T) {
	t.Parallel()

	// IndexOf and IsWord must agree.
	tests := []struct {
		word       string
		wantIsWord bool
	}{
		{testWordAbandon, true},
		{testWordZoo, true},
		{"notaword", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.word, func(t *testing.T) {
			t.Parallel()
			if got := IsWord(tt.word); got != tt.wantIsWord {
				t.Errorf("IsWord(%q) = %v, want %v", tt.word, got, tt.wantIsWord)
			}
			if tt.wantIsWord {
				if idx := IndexOf(tt.word); idx < 0 {
					t.Errorf("IndexOf(%q) = %d, but IsWord returned true", tt.word, idx)
				}
			} else {
				if idx := IndexOf(tt.word); idx >= 0 {
					t.Errorf("IndexOf(%q) = %d, but IsWord returned false", tt.word, idx)
				}
			}
		})
	}
}
