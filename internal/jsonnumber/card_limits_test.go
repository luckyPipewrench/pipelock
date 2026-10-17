// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardNumberBoundsAndIssuer(t *testing.T) {
	if !ValidCardNumber(cardtest.Number()) {
		t.Fatal("valid control rejected")
	}
	if ValidCardNumber(cardtest.Number() + "1234") {
		t.Fatal("overlong card accepted")
	}
	for _, tt := range []struct {
		prefix string
		length int
		valid  bool
	}{
		{"6011", 16, true},
		{"6440", 19, true},
		{"6499", 16, true},
		{"622126", 16, true},
		{"622925", 19, true},
		{"65", 16, true},
		{"6011", 17, false},
		{"6439", 16, false},
		{"6500", 15, false},
		{"622125", 16, false},
		{"622926", 16, false},
	} {
		t.Run(tt.prefix+strings.Repeat("x", tt.length), func(t *testing.T) {
			digits := make([]byte, tt.length)
			for i, c := range []byte(tt.prefix) {
				digits[i] = c - '0'
			}
			if got := ValidCardIssuer(digits, tt.length); got != tt.valid {
				t.Fatalf("issuer valid=%v want=%v", got, tt.valid)
			}
		})
	}
}

func TestBoundaryCardRunBarriers(t *testing.T) {
	for _, text := range []string{"ordinary prose", "x" + NumberBoundary + "1234", "1234" + NumberBoundary + "x"} {
		if runs := BoundaryCardRuns(text); len(runs) != 0 {
			t.Fatal("non-numeric boundary generated evidence")
		}
	}
	card := cardtest.Number()
	if runs := BoundaryCardRuns(card[:8] + NumberBoundary + card[8:]); len(runs) == 0 || !runs[0].NumberOnly {
		t.Fatal("number-only control lost evidence")
	}
}
