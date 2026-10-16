// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"slices"
	"strings"
	"testing"
)

func TestCardRunPieceClasses(t *testing.T) {
	card := "4111" + "1111" + "1111" + "1111"
	for _, tt := range []struct {
		name, input string
		numberOnly  bool
	}{
		{"numbers", `[4111,1111,1111,1111]`, true},
		{"decimal groups", `[4111.0,1111.0,1111.0,1111.0]`, true},
		{"exponent groups", `[4111e0,1111e-2,1111E2,1111e+1]`, true},
		{"strings", `["4111","1111","1111","1111"]`, false},
		{"string first", `["4111",1111,1111,1111]`, false},
		{"string last", `[4111,1111,1111,"1111"]`, false},
		{"string middle", `[4111,"1111",1111,1111]`, false},
		{"single", `[` + card + `]`, false},
		{"single fraction", `[` + card + `.5]`, false},
		{"single exponent", `[` + card + `e-2]`, false},
		{"negative single", `[-` + card + `.1]`, false},
		{"after prose", `{"a":"report","b":[4111,1111,1111,1111]}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runs, limit := CardRunsWithLimit(tt.input, 64)
			if limit != CardRunWithinBudget || !slices.Contains(runs, CardRun{Digits: card, NumberOnly: tt.numberOnly}) {
				t.Fatalf("candidate class missing: limit=%v count=%d", limit, len(runs))
			}
			for _, run := range runs {
				if run.Digits == card && run.NumberOnly != tt.numberOnly {
					t.Fatal("candidate has conflicting provenance")
				}
			}
		})
	}
}

func TestCardRunInputBoundariesStayStrings(t *testing.T) {
	card := "4111" + "1111" + "1111" + "1111"
	for _, separator := range []string{NumberBoundary, NumberStringBoundary, StringNumberBoundary} {
		text := strings.Join([]string{"4111", "1111", "1111", "1111"}, separator)
		runs := BoundaryCardRuns(EscapeCardBoundaries(text))
		if !slices.Contains(runs, CardRun{Digits: card}) {
			t.Fatal("input boundary lost enforcement or claimed numeric provenance")
		}
	}
}

func TestBoundaryCardRunPieceClasses(t *testing.T) {
	card := "4111" + "1111" + "1111" + "1111"
	for _, types := range [][]bool{{true, true, true, true}, {false, true, true, true}, {true, false, true, true}, {true, true, true, false}} {
		var view strings.Builder
		for i, piece := range []string{"4111", "1111", "1111", "1111"} {
			if i > 0 {
				view.WriteString(CardBoundary(types[i-1], types[i]))
			}
			view.WriteString(piece)
		}
		runs := BoundaryCardRuns(view.String())
		want := !slices.Contains(types, false)
		if !slices.Contains(runs, CardRun{Digits: card, NumberOnly: want}) {
			t.Fatalf("boundary class missing for types %v", types)
		}
	}
	if CardBoundary(false, false) != "" {
		t.Fatal("string boundary must retain caller separator")
	}
}
