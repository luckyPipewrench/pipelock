// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestCardRuns(t *testing.T) {
	card := "4111" + "1111" + "1111" + "1111"
	groups := "4111,1111" + ",1111,1111"
	for _, tt := range []struct {
		name, input string
		want        bool
	}{
		{"array siblings", `[` + groups + `]`, true},
		{"object siblings", `{"a":4111,"b":1111,"c":1111,"d":1111}`, false},
		{"nested values", `{"a":[4111,{"b":1111}],"c":[1111,1111]}`, false},
		{"mixed string and number", `{"a":"4111","b":1111,"c":1111,"d":1111}`, false},
		{"envelope prefix", `{"id":1,"params":{"ids":[` + groups + `]}}`, true},
		{"separate decimals", `[4111.21,1111.22,1111.23,1111.24]`, true},
		{"single decimal", `{"n":0.` + card + `}`, false},
		{"non-digit value breaks run", `{"a":4111,"b":"ordinary","c":1111,"d":1111,"e":1111}`, false},
		{"ordinary telemetry", `[1200.21,3400.22,5600.23,7800.24]`, false},
		{"malformed", `[` + groups, false},
		{"over depth", `[[` + groups + `]]`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			depth := 64
			if tt.name == "over depth" {
				depth = 1
			}
			if got := slices.ContainsFunc(CardRuns(tt.input, depth), func(run CardRun) bool { return run.Digits == card }); got != tt.want {
				t.Fatalf("candidate found=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestCardRunsOverLimit(t *testing.T) {
	for _, input := range []string{
		`{"n":` + strings.Repeat("9", maxNumberChars+1) + `}`,
		`[[1]]`,
	} {
		depth := 64
		if input == `[[1]]` {
			depth = 1
		}
		if _, limit := CardRunsWithLimit(input, depth); limit == CardRunWithinBudget {
			t.Fatal("valid JSON exceeded the typed inspection limit without reporting it")
		}
	}
}

func TestBoundaryCardRuns(t *testing.T) {
	card := "4111" + "1111" + "1111" + "1111"
	view := "4111,," + NumberBoundary + "1111,," + NumberBoundary + "1111,," + NumberBoundary + "1111,,"
	if !slices.ContainsFunc(BoundaryCardRuns(view), func(run CardRun) bool { return run.Digits == card }) {
		t.Fatal("decimal scalar pieces were not joined")
	}
}

func TestIntegralView(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"42", "42"},
		{"-42.5", "-42,,"},
		{"42e-3", "42,,,"},
		{"0.125E+10", "0,,,,,,,,"},
		{"1e10000", "1,,,,,,"},
		{"01.5", "01.5"},
		{"1.", "1."},
		{"1e10001", "1e10001"},
		{strings.Repeat("9", 4097) + ".1", strings.Repeat("9", 4097) + ".1"},
	} {
		t.Run(tt.input[:min(len(tt.input), 20)], func(t *testing.T) {
			if got := IntegralView(json.Number(tt.input)); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestCardViewDocumentBoundaries(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"document", ` {"n":-42.5,"e":1E+2} `, ` {"n":-42,,,"e":1,,,} `},
		{"root scalar", "0.25", "0,,,"},
		{"array", "[1.5,true,null,2]", "[1,,,true,null,2]"},
		{"literal strings", `{"0.125":"{\"n\":0.125}","v":0.5}`, `{"0.125":"{\"n\":0.125}","v":0,,}`},
		{"escaped quote", `{"a":"\"1.5","n":1.5}`, `{"a":"\"1.5","n":1,,}`},
		{"duplicate occurrences", `{"n":1.5,"n":2.5}`, `{"n":1,,,"n":2,,}`},
		{"integer only", "[42]", "[42]"},
		{"strings only", `["1.5","example"]`, `["1.5","example"]`},
		{"empty", "", ""},
		{"malformed", `{"n":0.125`, `{"n":0.125`},
		{"two documents", "[0.5] [0.5]", "[0.5] [0.5]"},
		{"over depth", "[[[0.5]]]", "[[[0.5]]]"},
		{"over exponent budget", "[0.5,1e10001]", "[0.5,1e10001]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := CardView(tt.input, 2); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestStructuredCardView(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"object", `{"n":0.5}`, `{"n":0,,}`},
		{"array", "[0.5,2]", "[0,,,2]"},
		{"padded array", "\n\t [1.5] ", "\n\t [1,,] "},
		{"root number", "0.25", "0.25"},
		{"padded root number", " 0.25 ", " 0.25 "},
		{"root string", `"0.25"`, `"0.25"`},
		{"plain text", "total 0.25", "total 0.25"},
		{"empty", "", ""},
		{"whitespace", " \n", " \n"},
		{"malformed array", "[0.5", "[0.5"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := StructuredCardView(tt.input, 2); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func BenchmarkCardView(b *testing.B) {
	body := `{"rows":[{"ctr":0.125,"position":4.25,"name":"ordinary report"}]}`
	for b.Loop() {
		_ = CardView(body, 64)
	}
}

func TestScalarIntegerCardRuns(t *testing.T) {
	card := "4111" + "1111" + "1111" + "1111"
	for _, number := range []string{card, card + "e10001", "-" + card + ".25", " " + card + "E+3 "} {
		runs := ScalarIntegerCardRuns(number)
		if len(runs) != 1 || runs[0].Digits != card || runs[0].NumberOnly {
			t.Fatalf("number %.24q runs=%+v", number, runs)
		}
	}
	for _, number := range []string{strings.Repeat("7", 4097), "0." + card, card[:15] + "e5", card + "1", "-", ""} {
		if runs := ScalarIntegerCardRuns(number); len(runs) != 0 {
			t.Fatalf("number %.24q produced runs %+v", number, runs)
		}
	}
}
