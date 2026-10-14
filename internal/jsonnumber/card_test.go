// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIntegralView(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"42", "42"},
		{"-42.5", "-42  "},
		{"42e-3", "42   "},
		{"0.125E+10", "0        "},
		{"1e10000", "1      "},
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
		{"document", ` {"n":-42.5,"e":1E+2} `, ` {"n":-42  ,"e":1   } `},
		{"root scalar", "0.25", "0   "},
		{"array", "[1.5,true,null,2]", "[1  ,true,null,2]"},
		{"literal strings", `{"0.125":"{\"n\":0.125}","v":0.5}`, `{"0.125":"{\"n\":0.125}","v":0  }`},
		{"escaped quote", `{"a":"\"1.5","n":1.5}`, `{"a":"\"1.5","n":1  }`},
		{"duplicate occurrences", `{"n":1.5,"n":2.5}`, `{"n":1  ,"n":2  }`},
		{"integer only", "[42]", "[42]"},
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

func BenchmarkCardView(b *testing.B) {
	body := `{"rows":[{"ctr":0.125,"position":4.25,"name":"ordinary report"}]}`
	for b.Loop() {
		_ = CardView(body, 64)
	}
}
