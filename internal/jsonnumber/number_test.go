// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestParseExactValue(t *testing.T) {
	for _, tt := range []struct {
		name, spelling, value string
	}{
		{"zero", "0", "0"},
		{"negative zero", "-0.0e-10000", "0"},
		{"fraction", "0.125", "1/8"},
		{"negative fraction", "-42.5", "-85/2"},
		{"positive exponent", "1.25e2", "125"},
		{"negative exponent", "125E-2", "5/4"},
		{"explicit exponent sign", "1.25e+2", "125"},
		{"trailing fraction zeroes", "123.000", "123"},
		{"long integer precision", "41111111" + "11111111110.0", "41111111" + "11111111110"},
		{"fraction precision", "41111111" + "11111111.0000000000000001", "41111111" + "111111110000000000000001/10000000000000000"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Parse(json.Number(tt.spelling))
			want, valid := new(big.Rat).SetString(tt.value)
			if !valid {
				t.Fatal("invalid expected rational")
			}
			if !ok || got.Cmp(want) != 0 {
				t.Fatalf("value=%v ok=%v want=%v", got, ok, want)
			}
		})
	}
}

func TestParseGrammarAndBounds(t *testing.T) {
	for _, tt := range []struct {
		name, spelling string
		valid          bool
	}{
		{"empty", "", false},
		{"leading zero", "01", false},
		{"leading plus", "+1", false},
		{"missing integer", ".1", false},
		{"missing fraction", "1.", false},
		{"missing exponent", "1e", false},
		{"whitespace", " 1", false},
		{"not finite", "NaN", false},
		{"exponent overflow", "1e99999999999999999999", false},
		{"positive exponent at bound", "1e10000", true},
		{"negative exponent at bound", "1e-10000", true},
		{"positive exponent over bound", "1e10001", false},
		{"negative exponent over bound", "1e-10001", false},
		{"spelling at bound", strings.Repeat("9", 4096), true},
		{"spelling over bound", strings.Repeat("9", 4097), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := Parse(json.Number(tt.spelling))
			if ok != tt.valid {
				t.Fatalf("accepted=%v want=%v", ok, tt.valid)
			}
		})
	}
}
