// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestParseBoundedJSONNumber_ExponentBound is a regression guard against a
// CPU/memory amplification vector: an attacker-supplied tool-call value like
// 1e1000001 is only a few bytes but, if fed to big.Rat.SetString, eagerly
// expands into a multi-megabyte integer (10^1000000 builds in ~17ms). The
// parser must bound the exponent BEFORE any big-number construction and reject
// it. If a future change reintroduces the eager SetString shortcut, an
// over-bound exponent would parse as valid and this test fails.
func TestParseBoundedJSONNumber_ExponentBound(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"small integer", "1000", true},
		{"zero", "0", true},
		{"scientific within bound", "1e9", true},
		{"negative exponent within bound", "1e-9", true},
		{"negative", "-42.5", true},
		{"exponent at bound", "1e10000", true},
		{"exponent just over bound", "1e10001", false},
		{"amplification exponent", "1e1000001", false},
		{"negative exponent over bound", "1e-10001", false},
		{"garbage", "not-a-number", false},
		{"empty", "", false},
		{"lone e", "1e", false},
		{"over-long", strings.Repeat("9", 5000), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := ParseBoundedJSONNumber(json.Number(tt.in))
			if ok != tt.want {
				t.Fatalf("ParseBoundedJSONNumber(%q) ok=%v, want %v", tt.in, ok, tt.want)
			}
		})
	}
}

// TestParseBoundedJSONNumber_Fidelity proves scientific and plain forms compare
// exactly equal (no float collapse), backing the numeric-range invariant.
func TestParseBoundedJSONNumber_Fidelity(t *testing.T) {
	sci, ok := ParseBoundedJSONNumber(json.Number("1e9"))
	if !ok {
		t.Fatal("expected 1e9 to parse")
	}
	plain, ok := ParseBoundedJSONNumber(json.Number("1000000000"))
	if !ok {
		t.Fatal("expected 1000000000 to parse")
	}
	if sci.Cmp(plain) != 0 {
		t.Fatalf("1e9 != 1000000000 exactly: %s vs %s", sci.String(), plain.String())
	}
}
