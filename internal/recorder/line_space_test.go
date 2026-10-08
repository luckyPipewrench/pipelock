// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"encoding/json"
	"os"
	"testing"
	"unicode"
)

func TestEntryLineSpaceVectors(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) != (TrimEntryLine(string(r)) == "") {
			t.Fatalf("U+%04X differs from Go unicode.IsSpace", r)
		}
	}
	var fixture struct {
		Vectors []struct {
			Name      string `json:"name"`
			Codepoint rune   `json:"codepoint"`
			Placement string `json:"placement"`
			Line      string `json:"line"`
			Expected  string `json:"expected"`
		} `json:"vectors"`
	}
	data, err := os.ReadFile("../../sdk/conformance/testdata/receipt-line-whitespace.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 93 {
		t.Fatalf("vectors = %d, want 93", len(fixture.Vectors))
	}
	covered := make(map[rune]map[string]bool)
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if covered[v.Codepoint] == nil {
				covered[v.Codepoint] = make(map[string]bool)
			}
			if covered[v.Codepoint][v.Placement] {
				t.Fatal("duplicate code point and placement")
			}
			covered[v.Codepoint][v.Placement] = true
			trimmed := TrimEntryLine(v.Line)
			got := "reject"
			if trimmed == "" {
				got = "skip"
			} else if json.Valid([]byte(trimmed)) {
				got = "parse"
			}
			if got != v.Expected {
				t.Fatalf("outcome = %s, want %s", got, v.Expected)
			}
		})
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) {
			for _, placement := range []string{"whole", "leading", "trailing"} {
				if !covered[r][placement] {
					t.Fatalf("missing U+%04X %s vector", r, placement)
				}
			}
		}
	}
	for _, r := range []rune{0x1c, 0x1d, 0x1e, 0x1f, 0xfeff, 0x200b} {
		for _, placement := range []string{"whole", "leading", "trailing"} {
			if !covered[r][placement] {
				t.Fatalf("missing U+%04X %s vector", r, placement)
			}
		}
	}
}
