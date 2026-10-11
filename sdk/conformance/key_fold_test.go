// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

func TestJSONKeyFoldParity(t *testing.T) {
	raw, err := os.ReadFile("testdata/json-key-folding.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Groups []string
		Cases  []struct {
			Name, Raw string
			Valid     bool
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, group := range fixture.Groups {
		chars := []rune(group)
		for _, c := range chars[1:] {
			raw, err := json.Marshal(map[string]int{string(chars[0]): 1, string(c): 2})
			if err != nil {
				t.Fatal(err)
			}
			if err := jsonscan.RejectDuplicateKeys(raw); err == nil {
				t.Errorf("fold cycle accepted: %q", group)
			}
		}
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if err := jsonscan.ValidateKeys([]byte(tc.Raw), jsonscan.MaxNestingDepth); (err == nil) != tc.Valid {
				t.Fatalf("valid=%v: %v", tc.Valid, err)
			}
		})
	}
}
