// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidencename

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestSharedFilenameVectors(t *testing.T) {
	raw, err := os.ReadFile("../../sdk/verifiers/filename-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Parse []struct {
			Name    string  `json:"name"`
			Session *string `json:"session"`
			Seq     *uint64 `json:"seq"`
		} `json:"parse"`
		Duplicate []string `json:"duplicate"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Parse {
		session, seq, ok := Parse(vector.Name)
		if ok != (vector.Session != nil) {
			t.Fatalf("%s: parse acceptance = %v", vector.Name, ok)
		}
		if ok && (session != *vector.Session || seq != *vector.Seq) {
			t.Fatalf("%s: got (%q, %d), want (%q, %d)", vector.Name, session, seq, *vector.Session, *vector.Seq)
		}
	}
	if err := CheckNoDuplicateSeqStart(vectors.Duplicate); !errors.Is(err, ErrAmbiguousSeqStart) {
		t.Fatalf("duplicate sequence = %v", err)
	}
}
