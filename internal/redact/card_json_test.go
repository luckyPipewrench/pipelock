// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestRewriteJSONCardNumbers(t *testing.T) {
	for _, tt := range []struct {
		number string
		block  bool
	}{
		{"0.41111111" + "11111111", false},
		{"4.41111111" + "11111111", false},
		{"41111111.11111111", false},
		{"41111111" + "11111111", true},
		{"41111111" + "11111111.1", true},
		{"-41111111" + "11111111.1", true},
		{"41111111" + "11111111.0", true},
		{"41111111" + "11111111e0", true},
		{"4.11111111" + "1111111e15", false},
		{"-4.11111111" + "1111111e15", false},
		{"41111111" + "11111111110.0", false},
	} {
		t.Run(tt.number, func(t *testing.T) {
			body := []byte(`{"n":` + tt.number + `}`)
			out, _, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
			if tt.block {
				be, ok := asBlockError(err)
				if !ok || be.Reason != ReasonSecretInNumericScalar {
					t.Fatalf("numeric card not blocked: %v", err)
				}
			} else if err != nil || string(out) != string(body) {
				t.Fatalf("numeric data changed: out=%s error=%v", out, err)
			}
		})
	}
}

func TestRewriteJSONNumericCardDictionary(t *testing.T) {
	m := NewDefaultMatcher()
	if err := m.AddDictionary(Dictionary{Class: ClassCreditCard, Entries: []string{"4111" + "1111" + "1111" + "1111"}}); err != nil {
		t.Fatal(err)
	}
	_, _, err := RewriteJSON([]byte(`{"ctr":0.41111111`+`11111111}`), m, NewRedactor(), Limits{})
	be, ok := asBlockError(err)
	if !ok || be.Reason != ReasonSecretInNumericScalar {
		t.Fatalf("literal dictionary detection lost: %v", err)
	}
}
