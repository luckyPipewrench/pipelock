// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

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

func TestRewriteJSONSplitCardNumbers(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		block      bool
	}{
		{"array", `{"ids":[4111,1111,1111,1111]}`, false},
		{"sibling fields", `{"a":4111,"b":1111,"c":1111,"d":1111}`, false},
		{"mixed pieces", `{"a":"4111","b":1111,"c":1111,"d":1111}`, true},
		{"ordinary telemetry", `{"bbox":[1200.21,3400.22,5600.23,7800.24]}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := RewriteJSON([]byte(tt.body), NewDefaultMatcher(), NewRedactor(), Limits{})
			if tt.block {
				be, ok := asBlockError(err)
				if !ok || be.Reason != ReasonSecretInNumericScalar {
					t.Fatalf("split card was not blocked: %v", err)
				}
			} else if err != nil {
				t.Fatalf("ordinary telemetry blocked: %v", err)
			}
		})
	}
}

func TestRewriteJSONNumberBudgetFailsClosed(t *testing.T) {
	body := []byte(`{"n":` + strings.Repeat("9", 4097) + `}`)
	_, _, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	be, ok := asBlockError(err)
	if !ok || be.Reason != ReasonSecretInNumericScalar {
		t.Fatalf("over-budget number was not blocked: %v", err)
	}
}

func TestRewriteJSONSharedCardCorpus(t *testing.T) {
	for _, tt := range cardtest.JSONCases() {
		t.Run(tt.Name, func(t *testing.T) {
			_, report, err := RewriteJSON([]byte(tt.Body), NewDefaultMatcher(), NewRedactor(), Limits{})
			if (tt.Clean || tt.Warn) && err != nil {
				t.Fatalf("benign JSON blocked: %v", err)
			}
			if !tt.Clean && !tt.Warn && err == nil && (report == nil || !report.Applied) {
				t.Fatal("card neither redacted nor refused")
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
