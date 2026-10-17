// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestCardUnionCorpus(t *testing.T) {
	for _, tt := range cardtest.UnionCases() {
		t.Run(tt.Name, func(t *testing.T) {
			raw, limit := jsonnumber.CardRunsWithLimit(tt.Body, extract.MaxExtractDepth)
			if limit != jsonnumber.CardRunWithinBudget {
				t.Fatal("corpus exceeded budget")
			}
			atoms := extract.AllStringsFromJSONResult(json.RawMessage(tt.Body)).Atoms
			typed := jsonnumber.BoundaryCardRuns(extract.JoinCardAtoms(atoms, " "))
			for _, runs := range [][]jsonnumber.CardRun{raw, typed} {
				if tt.Warn && len(runs) == 0 {
					t.Fatal("informational evidence missing")
				}
				if tt.Clean && len(runs) != 0 {
					t.Fatal("clean case produced card evidence")
				}
				enforces := slices.ContainsFunc(runs, func(run jsonnumber.CardRun) bool { return run.EnforcesShippedRule() })
				if enforces != (!tt.Clean && !tt.Warn) {
					t.Fatalf("enforces=%v want clean=%v warn=%v", enforces, tt.Clean, tt.Warn)
				}
				for _, run := range runs {
					if !jsonnumber.ValidCardNumber(run.Digits) {
						t.Fatal("unvalidated run")
					}
				}
			}
		})
	}
}

func TestCardUnionWholeLeafStaysOrdinary(t *testing.T) {
	for _, tt := range cardtest.JSONCases() {
		if tt.Name != "string card" {
			continue
		}
		if runs := jsonnumber.CardRuns(tt.Body, extract.MaxExtractDepth); len(runs) != 0 {
			t.Fatal("whole string promoted to cross-piece run")
		}
	}
}

func TestCardUnionNoDuplicateEvidence(t *testing.T) {
	for _, tt := range cardtest.JSONCases() {
		t.Run(tt.Name, func(t *testing.T) {
			seen := make(map[jsonnumber.CardRun]bool)
			for _, run := range jsonnumber.CardRuns(tt.Body, extract.MaxExtractDepth) {
				if seen[run] {
					t.Fatal("ANCHORED and WINDOW duplicated one candidate")
				}
				seen[run] = true
			}
		})
	}
}
