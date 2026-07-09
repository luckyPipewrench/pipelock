// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"testing"
)

func TestGroupByAgent(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := GroupByAgent(nil)
		if got != nil {
			t.Error("GroupByAgent(nil) should return nil")
		}
	})

	t.Run("single agent", func(t *testing.T) {
		summaries := []SessionSummary{
			{ID: "s1", Agent: "agent-a", ReceiptsEnabled: true, Pips: ScorecardPips(AbsentScorecard())},
			{ID: "s2", Agent: "agent-a", ReceiptsEnabled: true, Pips: ScorecardPips(AbsentScorecard())},
		}
		groups := GroupByAgent(summaries)
		if len(groups) != 1 {
			t.Fatalf("len(groups) = %d, want 1", len(groups))
		}
		if groups[0].Agent != "agent-a" {
			t.Errorf("Agent = %q, want %q", groups[0].Agent, "agent-a")
		}
		if groups[0].SessionCount != 2 {
			t.Errorf("SessionCount = %d, want 2", groups[0].SessionCount)
		}
	})

	t.Run("multiple agents deterministic order", func(t *testing.T) {
		summaries := []SessionSummary{
			{ID: "s1", Agent: "zebra", ReceiptsEnabled: true, Pips: ScorecardPips(AbsentScorecard())},
			{ID: "s2", Agent: "alpha", ReceiptsEnabled: true, Pips: ScorecardPips(AbsentScorecard())},
			{ID: "s3", Agent: "alpha", ReceiptsEnabled: false, Pips: ScorecardPips(AbsentScorecard())},
			{ID: "s4", Agent: "beta", ReceiptsEnabled: true, Pips: ScorecardPips(AbsentScorecard())},
		}
		groups := GroupByAgent(summaries)
		if len(groups) != 3 {
			t.Fatalf("len(groups) = %d, want 3", len(groups))
		}
		// Must be sorted alphabetically.
		wantOrder := []string{"alpha", "beta", "zebra"}
		for i, g := range groups {
			if g.Agent != wantOrder[i] {
				t.Errorf("groups[%d].Agent = %q, want %q", i, g.Agent, wantOrder[i])
			}
		}
		// Alpha has 2 sessions.
		if groups[0].SessionCount != 2 {
			t.Errorf("alpha SessionCount = %d, want 2", groups[0].SessionCount)
		}
	})

	t.Run("rollup counts", func(t *testing.T) {
		// Sessions with no receipts enabled should show in NotReported.
		summaries := []SessionSummary{
			{ID: "s1", Agent: "agent-a", ReceiptsEnabled: false, Pips: ScorecardPips(AbsentScorecard())},
			{ID: "s2", Agent: "agent-a", ReceiptsEnabled: true, Pips: []SummaryPip{
				{State: StateVerify, Label: "A"},
				{State: StateVerify, Label: "U"},
				{State: StateWarn, Label: "N"},
				{State: StateLimited, Label: "C"},
			}},
		}
		groups := GroupByAgent(summaries)
		if len(groups) != 1 {
			t.Fatalf("len(groups) = %d, want 1", len(groups))
		}
		r := groups[0].Rollup
		if r.NotReported != 1 {
			t.Errorf("NotReported = %d, want 1", r.NotReported)
		}
		if r.TrustedKeyPresent != 1 {
			t.Errorf("TrustedKeyPresent = %d, want 1", r.TrustedKeyPresent)
		}
		if r.ChainsIntact != 1 {
			t.Errorf("ChainsIntact = %d, want 1", r.ChainsIntact)
		}
		if r.NotAnchored != 1 {
			t.Errorf("NotAnchored = %d, want 1", r.NotAnchored)
		}
	})

	t.Run("rollup counts broken, unverified, limited, and externally anchored", func(t *testing.T) {
		// Exercise the counters the happy-path case above does not:
		// ChainsBroken (U=Fail), ChainsIntact for read-limited chains
		// (U=Limited), Unverified (A=Warn), AnchoredExternal (N=Verify).
		summaries := []SessionSummary{
			{ID: "s1", Agent: "agent-x", ReceiptsEnabled: true, Pips: []SummaryPip{
				{State: StateWarn, Label: "A"},    // Unverified
				{State: StateFail, Label: "U"},    // ChainsBroken
				{State: StateLimited, Label: "U"}, // ChainsIntact
				{State: StateVerify, Label: "N"},  // AnchoredExternal
				{State: StateLimited, Label: "C"},
			}},
		}
		r := GroupByAgent(summaries)[0].Rollup
		if r.ChainsBroken != 1 {
			t.Errorf("ChainsBroken = %d, want 1", r.ChainsBroken)
		}
		if r.Unverified != 1 {
			t.Errorf("Unverified = %d, want 1", r.Unverified)
		}
		if r.AnchoredExternal != 1 {
			t.Errorf("AnchoredExternal = %d, want 1", r.AnchoredExternal)
		}
		if r.ChainsIntact != 1 {
			t.Errorf("ChainsIntact = %d, want 1", r.ChainsIntact)
		}
		if r.TrustedKeyPresent != 0 || r.NotAnchored != 0 || r.NotReported != 0 {
			t.Errorf("unexpected non-zero counter: %+v", r)
		}
	})
}
