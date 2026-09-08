// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestSessionSummaryOf(t *testing.T) {
	t.Run("empty receipts", func(t *testing.T) {
		s := SessionSummaryOf("sess-1", nil, nil, false, 5000)
		if s.ReceiptsEnabled {
			t.Error("expected ReceiptsEnabled=false for empty receipts")
		}
		if s.Agent != "sess-1" {
			t.Errorf("Agent = %q, want %q", s.Agent, "sess-1")
		}
		if len(s.Pips) != 4 {
			t.Errorf("Pips len = %d, want 4", len(s.Pips))
		}
	})

	t.Run("with receipts", func(t *testing.T) {
		_, priv := generateTestKey(t)
		chain := buildTestChain(t, priv, 1)
		s := SessionSummaryOf("sess-1", chain, nil, false, 5000)
		if !s.ReceiptsEnabled {
			t.Error("expected ReceiptsEnabled=true")
		}
		if s.ReceiptCount != 1 {
			t.Errorf("ReceiptCount = %d, want 1", s.ReceiptCount)
		}
	})

	t.Run("read limited", func(t *testing.T) {
		_, priv := generateTestKey(t)
		chain := buildTestChain(t, priv, 1)
		s := SessionSummaryOf("sess-1", chain, nil, true, 100)
		if !s.ReadLimited {
			t.Error("expected ReadLimited=true")
		}
		// Read-limited scorecard shows StateLimited for authentic.
		if s.Pips[0].State != StateLimited {
			t.Errorf("read-limited authentic pip state = %q, want %q", s.Pips[0].State, StateLimited)
		}
	})
}

func TestSessionSummaryOf_Verdicts(t *testing.T) {
	// Plain (unsigned) receipts: sessionVerdicts only reads ActionRecord.Verdict,
	// so no signing is needed to exercise the verdict-set population.
	receipts := []receipt.Receipt{
		{ActionRecord: receipt.ActionRecord{Verdict: "block"}},
		{ActionRecord: receipt.ActionRecord{Verdict: "ALLOW"}},   // mixed case -> normalized
		{ActionRecord: receipt.ActionRecord{Verdict: " block "}}, // dup after trim
		{ActionRecord: receipt.ActionRecord{Verdict: ""}},        // empty skipped
	}
	s := SessionSummaryOf("sess-verdicts", receipts, nil, false, 5000)

	want := []string{"allow", "block"} // sorted, deduped, lower-cased, no empty
	if len(s.Verdicts) != len(want) {
		t.Fatalf("Verdicts = %v, want %v", s.Verdicts, want)
	}
	for i, v := range want {
		if s.Verdicts[i] != v {
			t.Fatalf("Verdicts = %v, want %v", s.Verdicts, want)
		}
	}
	if !s.HasVerdict("block") || !s.HasVerdict("BLOCK") || !s.HasVerdict(" allow ") {
		t.Errorf("HasVerdict should match block/allow case- and space-insensitively; got %v", s.Verdicts)
	}
	if s.HasVerdict("warn") || s.HasVerdict("defer") {
		t.Errorf("HasVerdict should not match absent verdicts; got %v", s.Verdicts)
	}
	if !s.HasVerdict("") {
		t.Error("HasVerdict(\"\") should be true (empty = any)")
	}

	// Empty session: no verdicts, HasVerdict only matches the empty query.
	empty := SessionSummaryOf("sess-empty", nil, nil, false, 5000)
	if len(empty.Verdicts) != 0 {
		t.Errorf("empty session Verdicts = %v, want none", empty.Verdicts)
	}
	if empty.HasVerdict("block") {
		t.Error("empty session should not report HasVerdict(block)")
	}
}

func TestSessionEvidenceOf(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		ev := SessionEvidenceOf("sess-1", nil, nil, false, 5000, 500)
		if ev.ReceiptsEnabled {
			t.Error("expected ReceiptsEnabled=false")
		}
		if ev.TrustedKeyText != "none" {
			t.Errorf("TrustedKeyText = %q, want %q", ev.TrustedKeyText, "none")
		}
	})

	t.Run("with receipts", func(t *testing.T) {
		_, priv := generateTestKey(t)
		chain := buildTestChain(t, priv, 1)
		ev := SessionEvidenceOf("sess-1", chain, nil, false, 5000, 500)
		if !ev.ReceiptsEnabled {
			t.Error("expected ReceiptsEnabled=true")
		}
		if len(ev.Timeline) != 1 {
			t.Errorf("Timeline len = %d, want 1", len(ev.Timeline))
		}
		if ev.Timeline[0].Verdict != "allow" {
			t.Errorf("Timeline[0].Verdict = %q, want %q", ev.Timeline[0].Verdict, "allow")
		}
	})
}

func TestSessionEvidenceOf_TimelineWindowPreservesChainPositions(t *testing.T) {
	pub, priv := generateTestKey(t)
	trusted := map[string]TrustedKey{hex.EncodeToString(pub): {Source: "test"}}
	tampered := buildTestChain(t, priv, 3)
	const tamperedTarget = "https://api.vendor.example/tampered"
	tampered[1].ActionRecord.Target = tamperedTarget
	timelineBase := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		readLimited bool
		wantWindow  string
		want        []TimelineItem
	}{
		{
			name:        "bounded read shows first window",
			readLimited: true,
			wantWindow:  "first",
			want: []TimelineItem{
				{Seq: 0, Time: timelineBase, Verdict: "allow", Reason: "read", Destination: testTarget},
				{Seq: 1, Time: timelineBase.Add(time.Second), Verdict: "allow", Reason: "read", Destination: tamperedTarget, Unverifiable: true},
			},
		},
		{
			name:       "complete read shows latest window",
			wantWindow: "latest",
			want: []TimelineItem{
				{Seq: 1, Time: timelineBase.Add(time.Second), Verdict: "allow", Reason: "read", Destination: tamperedTarget, Unverifiable: true},
				{Seq: 2, Time: timelineBase.Add(2 * time.Second), Verdict: "allow", Reason: "read", Destination: testTarget, Unverifiable: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := SessionEvidenceOf("sess-window", tampered, trusted, tt.readLimited, 2, 2)
			if evidence.Chain.Valid || evidence.Chain.BrokenAtIndex != 1 {
				t.Fatalf("chain = %+v, want verification break at index 1", evidence.Chain)
			}
			if evidence.ReadLimited != tt.readLimited {
				t.Fatalf("ReadLimited = %t, want %t", evidence.ReadLimited, tt.readLimited)
			}
			if !evidence.TimelineLimited || evidence.TimelineWindow != tt.wantWindow {
				t.Fatalf("timeline state = limited:%t window:%q, want limited:%t window:%q", evidence.TimelineLimited, evidence.TimelineWindow, true, tt.wantWindow)
			}
			if len(evidence.Timeline) != len(tt.want) {
				t.Fatalf("timeline length = %d, want %d", len(evidence.Timeline), len(tt.want))
			}
			for i, item := range evidence.Timeline {
				want := tt.want[i]
				if item.Seq != want.Seq || !item.Time.Equal(want.Time) || item.Verdict != want.Verdict || item.Reason != want.Reason || item.Destination != want.Destination || item.Unverifiable != want.Unverifiable {
					t.Errorf("timeline[%d] = seq:%d time:%s verdict:%q reason:%q destination:%q unverifiable:%t, want seq:%d time:%s verdict:%q reason:%q destination:%q unverifiable:%t", i, item.Seq, item.Time, item.Verdict, item.Reason, item.Destination, item.Unverifiable, want.Seq, want.Time, want.Verdict, want.Reason, want.Destination, want.Unverifiable)
				}
			}
		})
	}

	valid := buildTestChain(t, priv, 2)
	exactLimit := SessionEvidenceOf("sess-exact", valid, trusted, false, 2, 2)
	if !exactLimit.Chain.Valid || exactLimit.TimelineLimited || exactLimit.TimelineWindow != "all" || len(exactLimit.Timeline) != 2 {
		t.Fatalf("exact-limit evidence = %+v, want verified all-receipts timeline", exactLimit)
	}

	defaultLimit := SessionEvidenceOf("sess-default", buildTestChain(t, priv, 3), trusted, false, 3, 0)
	if !defaultLimit.Chain.Valid || defaultLimit.TimelineLimited || defaultLimit.TimelineWindow != "all" || len(defaultLimit.Timeline) != 3 {
		t.Fatalf("default-limit evidence = %+v, want verified all-receipts timeline", defaultLimit)
	}
}

func TestRedactRaw(t *testing.T) {
	now := time.Now()
	ev := SessionEvidence{
		Receipts: []receipt.Receipt{{}},
		Timeline: []TimelineItem{
			{Destination: "https://api.vendor.example/with-cap-tok", RawJSON: `{"key":"value"}`, Time: now},
		},
	}
	redacted := RedactRaw(ev)
	if !redacted.RawRedacted {
		t.Error("expected RawRedacted=true")
	}
	if redacted.Receipts != nil {
		t.Error("expected Receipts to be nil after redaction")
	}
	if redacted.Timeline[0].Destination != RedactedDestination {
		t.Errorf("Destination = %q, want redacted", redacted.Timeline[0].Destination)
	}
	if redacted.Timeline[0].RawJSON != "" {
		t.Errorf("RawJSON should be empty after redaction, got %q", redacted.Timeline[0].RawJSON)
	}
	// RedactRaw must NOT mutate the caller's evidence: the original timeline
	// entry keeps its raw destination and payload (they share a backing array).
	if ev.Timeline[0].Destination != "https://api.vendor.example/with-cap-tok" {
		t.Errorf("RedactRaw mutated the caller's Destination: %q", ev.Timeline[0].Destination)
	}
	if ev.Timeline[0].RawJSON != `{"key":"value"}` {
		t.Errorf("RedactRaw mutated the caller's RawJSON: %q", ev.Timeline[0].RawJSON)
	}
}

func TestCloneTrustedKeys(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := CloneTrustedKeys(nil)
		if got != nil {
			t.Error("CloneTrustedKeys(nil) should return nil")
		}
	})

	t.Run("clone is independent", func(t *testing.T) {
		original := map[string]TrustedKey{"k1": {Source: "test"}}
		cloned := CloneTrustedKeys(original)
		cloned["k2"] = TrustedKey{Source: "added"}
		if _, ok := original["k2"]; ok {
			t.Error("modifying clone should not affect original")
		}
	})
}

func TestScorecardPips(t *testing.T) {
	sc := AbsentScorecard()
	pips := ScorecardPips(sc)
	if len(pips) != 4 {
		t.Fatalf("ScorecardPips len = %d, want 4", len(pips))
	}
	labels := []string{"A", "U", "N", "C"}
	for i, p := range pips {
		if p.Label != labels[i] {
			t.Errorf("pip[%d].Label = %q, want %q", i, p.Label, labels[i])
		}
	}
}
