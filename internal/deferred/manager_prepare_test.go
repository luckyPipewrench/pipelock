// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestManagerPrepareSettlesJournaledDecision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		decision   string
		prepare    func(Resolution) Resolution
		wantFinal  string
		wantSource string
		wantState  string
	}{
		{
			name:      "keeps_allow",
			decision:  config.ActionAllow,
			prepare:   func(r Resolution) Resolution { return r },
			wantFinal: config.ActionAllow, wantSource: SourceApproval, wantState: StateResolvedAllow,
		},
		{
			name:     "downgrades_allow_to_kill_switch_block",
			decision: config.ActionAllow,
			prepare: func(r Resolution) Resolution {
				r.FinalDecision = config.ActionBlock
				r.ResolutionSource = SourceKillSwitch
				return r
			},
			wantFinal: config.ActionBlock, wantSource: SourceKillSwitch, wantState: StateResolvedBlock,
		},
		{
			name:     "cannot_open_a_block",
			decision: config.ActionBlock,
			prepare: func(r Resolution) Resolution {
				r.FinalDecision = config.ActionAllow
				return r
			},
			wantFinal: config.ActionBlock, wantSource: SourceApproval, wantState: StateResolvedBlock,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal := filepath.Join(t.TempDir(), "journal.jsonl")
			m := NewManager(Config{Enabled: true, Timeout: time.Minute, JournalPath: journal})
			finished := false
			var got Resolution
			if err := m.Hold(HeldAction{
				DeferID: "held", ActionID: "held", Target: "tool", SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "session"},
				Prepare: func(r Resolution) (Resolution, func()) {
					return tc.prepare(r), func() { finished = true }
				},
				Resolve: func(res Resolution) {
					if finished {
						t.Error("finish ran before Resolve")
					}
					got = res
				},
			}); err != nil {
				t.Fatalf("hold: %v", err)
			}
			if err := m.Resolve("held", tc.decision, SourceApproval); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !finished {
				t.Fatal("finish did not run")
			}
			if got.FinalDecision != tc.wantFinal || got.ResolutionSource != tc.wantSource {
				t.Fatalf("resolution = %s/%s, want %s/%s", got.FinalDecision, got.ResolutionSource, tc.wantFinal, tc.wantSource)
			}
			data, err := os.ReadFile(filepath.Clean(journal))
			if err != nil {
				t.Fatalf("read journal: %v", err)
			}
			want := `"state":"` + tc.wantState + `","source":"` + tc.wantSource + `"`
			if !strings.Contains(string(data), want) || strings.Count(string(data), `"state":"resolved_`) != 1 {
				t.Fatalf("journal lacks single terminal %s:\n%s", want, data)
			}
		})
	}
}

// TestManagerPrepareFinishRunsWhenResolvePanics guards the sink lock: a panic
// in the release callback must still release what Prepare acquired.
func TestManagerPrepareFinishRunsWhenResolvePanics(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Minute})
	finished := false
	if err := m.Hold(HeldAction{
		DeferID: "held", ActionID: "held", Target: "tool", SizeBytes: 1,
		Prepare: func(r Resolution) (Resolution, func()) { return r, func() { finished = true } },
		Resolve: func(Resolution) { panic("sink failed") },
	}); err != nil {
		t.Fatalf("hold: %v", err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic from Resolve")
			}
		}()
		_ = m.Resolve("held", config.ActionAllow, SourceApproval)
	}()
	if !finished {
		t.Fatal("finish did not run after Resolve panicked")
	}
}
