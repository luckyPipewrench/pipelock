// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestManagerAfterJournal pins when the post-journal hook runs and what a
// failure does. The hook is where the allow resolution receipt is written, so
// it must run only for an allow the journal accepted, and its failure must close
// the decision everywhere it is recorded.
func TestManagerAfterJournal(t *testing.T) {
	errReceipt := errors.New("receipt write failed")
	for _, tc := range []struct {
		name        string
		decision    string
		hookErr     error
		breakLog    bool
		wantCalled  bool
		wantFinal   string
		wantSource  string
		wantReason  string
		wantJournal []string // terminal journal entries, in order; nil when the journal is unreadable
	}{
		{
			name: "allow, hook succeeds", decision: config.ActionAllow, wantCalled: true,
			wantFinal: config.ActionAllow, wantSource: SourceApproval,
			wantJournal: []string{`"state":"resolved_allow","source":"approval"`},
		},
		{
			// The allow never reaches the journal as final: the release stays
			// pending until the hook succeeds, so a failed hook leaves only
			// the block.
			name: "allow, hook fails closes to block", decision: config.ActionAllow, hookErr: errReceipt, wantCalled: true,
			wantFinal: config.ActionBlock, wantSource: SourceCancel, wantReason: ReasonReceiptNotWritten,
			wantJournal: []string{`"state":"resolved_block","source":"cancel"`},
		},
		{
			name: "block never calls the hook", decision: config.ActionBlock, hookErr: errReceipt,
			wantFinal: config.ActionBlock, wantSource: SourceApproval,
			wantJournal: []string{`"state":"resolved_block","source":"approval"`},
		},
		{
			name: "journal failure never calls the hook", decision: config.ActionAllow, breakLog: true,
			wantFinal: config.ActionBlock, wantSource: SourceCancel,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal := filepath.Join(t.TempDir(), "journal.jsonl")
			m := NewManager(Config{Enabled: true, Timeout: time.Minute, JournalPath: journal})
			called := false
			var got Resolution
			if err := m.Hold(HeldAction{
				DeferID: "held", ActionID: "held", Target: "tool", SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "session"},
				AfterJournal: func(Resolution) error {
					called = true
					return tc.hookErr
				},
				Resolve: func(res Resolution) { got = res },
			}); err != nil {
				t.Fatalf("hold: %v", err)
			}
			if tc.breakLog {
				if err := os.Rename(journal, journal+".moved"); err != nil {
					t.Fatalf("move journal: %v", err)
				}
				if err := os.Mkdir(journal, 0o750); err != nil {
					t.Fatalf("replace journal with a directory: %v", err)
				}
			}
			applied, err := m.resolveApplied("held", tc.decision, SourceApproval)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if called != tc.wantCalled {
				t.Fatalf("hook called = %v, want %v", called, tc.wantCalled)
			}
			if applied != tc.wantFinal || got.FinalDecision != tc.wantFinal || got.ResolutionSource != tc.wantSource {
				t.Fatalf("applied=%s resolution=%s/%s, want %s/%s", applied, got.FinalDecision, got.ResolutionSource, tc.wantFinal, tc.wantSource)
			}
			if got.Reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if tc.wantJournal == nil {
				return
			}
			data, err := os.ReadFile(filepath.Clean(journal))
			if err != nil {
				t.Fatalf("read journal: %v", err)
			}
			var terminal []string
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if strings.Contains(line, `"state":"resolved_`) {
					terminal = append(terminal, line)
				}
			}
			if len(terminal) != len(tc.wantJournal) {
				t.Fatalf("terminal journal entries = %d, want %d:\n%s", len(terminal), len(tc.wantJournal), data)
			}
			for i, want := range tc.wantJournal {
				if !strings.Contains(terminal[i], want) {
					t.Fatalf("terminal entry %d = %s, want it to contain %s", i, terminal[i], want)
				}
			}
		})
	}
}
