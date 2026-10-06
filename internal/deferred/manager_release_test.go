// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type releaseHarness struct {
	m        *Manager
	journal  string
	called   int
	lastHook string
	got      Resolution
	warn     strings.Builder
}

// newReleaseHarness holds one action whose AfterJournal hook runs hook. failWrites
// lists 1-based journal write numbers that fail (the hold is write 1).
func newReleaseHarness(t *testing.T, hook func(Resolution) error, failWrites ...int) *releaseHarness {
	t.Helper()
	h := &releaseHarness{journal: filepath.Join(t.TempDir(), "journal.jsonl")}
	writes := 0
	failing := map[int]bool{}
	for _, n := range failWrites {
		failing[n] = true
	}
	h.m = NewManager(Config{
		Enabled: true, Timeout: time.Minute, JournalPath: h.journal,
		JournalWriteGuard: func(write func() error) error {
			writes++
			if failing[writes] {
				return fmt.Errorf("injected journal write %d failure", writes)
			}
			return write()
		},
		Warningf: func(format string, args ...any) { fmt.Fprintf(&h.warn, format, args...) },
	})
	if err := h.m.Hold(HeldAction{
		DeferID: "held", ActionID: "action-1", Target: "tool", SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "session"},
		AfterJournal: func(res Resolution) error {
			h.called++
			h.lastHook = res.FinalDecision
			if hook == nil {
				return nil
			}
			return hook(res)
		},
		Resolve: func(res Resolution) { h.got = res },
	}); err != nil {
		t.Fatalf("hold: %v", err)
	}
	return h
}

func journalStates(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, e := range readJournalEntries(t, path) {
		state := e.State
		if e.ReleasePending {
			state += "+release_pending"
		}
		out = append(out, state)
	}
	return out
}

// TestManagerReleaseFailures walks a failure through each step of an allow's
// release: the release-pending entry, the receipt hook and the terminal entry.
// Every one closes the allow, and every journal it leaves recovers to block.
func TestManagerReleaseFailures(t *testing.T) {
	errReceipt := errors.New("receipt write failed")
	for _, tc := range []struct {
		name        string
		failWrites  []int
		hookErr     error
		wantCalled  int
		wantFinal   string
		wantReason  string
		wantStates  []string
		wantPending int
		wantWarning bool
	}{
		{
			name:       "released",
			wantCalled: 1, wantFinal: config.ActionAllow,
			wantStates: []string{StateHeld, StateHeld + "+release_pending", StateResolvedAllow},
		},
		{
			// Neither the pending entry nor the corrective block receipt is
			// written, so no terminal entry is either: the hold stays pending.
			name:       "release-pending entry and corrective receipt fail",
			failWrites: []int{2},
			hookErr:    errReceipt,
			wantCalled: 1, wantFinal: config.ActionBlock,
			wantStates:  []string{StateHeld},
			wantPending: 1, wantWarning: true,
		},
		{
			// The hook still runs once, for the corrective block receipt.
			name:       "release-pending entry fails",
			failWrites: []int{2},
			wantCalled: 1, wantFinal: config.ActionBlock,
			wantStates: []string{StateHeld, StateResolvedBlock},
		},
		{
			// The failed allow write may still have reached the file, so when
			// the corrective receipt fails too the hold stays pending and
			// recovery closes it, rather than a terminal block beside a
			// possible lone allow receipt.
			name:       "receipt hook fails",
			hookErr:    errReceipt,
			wantCalled: 2, wantFinal: config.ActionBlock, wantReason: ReasonReceiptNotWritten,
			wantStates:  []string{StateHeld, StateHeld + "+release_pending"},
			wantPending: 1, wantWarning: true,
		},
		{
			// The allow receipt exists, but the call must not be sent: the
			// journal still says release pending, and recovery would close
			// it to block.
			name:       "terminal allow entry fails",
			failWrites: []int{3},
			wantCalled: 2, wantFinal: config.ActionBlock, wantReason: ReasonReleaseNotJournaled,
			wantStates: []string{StateHeld, StateHeld + "+release_pending", StateResolvedBlock},
		},
		{
			name:       "terminal allow and corrective block both fail",
			failWrites: []int{3, 4},
			wantCalled: 2, wantFinal: config.ActionBlock, wantReason: ReasonReleaseNotJournaled,
			wantStates:  []string{StateHeld, StateHeld + "+release_pending"},
			wantPending: 1, wantWarning: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hookErr := tc.hookErr
			h := newReleaseHarness(t, func(Resolution) error { return hookErr }, tc.failWrites...)
			applied, err := h.m.resolveApplied("held", config.ActionAllow, SourceApproval)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if h.called != tc.wantCalled {
				t.Fatalf("hook calls = %d, want %d", h.called, tc.wantCalled)
			}
			if applied != tc.wantFinal || h.got.FinalDecision != tc.wantFinal {
				t.Fatalf("applied=%s delivered=%s, want %s", applied, h.got.FinalDecision, tc.wantFinal)
			}
			if tc.wantFinal == config.ActionBlock && (h.got.ResolutionSource != SourceCancel || h.got.Reason != tc.wantReason) {
				t.Fatalf("delivered %s/%q, want cancel/%q", h.got.ResolutionSource, h.got.Reason, tc.wantReason)
			}
			if got := journalStates(t, h.journal); strings.Join(got, ",") != strings.Join(tc.wantStates, ",") {
				t.Fatalf("journal states = %v, want %v", got, tc.wantStates)
			}
			if got := strings.Contains(h.warn.String(), "audit_gap=true"); got != tc.wantWarning {
				t.Fatalf("audit gap warning = %v, want %v: %q", got, tc.wantWarning, h.warn.String())
			}
			for name, read := range map[string]func(string) ([]HeldAction, error){
				"current": PendingJournal,
				"v3.6.0":  v360PendingJournal,
			} {
				pending, err := read(h.journal)
				if err != nil {
					t.Fatalf("%s reader: %v", name, err)
				}
				if len(pending) != tc.wantPending {
					t.Fatalf("%s reader pending = %d, want %d", name, len(pending), tc.wantPending)
				}
			}
		})
	}
}

// TestManagerReleaseCorrectiveReceiptPrecedesTerminalEntry checks every way a
// release closes to block: the block's receipt is attempted while the journal
// still has no terminal block, so a process that dies before that receipt
// leaves a hold recovery can close rather than a closed hold with no receipt.
func TestManagerReleaseCorrectiveReceiptPrecedesTerminalEntry(t *testing.T) {
	errReceipt := errors.New("receipt write failed")
	for _, tc := range []struct {
		name       string
		failWrites []int
		allowErr   error
	}{
		{name: "release-pending entry fails", failWrites: []int{2}},
		{name: "allow receipt fails", allowErr: errReceipt},
		{name: "terminal allow entry fails", failWrites: []int{3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h *releaseHarness
			blockCalls := 0
			h = newReleaseHarness(t, func(res Resolution) error {
				if res.FinalDecision != config.ActionBlock {
					return tc.allowErr
				}
				blockCalls++
				for _, state := range journalStates(t, h.journal) {
					if state == StateResolvedBlock {
						t.Fatalf("terminal block journaled before its receipt")
					}
				}
				return nil
			}, tc.failWrites...)
			if _, err := h.m.resolveApplied("held", config.ActionAllow, SourceApproval); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if blockCalls != 1 {
				t.Fatalf("corrective receipt attempts = %d, want 1", blockCalls)
			}
			if got := journalStates(t, h.journal); got[len(got)-1] != StateResolvedBlock {
				t.Fatalf("journal states = %v, want a terminal block last", got)
			}
		})
	}
}

// TestManagerReleaseFailedAllowThenCorrectiveStaysPending covers an allow
// receipt write that reports failure after reaching the file, followed by a
// corrective block receipt that fails too. Recovery must still see the hold,
// so the chain never ends with that allow alone.
func TestManagerReleaseFailedAllowThenCorrectiveStaysPending(t *testing.T) {
	h := newReleaseHarness(t, func(res Resolution) error {
		return fmt.Errorf("%s receipt not confirmed", res.FinalDecision)
	})
	if _, err := h.m.resolveApplied("held", config.ActionAllow, SourceApproval); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	pending, err := PendingJournal(h.journal)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %d err=%v, want the hold left for recovery", len(pending), err)
	}
	if h.got.FinalDecision != config.ActionBlock {
		t.Fatalf("delivered %s, want block", h.got.FinalDecision)
	}
}

// TestManagerReleaseCrashRecoversToBlock simulates the process dying while the
// allow receipt is being written: the journal holds only the release-pending
// entry. Both this binary and v3.6.0, which predates the marker, must read the
// hold as pending, so recovery closes it to block, and the recovery entry must
// close it for both.
func TestManagerReleaseCrashRecoversToBlock(t *testing.T) {
	h := newReleaseHarness(t, func(Resolution) error { panic("simulated crash") })
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash hook did not run")
			}
		}()
		_, _ = h.m.resolveApplied("held", config.ActionAllow, SourceApproval)
	}()
	if h.got.FinalDecision != "" {
		t.Fatalf("resolution delivered after crash: %+v", h.got)
	}
	if got := journalStates(t, h.journal); strings.Join(got, ",") != StateHeld+","+StateHeld+"+release_pending" {
		t.Fatalf("journal after crash = %v", got)
	}

	for name, read := range map[string]func(string) ([]HeldAction, error){
		"current": PendingJournal,
		"v3.6.0":  v360PendingJournal,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.jsonl")
			data, err := os.ReadFile(filepath.Clean(h.journal))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			pending, err := read(path)
			if err != nil {
				t.Fatalf("reader: %v", err)
			}
			if len(pending) != 1 || pending[0].DeferID != "held" || pending[0].ActionID != "action-1" {
				t.Fatalf("pending = %+v, want the released hold", pending)
			}
			if err := RecordRestartRecoveryJournal(path, pending[0]); err != nil {
				t.Fatalf("RecordRestartRecoveryJournal: %v", err)
			}
			if pending, err := read(path); err != nil || len(pending) != 0 {
				t.Fatalf("after recovery pending=%d err=%v, want none", len(pending), err)
			}
		})
	}
}

// TestV360RejectsUnknownReleasingState records why the release marker is a flag
// on deferred_held: v3.6.0 refuses a journal holding any state it does not
// know, so a new state would stop an older binary from starting after rollback.
func TestV360RejectsUnknownReleasingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	raw := `{"defer_id":"d1","action_id":"a1","state":"deferred_held"}` + "\n" +
		`{"defer_id":"d1","action_id":"a1","state":"releasing"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v360PendingJournal(path); err == nil || !strings.Contains(err.Error(), "unknown state") {
		t.Fatalf("v3.6.0 reader err = %v, want unknown state", err)
	}
}

func TestPendingJournalReleaseMarkerIntegrity(t *testing.T) {
	const (
		held     = `{"defer_id":"d1","action_id":"a1","state":"deferred_held"}`
		release  = `{"defer_id":"d1","action_id":"a1","state":"deferred_held","release_pending":true}`
		allowed  = `{"defer_id":"d1","action_id":"a1","state":"resolved_allow"}`
		blocked  = `{"defer_id":"d1","action_id":"a1","state":"resolved_block"}`
		badState = `{"defer_id":"d1","action_id":"a1","state":"resolved_allow","release_pending":true}`
	)
	for _, tc := range []struct {
		name        string
		lines       []string
		wantPending int
		wantErr     string
	}{
		{name: "release pending stays pending", lines: []string{held, release}, wantPending: 1},
		{name: "released allow is closed", lines: []string{held, release, allowed}},
		{name: "closed release is closed", lines: []string{held, release, blocked}},
		{name: "marker on a terminal state", lines: []string{held, badState}, wantErr: "release_pending on state"},
		{name: "marker without a hold", lines: []string{release}, wantErr: "without a prior hold"},
		{name: "marker after a terminal state", lines: []string{held, allowed, release}, wantErr: "after terminal state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.jsonl")
			if err := os.WriteFile(path, []byte(strings.Join(tc.lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			pending, err := PendingJournal(path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("PendingJournal: %v", err)
			}
			if len(pending) != tc.wantPending {
				t.Fatalf("pending = %d, want %d", len(pending), tc.wantPending)
			}
		})
	}
}

// TestManagerJournalSyncFailure checks that a journal entry counts as written
// only once it is synced: a failed sync refuses the hold, and on the
// release-pending entry it closes the allow before the receipt hook runs.
func TestManagerJournalSyncFailure(t *testing.T) {
	errSync := errors.New("injected sync failure")
	t.Run("hold", func(t *testing.T) {
		m := NewManager(Config{Enabled: true, Timeout: time.Minute, JournalPath: filepath.Join(t.TempDir(), "journal.jsonl")})
		m.fileSync = func(*os.File) error { return errSync }
		err := m.Hold(HeldAction{DeferID: "held", ActionID: "a1", Resolve: func(Resolution) {}})
		if !errors.Is(err, errSync) {
			t.Fatalf("Hold err = %v, want sync failure", err)
		}
		if m.HeldCount() != 0 {
			t.Fatalf("held = %d after a failed sync, want 0", m.HeldCount())
		}
	})
	t.Run("release", func(t *testing.T) {
		h := newReleaseHarness(t, nil)
		syncs := 0
		h.m.fileSync = func(f *os.File) error {
			syncs++
			if syncs == 1 {
				return errSync
			}
			return f.Sync()
		}
		applied, err := h.m.resolveApplied("held", config.ActionAllow, SourceApproval)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		// The only receipt attempted is the corrective block.
		if applied != config.ActionBlock || h.called != 1 || h.lastHook != config.ActionBlock {
			t.Fatalf("applied=%s hook calls=%d last=%s, want block with only the corrective block receipt", applied, h.called, h.lastHook)
		}
	})
}

// A corrective block must have its receipt before it closes the pending
// release. A crash while that receipt is being written must remain recoverable.
func TestManagerReleaseCorrectiveReceiptCrashRemainsPending(t *testing.T) {
	h := newReleaseHarness(t, func(res Resolution) error {
		if res.FinalDecision == config.ActionBlock {
			panic("crash before corrective receipt")
		}
		return nil
	}, 3)
	h.m.holds["held"].Resolve = func(Resolution) {
		panic("crash before callback receipt")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash hook did not run")
			}
		}()
		_ = h.m.Resolve("held", config.ActionAllow, SourceApproval)
	}()
	pending, err := PendingJournal(h.journal)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending after corrective receipt crash = %d, err=%v; want 1", len(pending), err)
	}
}

func TestManagerReleaseCorrectiveReceiptFailureRemainsPending(t *testing.T) {
	h := newReleaseHarness(t, func(res Resolution) error {
		if res.FinalDecision == config.ActionBlock {
			return errors.New("corrective receipt failed")
		}
		return nil
	}, 3)
	if err := h.m.Resolve("held", config.ActionAllow, SourceApproval); err != nil {
		t.Fatal(err)
	}
	if h.called != 2 || h.got.FinalDecision != config.ActionBlock {
		t.Fatalf("receipt attempts = %d, final = %s; want 2 and block", h.called, h.got.FinalDecision)
	}
	pending, err := PendingJournal(h.journal)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending after corrective receipt failure = %d, err=%v; want 1", len(pending), err)
	}
	if !strings.Contains(h.warn.String(), "audit_gap=true") {
		t.Fatalf("missing audit gap warning: %s", h.warn.String())
	}
}

// TestManagerJournalDirectorySyncRetries checks the journal's directory is
// synced until a sync succeeds. A first write whose data sync or directory sync
// fails leaves the file in place, so later writes must still sync the
// directory; otherwise a crash could drop the whole journal, held entries and
// all, after those later writes reported success.
func TestManagerJournalDirectorySyncRetries(t *testing.T) {
	errSync := errors.New("injected sync failure")
	for _, tc := range []struct {
		name     string
		failFile bool
		failDir  bool
	}{
		{name: "first data sync fails", failFile: true},
		{name: "first directory sync fails", failDir: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(Config{Enabled: true, Timeout: time.Minute, JournalPath: filepath.Join(t.TempDir(), "journal.jsonl")})
			fileSyncs, dirSyncs := 0, 0
			m.fileSync = func(f *os.File) error {
				fileSyncs++
				if tc.failFile && fileSyncs == 1 {
					return errSync
				}
				return f.Sync()
			}
			m.dirSync = func(string) error {
				dirSyncs++
				if tc.failDir && dirSyncs == 1 {
					return errSync
				}
				return nil
			}
			hold := func(id string) error {
				return m.Hold(HeldAction{DeferID: id, ActionID: id, Resolve: func(Resolution) {}})
			}
			if err := hold("first"); !errors.Is(err, errSync) {
				t.Fatalf("first hold err = %v, want injected sync failure", err)
			}
			if err := hold("second"); err != nil {
				t.Fatalf("second hold: %v", err)
			}
			wantDirSyncs := 1
			if tc.failDir {
				wantDirSyncs = 2
			}
			if dirSyncs != wantDirSyncs {
				t.Fatalf("directory syncs after retry = %d, want %d", dirSyncs, wantDirSyncs)
			}
			if err := hold("third"); err != nil {
				t.Fatalf("third hold: %v", err)
			}
			if dirSyncs != wantDirSyncs {
				t.Fatalf("directory syncs after a confirmed sync = %d, want %d (no repeat)", dirSyncs, wantDirSyncs)
			}
		})
	}
}

// The v3.6.0 journal reader below is copied verbatim from the v3.6.0 tag
// (internal/deferred/manager.go), renamed, so the cross-version tests run the
// released parser rather than a description of it. Do not edit it.
type v360JournalEntry struct {
	DeferID       string                       `json:"defer_id"`
	ActionID      string                       `json:"action_id"`
	State         string                       `json:"state"`
	Source        string                       `json:"source,omitempty"`
	Target        string                       `json:"target,omitempty"`
	Surface       string                       `json:"surface,omitempty"`
	Method        string                       `json:"method,omitempty"`
	Reason        string                       `json:"reason,omitempty"`
	Authority     AuthoritySnapshot            `json:"authority"`
	Policy        ResolutionPolicy             `json:"policy"`
	RulePolicy    config.DeferResolutionPolicy `json:"rule_policy"`
	ParentDeferID string                       `json:"parent_defer_id,omitempty"`
	CascadeDepth  int                          `json:"cascade_depth,omitempty"`
	Linkage       string                       `json:"linkage,omitempty"`
	Deadline      time.Time                    `json:"deadline,omitempty"`
	Timestamp     time.Time                    `json:"timestamp"`
	SizeBytes     int                          `json:"size_bytes,omitempty"`
}

func v360PendingJournal(path string) ([]HeldAction, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	pending := map[string]v360JournalEntry{}
	terminal := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var entry v360JournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse defer journal: %w", err)
		}
		switch entry.State {
		case StateHeld:
			if _, seen := terminal[entry.DeferID]; seen {
				return nil, fmt.Errorf("defer journal integrity: held entry after terminal state for defer_id %q", entry.DeferID)
			}
			pending[entry.DeferID] = entry
		case StateResolvedAllow, StateResolvedBlock, StateResolvedStepUp:
			delete(pending, entry.DeferID)
			terminal[entry.DeferID] = struct{}{}
		case StateAdmissionRejected:
			// Audit-only marker for an action that was never held. It must not
			// touch hold lifecycle: for a duplicate defer_id it shares a live
			// hold's id, so resolving/terminalizing it here would drop that
			// live hold from recovery.
		default:
			return nil, fmt.Errorf("defer journal integrity: unknown state %q for defer_id %q", entry.State, entry.DeferID)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan defer journal: %w", err)
	}
	out := make([]HeldAction, 0, len(pending))
	for _, entry := range pending {
		out = append(out, HeldAction{
			DeferID:       entry.DeferID,
			ActionID:      entry.ActionID,
			Target:        entry.Target,
			Reason:        entry.Reason,
			Surface:       entry.Surface,
			Method:        entry.Method,
			SizeBytes:     entry.SizeBytes,
			Policy:        entry.Policy,
			RulePolicy:    entry.RulePolicy,
			Authority:     entry.Authority,
			ParentDeferID: entry.ParentDeferID,
			CascadeDepth:  entry.CascadeDepth,
			Linkage:       entry.Linkage,
			Deadline:      entry.Deadline,
		})
	}
	return out, nil
}
