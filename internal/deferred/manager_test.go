// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestManagerTimeoutResolvesBlockOnce(t *testing.T) {
	ch := make(chan Resolution, 2)
	m := NewManager(Config{
		Enabled:              true,
		Timeout:              10 * time.Millisecond,
		MaxPending:           1,
		MaxPendingPerSession: 1,
		MaxPendingBytes:      1024,
	})
	err := m.Hold(HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
		Resolve: func(res Resolution) {
			ch <- res
		},
	})
	if err != nil {
		t.Fatalf("Hold returned error: %v", err)
	}
	select {
	case got := <-ch:
		if got.FinalDecision != "block" || got.ResolutionSource != SourceTimeout {
			t.Fatalf("resolution = (%q,%q), want block timeout", got.FinalDecision, got.ResolutionSource)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timeout did not resolve")
	}
	if err := m.Resolve("d1", "allow", SourceContext); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolve after timeout error = %v, want ErrNotFound", err)
	}
	select {
	case got := <-ch:
		t.Fatalf("double resolution delivered: %+v", got)
	default:
	}
}

func TestManagerCapacityRejectsNewHold(t *testing.T) {
	m := NewManager(Config{
		Enabled:              true,
		Timeout:              time.Second,
		MaxPending:           1,
		MaxPendingPerSession: 1,
		MaxPendingBytes:      1024,
	})
	base := HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
		Resolve:   func(Resolution) {},
	}
	if err := m.Hold(base); err != nil {
		t.Fatalf("first Hold returned error: %v", err)
	}
	base.DeferID = "d2"
	base.ActionID = "d2"
	if err := m.Hold(base); !errors.Is(err, ErrCapacity) {
		t.Fatalf("second Hold error = %v, want ErrCapacity", err)
	}
	if err := m.Resolve("d1", "allow", SourceContext); err != nil {
		t.Fatalf("original hold was evicted or lost: %v", err)
	}
}

func TestManagerCapacityRejectsOverflowSize(t *testing.T) {
	m := NewManager(Config{
		Enabled:              true,
		Timeout:              time.Second,
		MaxPending:           4,
		MaxPendingPerSession: 4,
		MaxPendingBytes:      8,
	})
	if err := m.Hold(HeldAction{
		DeferID:   "huge",
		ActionID:  "huge",
		Target:    "tool",
		SizeBytes: 9,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
		Resolve:   func(Resolution) {},
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("Hold oversized error = %v, want ErrCapacity", err)
	}
}

func TestValidateActionRejectsUnsupportedSurface(t *testing.T) {
	err := ValidateAction(SurfaceFetch, config.ActionDefer)
	if err == nil {
		t.Fatal("ValidateAction(fetch, defer) succeeded, want error")
	}
	if !strings.Contains(err.Error(), "defer is not yet supported on fetch:") {
		t.Fatalf("error = %q, want registry rejection wording", err.Error())
	}
	if err := ValidateAction(SurfaceMCPStdio, config.ActionDefer); err != nil {
		t.Fatalf("ValidateAction(mcp_stdio, defer) = %v", err)
	}
}

func TestSurfaceRegistryUnknownAndCopy(t *testing.T) {
	support := LookupSurface("new_surface")
	if support.Status != StatusNotYetSupported || !strings.Contains(support.RejectReason, "not registered") {
		t.Fatalf("unknown surface support = %+v", support)
	}
	first := SupportedSurfaces()
	if len(first) == 0 {
		t.Fatal("SupportedSurfaces returned no entries")
	}
	first[0].Surface = "mutated"
	second := SupportedSurfaces()
	if second[0].Surface == "mutated" {
		t.Fatal("SupportedSurfaces returned shared backing storage")
	}
	if err := ValidateAction(SurfaceFetch, config.ActionAllow); err != nil {
		t.Fatalf("ValidateAction non-defer = %v", err)
	}
}

func TestPolicyStringHelpers(t *testing.T) {
	policy := ResolutionPolicy{
		Timeout:              2 * time.Second,
		MaxPending:           3,
		MaxPendingPerSession: 2,
		MaxPendingBytes:      512,
	}
	got := policy.String()
	for _, want := range []string{`"max_pending":3`, `"max_pending_per_session":2`, `"max_pending_bytes":512`} {
		if !strings.Contains(got, want) {
			t.Fatalf("ResolutionPolicy.String() = %q, want %s", got, want)
		}
	}
	receiptPolicy := ReceiptPolicyString(policy, config.DeferResolutionPolicy{
		AllowOn:  config.DeferAllowOn{Approval: true},
		StepUpOn: config.DeferStepUpOn{ApprovalRequestsHuman: true},
	})
	for _, want := range []string{"approval", "approval_requests_human"} {
		if !strings.Contains(receiptPolicy, want) {
			t.Fatalf("ReceiptPolicyString() = %q, want %s", receiptPolicy, want)
		}
	}
}

func TestManagerDefaultsNilHelpersAndValidation(t *testing.T) {
	m := NewManager(Config{})
	policy := m.Policy()
	if policy.Timeout != DefaultTimeoutSeconds*time.Second ||
		policy.MaxPending != DefaultMaxPending ||
		policy.MaxPendingPerSession != DefaultMaxPendingSession ||
		policy.MaxPendingBytes != DefaultMaxPendingBytes {
		t.Fatalf("default policy = %+v", policy)
	}
	if m.Enabled() {
		t.Fatal("zero config manager should be disabled")
	}
	if err := m.Hold(HeldAction{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled Hold error = %v, want ErrDisabled", err)
	}

	var nilManager *Manager
	if nilManager.Enabled() {
		t.Fatal("nil manager enabled")
	}
	if got := nilManager.Policy(); got != (ResolutionPolicy{}) {
		t.Fatalf("nil Policy = %+v, want zero", got)
	}
	if got := nilManager.JournalPath(); got != "" {
		t.Fatalf("nil JournalPath = %q, want empty", got)
	}
	if got := nilManager.Snapshot(); got != nil {
		t.Fatalf("nil Snapshot = %+v, want nil", got)
	}
	if _, ok := nilManager.Held("missing"); ok {
		t.Fatal("nil Held returned ok")
	}
	nilManager.ResolveAll(config.ActionBlock, SourceCancel)
	nilManager.ResolveToolInventory("sess", config.ActionBlock)
	nilManager.ResolvePolicyReload(func(HeldAction) (string, error) { return config.ActionBlock, nil })
	if err := nilManager.RecordRestartRecovery(HeldAction{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("nil RecordRestartRecovery = %v, want ErrDisabled", err)
	}
	if err := nilManager.Resolve("missing", "", ""); !errors.Is(err, ErrDisabled) {
		t.Fatalf("nil Resolve = %v, want ErrDisabled", err)
	}
}

func TestManagerHoldValidationAndSnapshotCopies(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour})
	base := HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "tool",
		SizeBytes: -10,
		Payload:   []byte("payload"),
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
		Resolve:   func(Resolution) {},
	}
	missingID := base
	missingID.DeferID = ""
	if err := m.Hold(missingID); err == nil || !strings.Contains(err.Error(), "defer_id is required") {
		t.Fatalf("missing id Hold error = %v", err)
	}
	missingResolve := base
	missingResolve.Resolve = nil
	if err := m.Hold(missingResolve); err == nil || !strings.Contains(err.Error(), "resolve callback is required") {
		t.Fatalf("missing resolve Hold error = %v", err)
	}
	if err := m.Hold(base); err != nil {
		t.Fatalf("Hold valid returned error: %v", err)
	}
	if err := m.Hold(base); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate Hold error = %v", err)
	}
	held, ok := m.Held("d1")
	if !ok {
		t.Fatal("Held(d1) returned false")
	}
	if held.SizeBytes != 0 {
		t.Fatalf("negative SizeBytes normalized to %d, want 0", held.SizeBytes)
	}
	held.Payload[0] = 'X'
	again, ok := m.Held("d1")
	if !ok || string(again.Payload) != "payload" {
		t.Fatalf("Held returned shared payload or missing hold: %+v ok=%v", again, ok)
	}
	if _, ok := m.Held("missing"); ok {
		t.Fatal("Held(missing) returned true")
	}
	if err := m.Resolve("d1", "", ""); err != nil {
		t.Fatalf("Resolve default returned error: %v", err)
	}
	if _, ok := m.Held("d1"); ok {
		t.Fatal("Held returned true after resolve")
	}
}

func TestResolveApprovalRequiresAffirmativePolicy(t *testing.T) {
	ch := make(chan Resolution, 1)
	m := NewManager(Config{Enabled: true, Timeout: time.Second})
	err := m.Hold(HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
		RulePolicy: config.DeferResolutionPolicy{
			AllowOn: config.DeferAllowOn{PolicyPermits: true},
		},
		Resolve: func(res Resolution) { ch <- res },
	})
	if err != nil {
		t.Fatalf("Hold returned error: %v", err)
	}
	if err := m.ResolveApproval("d1", config.ActionAllow); err != nil {
		t.Fatalf("ResolveApproval returned error: %v", err)
	}
	got := <-ch
	if got.FinalDecision != config.ActionBlock || got.ResolutionSource != SourceApproval {
		t.Fatalf("approval without allow_on.approval resolved %+v, want block approval", got)
	}
}

func TestResolveApprovalAllowsConfiguredStepUp(t *testing.T) {
	ch := make(chan Resolution, 1)
	m := NewManager(Config{Enabled: true, Timeout: time.Second})
	err := m.Hold(HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
		RulePolicy: config.DeferResolutionPolicy{
			StepUpOn: config.DeferStepUpOn{ApprovalRequestsHuman: true},
		},
		Resolve: func(res Resolution) { ch <- res },
	})
	if err != nil {
		t.Fatalf("Hold returned error: %v", err)
	}
	if err := m.ResolveApproval("d1", config.ActionAsk); err != nil {
		t.Fatalf("ResolveApproval returned error: %v", err)
	}
	got := <-ch
	if got.FinalDecision != config.ActionAsk || got.ResolutionSource != SourceApproval {
		t.Fatalf("approval step-up resolved %+v, want ask approval", got)
	}
}

func TestResolvePolicyReloadAllowBlockAndStillHeld(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour})
	resolved := make(chan Resolution, 3)
	for _, action := range []HeldAction{
		{
			DeferID:   "allow",
			ActionID:  "allow",
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
			RulePolicy: config.DeferResolutionPolicy{
				AllowOn: config.DeferAllowOn{PolicyPermits: true},
			},
		},
		{
			DeferID:   "block",
			ActionID:  "block",
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
		},
		{
			DeferID:   "still-held",
			ActionID:  "still-held",
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
			RulePolicy: config.DeferResolutionPolicy{
				AllowOn: config.DeferAllowOn{PolicyPermits: true},
			},
		},
	} {
		action := action
		action.Resolve = func(res Resolution) { resolved <- res }
		if err := m.Hold(action); err != nil {
			t.Fatalf("Hold(%s) returned error: %v", action.DeferID, err)
		}
	}

	m.ResolvePolicyReload(func(held HeldAction) (string, error) {
		switch held.DeferID {
		case "allow":
			return config.ActionAllow, nil
		case "block":
			return config.ActionBlock, nil
		case "still-held":
			return config.ActionDefer, nil
		default:
			return config.ActionBlock, nil
		}
	})

	got := map[string]Resolution{}
	for i := 0; i < 2; i++ {
		res := <-resolved
		got[res.DeferID] = res
	}
	if got["allow"].FinalDecision != config.ActionAllow || got["allow"].ResolutionSource != SourcePolicyReload {
		t.Fatalf("allow reload resolution = %+v", got["allow"])
	}
	if got["block"].FinalDecision != config.ActionBlock || got["block"].ResolutionSource != SourcePolicyReload {
		t.Fatalf("block reload resolution = %+v", got["block"])
	}
	if err := m.Resolve("still-held", config.ActionBlock, SourceTimeout); err != nil {
		t.Fatalf("defer reload result did not remain held: %v", err)
	}
}

func TestResolvePolicyReloadErrorBlocks(t *testing.T) {
	ch := make(chan Resolution, 1)
	m := NewManager(Config{Enabled: true, Timeout: time.Hour})
	if err := m.Hold(HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
		Resolve:   func(res Resolution) { ch <- res },
	}); err != nil {
		t.Fatalf("Hold returned error: %v", err)
	}
	m.ResolvePolicyReload(func(HeldAction) (string, error) {
		return "", errors.New("parse failed")
	})
	got := <-ch
	if got.FinalDecision != config.ActionBlock || got.ResolutionSource != SourcePolicyReload {
		t.Fatalf("reload error resolved %+v, want block policy_reload", got)
	}
}

func TestResolveToolInventoryScopesBySession(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 4, MaxPendingPerSession: 4})
	resolved := make(chan Resolution, 2)
	for _, action := range []HeldAction{
		{
			DeferID:   "matching",
			ActionID:  "matching",
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "mcp_stdio", SessionIDOriginal: "orig-a"},
			RulePolicy: config.DeferResolutionPolicy{
				AllowOn: config.DeferAllowOn{ToolInventoryBaseline: true},
			},
		},
		{
			DeferID:   "other-session",
			ActionID:  "other-session",
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "mcp_http", SessionIDOriginal: "orig-b"},
			RulePolicy: config.DeferResolutionPolicy{
				AllowOn: config.DeferAllowOn{ToolInventoryBaseline: true},
			},
		},
	} {
		action := action
		action.Resolve = func(res Resolution) { resolved <- res }
		if err := m.Hold(action); err != nil {
			t.Fatalf("Hold(%s) returned error: %v", action.DeferID, err)
		}
	}

	m.ResolveToolInventory("mcp_stdio", config.ActionAllow)
	got := <-resolved
	if got.DeferID != "matching" || got.FinalDecision != config.ActionAllow || got.ResolutionSource != SourceToolInventory {
		t.Fatalf("resolution = %+v, want matching allow tool_inventory", got)
	}
	if _, ok := m.Held("other-session"); !ok {
		t.Fatal("other-session hold was resolved by different session inventory")
	}
	select {
	case got := <-resolved:
		t.Fatalf("unexpected cross-session resolution: %+v", got)
	default:
	}
	if err := m.Resolve("other-session", config.ActionBlock, SourceCancel); err != nil {
		t.Fatalf("cleanup Resolve returned error: %v", err)
	}
}

func TestResolveAllKillSwitchBlocksHeldActions(t *testing.T) {
	ch := make(chan Resolution, 2)
	m := NewManager(Config{Enabled: true, Timeout: time.Hour})
	for _, id := range []string{"d1", "d2"} {
		if err := m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
			Resolve:   func(res Resolution) { ch <- res },
		}); err != nil {
			t.Fatalf("Hold(%s) returned error: %v", id, err)
		}
	}
	m.ResolveAll(config.ActionBlock, SourceKillSwitch)
	for i := 0; i < 2; i++ {
		got := <-ch
		if got.FinalDecision != config.ActionBlock || got.ResolutionSource != SourceKillSwitch {
			t.Fatalf("kill switch resolution = %+v, want block kill_switch", got)
		}
	}
}

func TestRecordRestartRecoveryClearsPendingJournal(t *testing.T) {
	path := t.TempDir() + "/deferred-actions.jsonl"
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, JournalPath: path})
	held := HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "tool",
		Surface:   SurfaceMCPStdio,
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
		Resolve:   func(Resolution) {},
	}
	if err := m.Hold(held); err != nil {
		t.Fatalf("Hold returned error: %v", err)
	}
	pending, err := PendingJournal(path)
	if err != nil {
		t.Fatalf("PendingJournal returned error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending count = %d, want 1", len(pending))
	}
	if err := m.RecordRestartRecovery(pending[0]); err != nil {
		t.Fatalf("RecordRestartRecovery returned error: %v", err)
	}
	pending, err = PendingJournal(path)
	if err != nil {
		t.Fatalf("PendingJournal after recovery returned error: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending count after recovery = %d, want 0", len(pending))
	}
	_ = m.Resolve("d1", config.ActionBlock, SourceCancel)
}

func TestPendingJournalEmptyMissingMalformedAndLongLine(t *testing.T) {
	pending, err := PendingJournal("")
	if err != nil || pending != nil {
		t.Fatalf("PendingJournal empty = (%+v,%v), want nil nil", pending, err)
	}
	pending, err = PendingJournal(filepath.Join(t.TempDir(), "missing.jsonl"))
	if err != nil || pending != nil {
		t.Fatalf("PendingJournal missing = (%+v,%v), want nil nil", pending, err)
	}
	malformed := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(malformed, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile malformed: %v", err)
	}
	if _, err := PendingJournal(malformed); err == nil || !strings.Contains(err.Error(), "parse defer journal") {
		t.Fatalf("PendingJournal malformed error = %v, want parse error", err)
	}
	longLine := filepath.Join(t.TempDir(), "long.jsonl")
	if err := os.WriteFile(longLine, []byte(strings.Repeat("x", 1024*1024+1)), 0o600); err != nil {
		t.Fatalf("WriteFile long: %v", err)
	}
	if _, err := PendingJournal(longLine); err == nil || !strings.Contains(err.Error(), "scan defer journal") {
		t.Fatalf("PendingJournal long line error = %v, want scan error", err)
	}
}

func TestAppendJournalFailsClosedOnPathErrors(t *testing.T) {
	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile parent: %v", err)
	}
	m := NewManager(Config{Enabled: true, JournalPath: filepath.Join(parentFile, "journal.jsonl")})
	if err := m.appendJournal(journalEntry{DeferID: "d1"}); err == nil {
		t.Fatal("appendJournal with file parent succeeded, want mkdir error")
	}

	dirPath := t.TempDir()
	m = NewManager(Config{Enabled: true, JournalPath: dirPath})
	if err := m.appendJournal(journalEntry{DeferID: "d1"}); err == nil {
		t.Fatal("appendJournal with directory path succeeded, want open/write error")
	}
}

func TestManagerTimerRace(t *testing.T) {
	m := NewManager(Config{
		Enabled:              true,
		Timeout:              time.Nanosecond,
		MaxPending:           512,
		MaxPendingPerSession: 512,
		MaxPendingBytes:      1024 * 1024,
	})
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		id := fmt.Sprintf("d%d", i)
		wg.Add(1)
		err := m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "orig"},
			Resolve: func(Resolution) {
				wg.Done()
			},
		})
		if err != nil {
			wg.Done()
			t.Fatalf("Hold returned error: %v", err)
		}
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timer resolutions did not complete")
	}
}
