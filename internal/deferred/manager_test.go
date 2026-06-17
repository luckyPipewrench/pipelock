// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"errors"
	"fmt"
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
	err := ValidateAction(SurfaceFetch, "defer")
	if err == nil {
		t.Fatal("ValidateAction(fetch, defer) succeeded, want error")
	}
	if !strings.Contains(err.Error(), "defer is not yet supported on fetch:") {
		t.Fatalf("error = %q, want registry rejection wording", err.Error())
	}
	if err := ValidateAction(SurfaceMCPStdio, "defer"); err != nil {
		t.Fatalf("ValidateAction(mcp_stdio, defer) = %v", err)
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
