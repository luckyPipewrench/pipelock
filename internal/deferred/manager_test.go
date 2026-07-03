// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"encoding/json"
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
		MaxCascadeDepth:      4,
	}
	got := policy.String()
	for _, want := range []string{`"max_pending":3`, `"max_pending_per_session":2`, `"max_pending_bytes":512`, `"max_cascade_depth":4`} {
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
	withCascade := ReceiptPolicyStringFor(ReceiptPolicyOptions{
		Bounds: policy,
		Cascade: &ReceiptCascade{
			ParentDeferID: "parent",
			CascadeDepth:  2,
			Linkage:       LinkageSessionPendingAncestor,
		},
	})
	var parsed ReceiptPolicy
	if err := json.Unmarshal([]byte(withCascade), &parsed); err != nil {
		t.Fatalf("ReceiptPolicyStringFor cascade JSON: %v", err)
	}
	if parsed.Cascade == nil || parsed.Cascade.ParentDeferID != "parent" || parsed.Cascade.CascadeDepth != 2 || parsed.Cascade.Linkage != LinkageSessionPendingAncestor {
		t.Fatalf("parsed cascade policy = %+v", parsed.Cascade)
	}
}

func TestManagerDefaultsNilHelpersAndValidation(t *testing.T) {
	m := NewManager(Config{})
	policy := m.Policy()
	if policy.Timeout != DefaultTimeoutSeconds*time.Second ||
		policy.MaxPending != DefaultMaxPending ||
		policy.MaxPendingPerSession != DefaultMaxPendingSession ||
		policy.MaxPendingBytes != DefaultMaxPendingBytes ||
		policy.MaxCascadeDepth != DefaultMaxCascadeDepth {
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
			Authority: AuthoritySnapshot{SessionID: "s2", SessionIDOriginal: "orig"},
		},
		{
			DeferID:   "still-held",
			ActionID:  "still-held",
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s3", SessionIDOriginal: "orig"},
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

func TestManagerDerivesSessionPendingAncestorLinkage(t *testing.T) {
	tests := []struct {
		name      string
		session   string
		wantChain bool
	}{
		{name: "named session", session: "s1", wantChain: true},
		// An empty session ID is not an identity: unrelated session-less
		// flows must never be linked into one ancestry chain.
		{name: "empty session stays unlinked", session: "", wantChain: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 8, MaxPendingPerSession: 8, MaxCascadeDepth: 8})
			for i, id := range []string{"a", "b", "c"} {
				if err := m.Hold(HeldAction{
					DeferID:   id,
					ActionID:  id,
					Target:    "tool",
					SizeBytes: 1,
					Authority: AuthoritySnapshot{SessionID: tt.session, SessionIDOriginal: tt.session},
					Resolve:   func(Resolution) {},
				}); err != nil {
					t.Fatalf("Hold(%s): %v", id, err)
				}
				held, ok := m.Held(id)
				if !ok {
					t.Fatalf("Held(%s) missing", id)
				}
				wantDepth := 1
				if tt.wantChain {
					wantDepth = i + 1
				}
				if held.CascadeDepth != wantDepth || held.Linkage != LinkageSessionPendingAncestor {
					t.Fatalf("Held(%s) depth/linkage = %d/%q, want depth %d", id, held.CascadeDepth, held.Linkage, wantDepth)
				}
			}
			b, _ := m.Held("b")
			c, _ := m.Held("c")
			if tt.wantChain {
				if b.ParentDeferID != "a" || c.ParentDeferID != "b" {
					t.Fatalf("parents b=%q c=%q, want a/b", b.ParentDeferID, c.ParentDeferID)
				}
			} else if b.ParentDeferID != "" || c.ParentDeferID != "" {
				t.Fatalf("session-less holds linked: b parent=%q c parent=%q, want none", b.ParentDeferID, c.ParentDeferID)
			}
		})
	}
}

func TestManagerEmptySessionDenialDoesNotCascadeToStrangers(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 8, MaxPendingPerSession: 8, MaxCascadeDepth: 8})
	resolved := make(chan Resolution, 2)
	for _, id := range []string{"a", "b"} {
		if err := m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{},
			Resolve:   func(res Resolution) { resolved <- res },
		}); err != nil {
			t.Fatalf("Hold(%s): %v", id, err)
		}
	}
	if err := m.Resolve("a", config.ActionBlock, SourceApproval); err != nil {
		t.Fatalf("Resolve(a): %v", err)
	}
	got := <-resolved
	if got.DeferID != "a" {
		t.Fatalf("resolved %q first, want a", got.DeferID)
	}
	if _, ok := m.Held("b"); !ok {
		t.Fatal("unrelated session-less hold b was cascade-resolved by a's denial")
	}
	select {
	case res := <-resolved:
		t.Fatalf("unexpected cascade resolution %+v for unrelated hold", res)
	default:
	}
}

func TestManagerLinkageResetAndCrossSessionIsolation(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 8, MaxPendingPerSession: 8, MaxCascadeDepth: 8})
	resolved := make(chan Resolution, 4)
	hold := func(id, session string) {
		t.Helper()
		if err := m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: session, SessionIDOriginal: session},
			Resolve:   func(res Resolution) { resolved <- res },
		}); err != nil {
			t.Fatalf("Hold(%s): %v", id, err)
		}
	}
	hold("a", "s1")
	hold("b", "s2")
	b, _ := m.Held("b")
	if b.ParentDeferID != "" || b.CascadeDepth != 1 {
		t.Fatalf("cross-session hold linked: %+v", b)
	}
	if err := m.Resolve("a", config.ActionAllow, SourceApproval); err != nil {
		t.Fatalf("Resolve(a): %v", err)
	}
	<-resolved
	hold("c", "s1")
	c, _ := m.Held("c")
	if c.ParentDeferID != "" || c.CascadeDepth != 1 {
		t.Fatalf("reset hold = %+v, want root depth 1", c)
	}
}

func TestManagerCascadeLimitDeniesBeforeStateAndJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deferred-actions.jsonl")
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 8, MaxPendingPerSession: 8, MaxCascadeDepth: 2, JournalPath: path})
	for _, id := range []string{"a", "b"} {
		if err := m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
			Resolve:   func(Resolution) {},
		}); err != nil {
			t.Fatalf("Hold(%s): %v", id, err)
		}
	}
	err := m.Hold(HeldAction{
		DeferID:   "c",
		ActionID:  "c",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
		Resolve:   func(Resolution) {},
	})
	var limitErr *CascadeLimitError
	if !errors.Is(err, ErrCascadeLimit) || !errors.As(err, &limitErr) {
		t.Fatalf("Hold(c) error = %v, want CascadeLimitError", err)
	}
	if limitErr.Depth != 3 || limitErr.Limit != 2 || limitErr.ParentDeferID != "b" {
		t.Fatalf("limit error = %+v", limitErr)
	}
	if HoldFailureSource(err) != SourceCascadeLimit {
		t.Fatalf("HoldFailureSource = %q, want cascade_limit", HoldFailureSource(err))
	}
	if _, ok := m.Held("c"); ok {
		t.Fatal("limit-denied action was held")
	}
	pending, journalErr := PendingJournal(path)
	if journalErr != nil {
		t.Fatalf("PendingJournal: %v", journalErr)
	}
	if len(pending) != 2 {
		t.Fatalf("pending journal count = %d, want 2", len(pending))
	}
}

func TestManagerSequentialRatchetBoundedByCascadeDepth(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 8, MaxPendingPerSession: 2, MaxCascadeDepth: 3})
	resolved := make(chan Resolution, 3)
	hold := func(id string) error {
		return m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
			Resolve:   func(res Resolution) { resolved <- res },
		})
	}
	for _, id := range []string{"a", "b"} {
		if err := hold(id); err != nil {
			t.Fatalf("Hold(%s): %v", id, err)
		}
	}
	if err := m.Resolve("a", config.ActionAllow, SourceApproval); err != nil {
		t.Fatalf("Resolve(a): %v", err)
	}
	<-resolved
	if err := hold("c"); err != nil {
		t.Fatalf("Hold(c): %v", err)
	}
	if err := m.Resolve("b", config.ActionAllow, SourceApproval); err != nil {
		t.Fatalf("Resolve(b): %v", err)
	}
	<-resolved
	err := hold("d")
	if !errors.Is(err, ErrCascadeLimit) {
		t.Fatalf("Hold(d) error = %v, want ErrCascadeLimit", err)
	}
	if got := len(m.Snapshot()); got != 1 {
		t.Fatalf("pending count = %d, want 1", got)
	}
}

func TestManagerDefaultBurstCompatUsesSessionCapacityBeforeCascadeLimit(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour})
	for i := 0; i < DefaultMaxPendingSession; i++ {
		id := fmt.Sprintf("d%d", i)
		if err := m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
			Resolve:   func(Resolution) {},
		}); err != nil {
			t.Fatalf("Hold(%s): %v", id, err)
		}
	}
	err := m.Hold(HeldAction{
		DeferID:   "overflow",
		ActionID:  "overflow",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
		Resolve:   func(Resolution) {},
	})
	if !errors.Is(err, ErrCapacity) || errors.Is(err, ErrCascadeLimit) {
		t.Fatalf("overflow error = %v, want capacity only", err)
	}
	if HoldFailureSource(err) != SourceCapacity {
		t.Fatalf("HoldFailureSource = %q, want capacity", HoldFailureSource(err))
	}
}

func TestManagerCascadeBlockDescendantsAndAllowDoesNotPropagate(t *testing.T) {
	t.Run("block cascades descendants", func(t *testing.T) {
		m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 8, MaxPendingPerSession: 8, MaxCascadeDepth: 8})
		resolved := make(chan Resolution, 3)
		for _, id := range []string{"a", "b", "c"} {
			if err := m.Hold(HeldAction{
				DeferID:   id,
				ActionID:  id,
				Target:    "tool",
				SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
				Resolve:   func(res Resolution) { resolved <- res },
			}); err != nil {
				t.Fatalf("Hold(%s): %v", id, err)
			}
		}
		if err := m.Resolve("a", config.ActionBlock, SourceApproval); err != nil {
			t.Fatalf("Resolve(a): %v", err)
		}
		got := map[string]Resolution{}
		for i := 0; i < 3; i++ {
			res := <-resolved
			got[res.DeferID] = res
		}
		if got["a"].ResolutionSource != SourceApproval {
			t.Fatalf("parent source = %q, want approval", got["a"].ResolutionSource)
		}
		for _, id := range []string{"b", "c"} {
			if got[id].FinalDecision != config.ActionBlock || got[id].ResolutionSource != SourceCascade {
				t.Fatalf("%s resolution = %+v, want block cascade", id, got[id])
			}
			if got[id].CascadeDepth == 0 || got[id].Linkage != LinkageSessionPendingAncestor {
				t.Fatalf("%s linkage fields missing: %+v", id, got[id])
			}
		}
	})

	t.Run("allow leaves child held", func(t *testing.T) {
		m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 4, MaxPendingPerSession: 4, MaxCascadeDepth: 4})
		resolved := make(chan Resolution, 2)
		for _, id := range []string{"a", "b"} {
			if err := m.Hold(HeldAction{
				DeferID:   id,
				ActionID:  id,
				Target:    "tool",
				SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
				Resolve:   func(res Resolution) { resolved <- res },
			}); err != nil {
				t.Fatalf("Hold(%s): %v", id, err)
			}
		}
		if err := m.Resolve("a", config.ActionAllow, SourceApproval); err != nil {
			t.Fatalf("Resolve(a): %v", err)
		}
		if got := <-resolved; got.DeferID != "a" || got.FinalDecision != config.ActionAllow {
			t.Fatalf("parent resolution = %+v", got)
		}
		if _, ok := m.Held("b"); !ok {
			t.Fatal("child was resolved by parent allow")
		}
		if err := m.Resolve("b", config.ActionAllow, SourceApproval); err != nil {
			t.Fatalf("Resolve(b): %v", err)
		}
		if got := <-resolved; got.DeferID != "b" || got.FinalDecision != config.ActionAllow || got.ResolutionSource != SourceApproval {
			t.Fatalf("child resolution = %+v", got)
		}
	})
}

func TestManagerParentBlockCallbackCannotAllowChildBeforeCascade(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 4, MaxPendingPerSession: 4, MaxCascadeDepth: 4})
	resolved := make(chan Resolution, 2)
	if err := m.Hold(HeldAction{
		DeferID:   "a",
		ActionID:  "a",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
		Resolve: func(res Resolution) {
			if err := m.Resolve("b", config.ActionAllow, SourceApproval); err != nil && !errors.Is(err, ErrNotFound) {
				t.Errorf("Resolve(b allow) from parent callback: %v", err)
			}
			resolved <- res
		},
	}); err != nil {
		t.Fatalf("Hold(a): %v", err)
	}
	if err := m.Hold(HeldAction{
		DeferID:   "b",
		ActionID:  "b",
		Target:    "tool",
		SizeBytes: 1,
		Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
		Resolve:   func(res Resolution) { resolved <- res },
	}); err != nil {
		t.Fatalf("Hold(b): %v", err)
	}
	if err := m.Resolve("a", config.ActionBlock, SourceApproval); err != nil {
		t.Fatalf("Resolve(a): %v", err)
	}
	got := map[string]Resolution{}
	for i := 0; i < 2; i++ {
		res := waitResolution(t, resolved)
		got[res.DeferID] = res
	}
	if got["b"].FinalDecision != config.ActionBlock || got["b"].ResolutionSource != SourceCascade {
		t.Fatalf("child resolution = %+v, want fail-closed cascade block", got["b"])
	}
}

func TestManagerTimeoutAndStepUpCascadeBlockChildren(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		resolved := make(chan Resolution, 2)
		m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 4, MaxPendingPerSession: 4, MaxCascadeDepth: 4})
		for _, id := range []string{"a", "b"} {
			if err := m.Hold(HeldAction{
				DeferID:   id,
				ActionID:  id,
				Target:    "tool",
				SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
				Resolve:   func(res Resolution) { resolved <- res },
			}); err != nil {
				t.Fatalf("Hold(%s): %v", id, err)
			}
		}
		if err := m.Resolve("a", config.ActionBlock, SourceTimeout); err != nil {
			t.Fatalf("Resolve(a timeout): %v", err)
		}
		got := map[string]Resolution{}
		for i := 0; i < 2; i++ {
			res := waitResolution(t, resolved)
			got[res.DeferID] = res
		}
		if got["a"].ResolutionSource != SourceTimeout || got["b"].ResolutionSource != SourceCascade {
			t.Fatalf("timeout cascade resolutions = %+v", got)
		}
	})

	t.Run("step up", func(t *testing.T) {
		resolved := make(chan Resolution, 2)
		m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 4, MaxPendingPerSession: 4, MaxCascadeDepth: 4})
		for _, action := range []HeldAction{
			{
				DeferID:   "a",
				ActionID:  "a",
				Target:    "tool",
				SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
				RulePolicy: config.DeferResolutionPolicy{
					StepUpOn: config.DeferStepUpOn{ApprovalRequestsHuman: true},
				},
			},
			{
				DeferID:   "b",
				ActionID:  "b",
				Target:    "tool",
				SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
			},
		} {
			action := action
			action.Resolve = func(res Resolution) { resolved <- res }
			if err := m.Hold(action); err != nil {
				t.Fatalf("Hold(%s): %v", action.DeferID, err)
			}
		}
		if err := m.ResolveApproval("a", config.ActionAsk); err != nil {
			t.Fatalf("ResolveApproval(a): %v", err)
		}
		got := map[string]Resolution{}
		for i := 0; i < 2; i++ {
			res := <-resolved
			got[res.DeferID] = res
		}
		if got["a"].FinalDecision != config.ActionAsk || got["b"].ResolutionSource != SourceCascade {
			t.Fatalf("step-up cascade resolutions = %+v", got)
		}
	})
}

func TestManagerCascadeFixpointCatchesAttachDuringCascade(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 8, MaxPendingPerSession: 8, MaxCascadeDepth: 8})
	resolved := make(chan Resolution, 4)
	for _, id := range []string{"a", "b", "c"} {
		id := id
		if err := m.Hold(HeldAction{
			DeferID:   id,
			ActionID:  id,
			Target:    "tool",
			SizeBytes: 1,
			Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
			Resolve: func(res Resolution) {
				if res.DeferID == "b" && res.ResolutionSource == SourceCascade {
					if err := m.Hold(HeldAction{
						DeferID:   "d",
						ActionID:  "d",
						Target:    "tool",
						SizeBytes: 1,
						Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
						Resolve:   func(res Resolution) { resolved <- res },
					}); err != nil {
						t.Errorf("Hold(d) during cascade: %v", err)
					}
				}
				resolved <- res
			},
		}); err != nil {
			t.Fatalf("Hold(%s): %v", id, err)
		}
	}
	if err := m.Resolve("a", config.ActionBlock, SourceApproval); err != nil {
		t.Fatalf("Resolve(a): %v", err)
	}
	got := map[string]Resolution{}
	for i := 0; i < 4; i++ {
		res := waitResolution(t, resolved)
		got[res.DeferID] = res
	}
	for _, id := range []string{"b", "c", "d"} {
		if got[id].FinalDecision != config.ActionBlock || got[id].ResolutionSource != SourceCascade {
			t.Fatalf("%s resolution = %+v, want cascade block", id, got[id])
		}
	}
	if got["d"].ParentDeferID != "c" || got["d"].CascadeDepth != 4 {
		t.Fatalf("attach-during-cascade child linkage = %+v, want parent c depth 4", got["d"])
	}
	if pending := m.Snapshot(); len(pending) != 0 {
		t.Fatalf("pending after cascade fixpoint = %+v, want none", pending)
	}
}

func TestManagerConcurrentResolveAllAndCascadeResolveExactlyOnce(t *testing.T) {
	for iter := 0; iter < 25; iter++ {
		m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 16, MaxPendingPerSession: 16, MaxCascadeDepth: 16})
		resolved := make(chan Resolution, 8)
		for i := 0; i < 8; i++ {
			id := fmt.Sprintf("d%d", i)
			if err := m.Hold(HeldAction{
				DeferID:   id,
				ActionID:  id,
				Target:    "tool",
				SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
				Resolve:   func(res Resolution) { resolved <- res },
			}); err != nil {
				t.Fatalf("iter %d Hold(%s): %v", iter, id, err)
			}
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = m.Resolve("d0", config.ActionBlock, SourceApproval)
		}()
		go func() {
			defer wg.Done()
			m.ResolveAll(config.ActionBlock, SourceKillSwitch)
		}()
		wg.Wait()

		seen := map[string]Resolution{}
		for i := 0; i < 8; i++ {
			res := waitResolution(t, resolved)
			if _, exists := seen[res.DeferID]; exists {
				t.Fatalf("iter %d duplicate resolution for %s", iter, res.DeferID)
			}
			if res.FinalDecision != config.ActionBlock {
				t.Fatalf("iter %d resolution = %+v, want block", iter, res)
			}
			seen[res.DeferID] = res
		}
		select {
		case extra := <-resolved:
			t.Fatalf("iter %d extra resolution: %+v", iter, extra)
		default:
		}
		if pending := m.Snapshot(); len(pending) != 0 {
			t.Fatalf("iter %d pending after concurrent resolve = %+v, want none", iter, pending)
		}
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
		if got.FinalDecision != config.ActionBlock {
			t.Fatalf("kill switch resolution = %+v, want block", got)
		}
		if got.ResolutionSource != SourceKillSwitch && got.ResolutionSource != SourceCascade {
			t.Fatalf("kill switch resolution = %+v, want kill_switch or cascade", got)
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

func TestPendingJournalRoundTripsCascadeFieldsAndPreUpgradeEntries(t *testing.T) {
	t.Run("roundtrip cascade fields", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "deferred-actions.jsonl")
		m := NewManager(Config{Enabled: true, Timeout: time.Hour, MaxPending: 4, MaxPendingPerSession: 4, MaxCascadeDepth: 4, JournalPath: path})
		for _, id := range []string{"a", "b"} {
			if err := m.Hold(HeldAction{
				DeferID:   id,
				ActionID:  id,
				Target:    "tool",
				Surface:   SurfaceMCPStdio,
				SizeBytes: 1,
				Authority: AuthoritySnapshot{SessionID: "s1", SessionIDOriginal: "s1"},
				Resolve:   func(Resolution) {},
			}); err != nil {
				t.Fatalf("Hold(%s): %v", id, err)
			}
		}
		pending, err := PendingJournal(path)
		if err != nil {
			t.Fatalf("PendingJournal: %v", err)
		}
		byID := map[string]HeldAction{}
		for _, held := range pending {
			byID[held.DeferID] = held
		}
		if byID["b"].ParentDeferID != "a" || byID["b"].CascadeDepth != 2 || byID["b"].Linkage != LinkageSessionPendingAncestor {
			t.Fatalf("roundtripped child = %+v", byID["b"])
		}
	})

	t.Run("pre-upgrade entry", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "deferred-actions.jsonl")
		line := `{"defer_id":"legacy","action_id":"legacy-action","state":"deferred_held","authority":{"SessionID":"s1","SessionIDOriginal":"s1"},"timestamp":"2026-07-03T00:00:00Z"}` + "\n"
		if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		pending, err := PendingJournal(path)
		if err != nil {
			t.Fatalf("PendingJournal: %v", err)
		}
		if len(pending) != 1 || pending[0].CascadeDepth != 0 || pending[0].ParentDeferID != "" || pending[0].Linkage != "" {
			t.Fatalf("pre-upgrade pending = %+v", pending)
		}
	})
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
		MaxCascadeDepth:      512,
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

func waitResolution(t *testing.T, ch <-chan Resolution) Resolution {
	t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for deferred resolution")
	}
	return Resolution{}
}
