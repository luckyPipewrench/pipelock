// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Test-local constants for session operator helpers. goconst friendly —
// any string that appears in 3+ places in this file gets a name.
const (
	operKey    = "agent-a|10.0.0.1"
	operAgent  = "agent-a"
	operIP     = "10.0.0.1"
	operDetail = "dlp secret on outbound request"
	operTarget = "api.example.com"
)

func newOperatorTestManager(t *testing.T) (*SessionManager, func()) {
	t.Helper()
	cfg := &config.SessionProfiling{
		MaxSessions:            50,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 300,
		DomainBurst:            10,
		WindowMinutes:          5,
	}
	sm := NewSessionManager(cfg, nil, metrics.New())
	return sm, func() { sm.Close() }
}

func TestAirlockState_EnteredAt(t *testing.T) {
	a := NewAirlockState()
	if !a.EnteredAt().IsZero() {
		t.Errorf("new state EnteredAt: got %v, want zero", a.EnteredAt())
	}

	before := time.Now()
	if changed, _, _ := a.SetTier(config.AirlockTierSoft); !changed {
		t.Fatal("expected transition")
	}
	after := time.Now()

	got := a.EnteredAt()
	if got.Before(before) || got.After(after) {
		t.Errorf("EnteredAt after SetTier: got %v, want within [%v, %v]", got, before, after)
	}

	// Transition to hard updates enteredAt.
	time.Sleep(5 * time.Millisecond)
	if changed, _, _ := a.SetTier(config.AirlockTierHard); !changed {
		t.Fatal("expected transition")
	}
	newTs := a.EnteredAt()
	if !newTs.After(got) {
		t.Errorf("EnteredAt after hard transition should advance: got %v, prev %v", newTs, got)
	}
}

func TestAirlockState_EntryProvenance(t *testing.T) {
	a := NewAirlockState()

	if changed, _, _ := a.SetTierWithProvenance(config.AirlockTierHard, airlockTriggerOnCritical, airlockSourceTriggers); !changed {
		t.Fatal("expected transition")
	}

	trigger, source := a.EntryProvenance()
	if trigger != airlockTriggerOnCritical {
		t.Errorf("trigger: got %q, want %q", trigger, airlockTriggerOnCritical)
	}
	if source != airlockSourceTriggers {
		t.Errorf("source: got %q, want %q", source, airlockSourceTriggers)
	}

	if changed, _, _ := a.ForceSetTierWithProvenance(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI); !changed {
		t.Fatal("expected release to none")
	}
	if !a.EnteredAt().IsZero() {
		t.Errorf("none tier EnteredAt: got %v, want zero", a.EnteredAt())
	}
	trigger, source = a.EntryProvenance()
	if trigger != "" || source != "" {
		t.Errorf("none tier provenance should be cleared, got trigger=%q source=%q", trigger, source)
	}
}

func TestSessionState_RecordEvent_AppendsInOrder(t *testing.T) {
	s := &SessionState{kind: sessionKindIdentity}

	s.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: "one", Severity: "critical"})
	s.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: "two", Severity: "critical"})
	s.RecordEvent(SessionEvent{Kind: "anomaly", Target: operTarget, Detail: "three", Severity: "warn", Score: 2.5})

	events := s.RecentEvents()
	if got, want := len(events), 3; got != want {
		t.Fatalf("events: got %d, want %d", got, want)
	}
	if events[0].Detail != "one" || events[1].Detail != "two" || events[2].Detail != "three" {
		t.Errorf("events not in insertion order: %+v", events)
	}
	// RecordEvent should assign At when the caller leaves it zero.
	for i, e := range events {
		if e.At.IsZero() {
			t.Errorf("event %d has zero At", i)
		}
	}
}

func TestSessionState_RecordEvent_RingBufferOverflow(t *testing.T) {
	s := &SessionState{kind: sessionKindIdentity}

	// Push one more than the bound so the oldest entry is dropped.
	for i := 0; i < maxRecentEvents+5; i++ {
		s.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: "evt", Severity: "critical"})
	}

	events := s.RecentEvents()
	if got, want := len(events), maxRecentEvents; got != want {
		t.Errorf("buffer length: got %d, want %d", got, want)
	}
}

func TestSessionState_RecentEvents_ReturnsCopy(t *testing.T) {
	s := &SessionState{kind: sessionKindIdentity}
	s.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: "orig"})

	events := s.RecentEvents()
	events[0].Detail = "mutated"

	again := s.RecentEvents()
	if again[0].Detail != "orig" {
		t.Errorf("RecentEvents should return a copy: got %q, want %q", again[0].Detail, "orig")
	}
}

func TestSessionState_RecentEvents_Empty(t *testing.T) {
	s := &SessionState{kind: sessionKindIdentity}
	events := s.RecentEvents()
	if events == nil {
		t.Error("expected non-nil empty slice")
	}
	if len(events) != 0 {
		t.Errorf("length: got %d, want 0", len(events))
	}
}

func TestSessionState_Reset_ClearsRecentEvents(t *testing.T) {
	s := &SessionState{kind: sessionKindIdentity}
	s.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: "one"})
	s.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: "two"})

	s.Reset()

	events := s.RecentEvents()
	if len(events) != 0 {
		t.Errorf("Reset did not clear events: %+v", events)
	}
}

func TestSessionManager_SessionByKey(t *testing.T) {
	sm, cleanup := newOperatorTestManager(t)
	defer cleanup()

	if got := sm.SessionByKey(operKey); got != nil {
		t.Errorf("unknown key: got %v, want nil", got)
	}

	sm.GetOrCreate(operKey)
	got := sm.SessionByKey(operKey)
	if got == nil {
		t.Fatal("existing key: got nil, want session pointer")
	}
}

func TestSessionManager_SnapshotByKey_NotFound(t *testing.T) {
	sm, cleanup := newOperatorTestManager(t)
	defer cleanup()

	_, _, ok := sm.SnapshotByKey(operKey)
	if ok {
		t.Error("expected not found for unknown key")
	}
}

func TestSessionManager_SnapshotByKey_IncludesEvents(t *testing.T) {
	sm, cleanup := newOperatorTestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate(operKey)
	sess.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: operDetail, Severity: "critical"})
	_, _, _ = sess.Airlock().SetTier(config.AirlockTierSoft)

	snap, events, ok := sm.SnapshotByKey(operKey)
	if !ok {
		t.Fatal("expected found")
	}
	if snap.Key != operKey {
		t.Errorf("snap.Key: got %q, want %q", snap.Key, operKey)
	}
	if snap.Agent != operAgent {
		t.Errorf("snap.Agent: got %q, want %q", snap.Agent, operAgent)
	}
	if snap.ClientIP != operIP {
		t.Errorf("snap.ClientIP: got %q, want %q", snap.ClientIP, operIP)
	}
	if snap.AirlockTier != config.AirlockTierSoft {
		t.Errorf("snap.AirlockTier: got %q, want %q", snap.AirlockTier, config.AirlockTierSoft)
	}
	if len(events) != 1 {
		t.Fatalf("events: got %d, want 1", len(events))
	}
	if events[0].Detail != operDetail {
		t.Errorf("event detail: got %q, want %q", events[0].Detail, operDetail)
	}
}

func TestSessionManager_AdminSnapshotByKey_IncludesAirlockMetadata(t *testing.T) {
	sm, cleanup := newOperatorTestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate(operKey)
	sess.RecordEvent(SessionEvent{Kind: "block", Target: operTarget, Detail: operDetail, Severity: "critical"})
	_, _, _ = sess.Airlock().SetTierWithProvenance(config.AirlockTierHard, airlockTriggerOnCritical, airlockSourceTriggers)

	snap, ok := sm.AdminSnapshotByKey(operKey)
	if !ok {
		t.Fatal("expected found")
	}
	if snap.AirlockTier != config.AirlockTierHard {
		t.Errorf("snap.AirlockTier: got %q, want %q", snap.AirlockTier, config.AirlockTierHard)
	}
	if snap.AirlockEnteredAt.IsZero() {
		t.Fatal("AirlockEnteredAt should be non-zero")
	}
	if snap.AirlockTrigger != airlockTriggerOnCritical {
		t.Errorf("AirlockTrigger: got %q, want %q", snap.AirlockTrigger, airlockTriggerOnCritical)
	}
	if snap.AirlockTriggerSource != airlockSourceTriggers {
		t.Errorf("AirlockTriggerSource: got %q, want %q", snap.AirlockTriggerSource, airlockSourceTriggers)
	}
	if len(snap.RecentEvents) != 1 {
		t.Fatalf("RecentEvents: got %d, want 1", len(snap.RecentEvents))
	}
}

func TestSessionManager_AirlockConfig(t *testing.T) {
	sm, cleanup := newOperatorTestManager(t)
	defer cleanup()

	// No config set yet.
	if got := sm.AirlockConfig(); got != nil {
		t.Errorf("default AirlockConfig: got %v, want nil", got)
	}

	cfg := &config.Airlock{
		Enabled: true,
		Timers:  config.AirlockTimers{SoftMinutes: 5, HardMinutes: 10},
	}
	sm.UpdateConfig(
		&config.SessionProfiling{MaxSessions: 10, SessionTTLMinutes: 30, CleanupIntervalSeconds: 60, DomainBurst: 10, WindowMinutes: 5},
		nil,
		cfg,
	)

	got := sm.AirlockConfig()
	if got == nil {
		t.Fatal("after set: got nil, want pointer")
	}
	if got.Timers.SoftMinutes != 5 {
		t.Errorf("Timers.SoftMinutes: got %d, want 5", got.Timers.SoftMinutes)
	}
}

func TestFrozenToolRegistry_ToolNames(t *testing.T) {
	r := NewFrozenToolRegistry()
	if names := r.ToolNames("missing"); names != nil {
		t.Errorf("missing key: got %v, want nil", names)
	}

	r.Freeze("mcp-1", []string{"zeta", "alpha", "mu"})
	names := r.ToolNames("mcp-1")
	if got, want := len(names), 3; got != want {
		t.Fatalf("names: got %d, want %d", got, want)
	}
	// Sorted for stable preview.
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Errorf("names not sorted: %v", names)
		}
	}
}

func TestRecordSessionActivity_RecordsBlockEvent(t *testing.T) {
	// End-to-end: a blocked scanner result flows through recordSessionActivity
	// and surfaces in the session's recent-event ring buffer.
	cfg := config.Defaults()
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 50
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 60
	cfg.SessionProfiling.DomainBurst = 10
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.Internal = nil

	sc := scanner.New(cfg)
	defer sc.Close()

	logger := audit.NewNop()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	result := scanner.Result{Allowed: false, Reason: operDetail, Score: 0.9}
	p.recordSessionActivity(operIP, operAgent, operTarget, "req-1", result, cfg, logger, false)

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	key := operAgent + "|" + operIP
	sess := sm.SessionByKey(key)
	if sess == nil {
		t.Fatalf("expected session %q", key)
	}
	events := sess.RecentEvents()
	if len(events) == 0 {
		t.Fatal("expected at least one recorded event")
	}
	var foundBlock bool
	for _, e := range events {
		if e.Kind == "block" && e.Target == operTarget {
			foundBlock = true
			break
		}
	}
	if !foundBlock {
		t.Errorf("no block event found for target %q: %+v", operTarget, events)
	}
}
