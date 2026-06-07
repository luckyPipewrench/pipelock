// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	adaptiveScopePollHost = "poll.example"
	adaptiveScopeSendHost = "send.example"
)

func adaptiveScopedAirlockConfig() *config.Config {
	cfg := adaptiveConfigBlockAll()
	cfg.Airlock.Enabled = true
	cfg.Airlock.Triggers.OnElevated = config.AirlockTierHard
	cfg.Airlock.Triggers.OnHigh = config.AirlockTierHard
	cfg.Airlock.Triggers.OnCritical = config.AirlockTierDrain
	return cfg
}

func newAdaptiveScopeProxy(t *testing.T, cfg *config.Config) (*Proxy, *audit.Logger) {
	t.Helper()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p, logger
}

func scopedSession(t *testing.T, p *Proxy) *SessionState {
	t.Helper()
	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	return sm.GetOrCreate(adaptiveSessionKeyLoopback)
}

func recordPollThreat(p *Proxy, logger *audit.Logger, cfg *config.Config, reqID string) {
	p.recordSessionActivity(
		adaptiveSessionKeyLoopback,
		agentAnonymous,
		adaptiveScopePollHost,
		reqID,
		threatResult(),
		cfg,
		logger,
		true,
	)
}

func TestAdaptiveScope_AirlockDoesNotBlackholeUnrelatedDestination(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	recordPollThreat(p, logger, cfg, "req-poll-1")
	recordPollThreat(p, logger, cfg, "req-poll-2")

	pollScope := adaptiveScopeForHost(adaptiveScopePollHost)
	sendScope := adaptiveScopeForHost(adaptiveScopeSendHost)
	if got := sess.AirlockForScope(pollScope).Tier(); got != config.AirlockTierHard {
		t.Fatalf("poll scope tier = %q, want hard", got)
	}
	if got := sess.AirlockForScope(sendScope).Tier(); got != config.AirlockTierNone {
		t.Fatalf("send scope tier = %q, want none", got)
	}

	allowed, reason := ClassifyAction(sess.AirlockForScope(sendScope).Tier(), "POST", TransportForward, false)
	if !allowed {
		t.Fatalf("unrelated send destination was blocked: %s", reason)
	}
}

func TestAdaptiveScope_InfrastructureRetryStormDoesNotEnterAirlock(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	for i := 0; i < 20; i++ {
		p.recordSessionActivity(
			adaptiveSessionKeyLoopback,
			agentAnonymous,
			adaptiveScopePollHost,
			"req-infra-storm",
			infraErrorResult(),
			cfg,
			logger,
			true,
		)
	}

	scope := adaptiveScopeForHost(adaptiveScopePollHost)
	if got := sess.ScopedEscalationLevel(scope); got != 0 {
		t.Fatalf("infra retry storm scoped level = %d, want 0", got)
	}
	if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierNone {
		t.Fatalf("infra retry storm airlock tier = %q, want none", got)
	}
}

func TestAdaptiveScope_CleanRequestDoesNotEraseAttackEscalation(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)
	scope := adaptiveScopeForHost(adaptiveScopePollHost)

	recordPollThreat(p, logger, cfg, "req-threat-1")
	p.recordSessionActivity(
		adaptiveSessionKeyLoopback,
		agentAnonymous,
		adaptiveScopePollHost,
		"req-clean-1",
		scanner.Result{Allowed: true},
		cfg,
		logger,
		false,
	)
	recordPollThreat(p, logger, cfg, "req-threat-2")

	if got := sess.ScopedEscalationLevel(scope); got < 1 {
		t.Fatalf("alternating clean/threat scoped level = %d, want >= 1", got)
	}
	if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierHard {
		t.Fatalf("alternating clean/threat airlock tier = %q, want hard", got)
	}
}

func TestAdaptiveScope_RecoveredLaneCanEscalateAgain(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)
	scope := adaptiveScopeForHost(adaptiveScopePollHost)

	recordPollThreat(p, logger, cfg, "req-threat-1")
	recordPollThreat(p, logger, cfg, "req-threat-2")
	if got := sess.ScopedEscalationLevel(scope); got != 1 {
		t.Fatalf("initial scoped level = %d, want 1", got)
	}

	sess.mu.Lock()
	sess.scopes[scope].lastEscalation = time.Now().Add(-maxLevelDuration - time.Second)
	sess.mu.Unlock()
	changes := sess.TryAutoRecoverScopes(func(level int) bool {
		return level >= 1
	})
	if len(changes) != 1 {
		t.Fatalf("scoped recovery changes = %d, want 1", len(changes))
	}
	if got := sess.ScopedEscalationLevel(scope); got != 0 {
		t.Fatalf("recovered scoped level = %d, want 0", got)
	}

	recordPollThreat(p, logger, cfg, "req-threat-3")
	recordPollThreat(p, logger, cfg, "req-threat-4")
	if got := sess.ScopedEscalationLevel(scope); got < 1 {
		t.Fatalf("post-recovery scoped level = %d, want >= 1", got)
	}
}

func TestAdaptiveScope_CleanRequestDoesNotAllocateScope(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, _ := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	// A clean request to a host that never raised a signal must not create a
	// scope lane, so broad benign browsing cannot grow the map unbounded.
	sess.RecordScopedClean(adaptiveScopeForHost("never-threatened.example"), 1.0)

	sess.mu.Lock()
	n := len(sess.scopes)
	sess.mu.Unlock()
	if n != 0 {
		t.Fatalf("clean request to a never-threatened host allocated %d scope lanes, want 0", n)
	}
}

func TestAdaptiveScope_ScopeCardinalityIsBounded(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, _ := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	// High threshold so individual signals do not escalate; we only care that
	// the per-session scope map cannot grow past the cap.
	const highThreshold = 1_000_000.0
	for i := 0; i < maxAdaptiveScopes+50; i++ {
		sess.RecordScopedSignal(adaptiveScopeForHost(fmt.Sprintf("host-%d.example", i)), session.SignalNearMiss, highThreshold)
	}

	sess.mu.Lock()
	n := len(sess.scopes)
	authoritative := sess.globalSignalsAuthoritative
	sess.mu.Unlock()
	if n > maxAdaptiveScopes {
		t.Fatalf("scope map grew to %d entries, want <= %d", n, maxAdaptiveScopes)
	}
	if !authoritative {
		t.Fatal("over-cap destination signals must fall back to the global authoritative lane")
	}
}

func TestAdaptiveScope_OverCapEscalationLatchesGlobalBlockAll(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	const highThreshold = 1_000_000.0
	for i := 0; i < maxAdaptiveScopes; i++ {
		sess.RecordScopedSignal(adaptiveScopeForHost(fmt.Sprintf("host-%d.example", i)), session.SignalNearMiss, highThreshold)
	}

	sess.mu.Lock()
	sess.threatScore = 0
	sess.escalationLevel = 0
	sess.currentThreshold = 0
	sess.globalSignalsAuthoritative = false
	sess.mu.Unlock()

	ep := decide.EscalationParams{
		Threshold: 1.0,
		Logger:    logger,
		Session:   adaptiveSessionKeyLoopback,
		ClientIP:  adaptiveSessionKeyLoopback,
		RequestID: "req-over-cap",
	}
	recordAdaptiveSignalForScope(sess, adaptiveScopeForHost("over-cap.example"), session.SignalBlock, &cfg.AdaptiveEnforcement, ep)

	if !sess.BlockAll() {
		t.Fatal("over-cap scoped escalation must latch global block_all")
	}
}

func TestRecordScopedSignal_MirrorsAggregateScoreWithoutGlobalBlockAll(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	recordPollThreat(p, logger, cfg, "req-threat-1")
	recordPollThreat(p, logger, cfg, "req-threat-2")

	if sess.EscalationLevel() == 0 {
		t.Fatal("aggregate session level did not record scoped threat signals")
	}
	if sess.BlockAll() {
		t.Fatal("aggregate block_all must not be latched by destination-scoped escalation")
	}
}

func TestRecordAdaptiveSignalForScope_LatchesOnlyScopedBlockAll(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)
	scope := adaptiveScopeForHost(adaptiveScopePollHost)

	ep := decide.EscalationParams{
		Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
		Logger:    logger,
		Session:   adaptiveSessionKeyLoopback,
		ClientIP:  adaptiveSessionKeyLoopback,
		RequestID: "req-scoped-helper",
	}
	recordAdaptiveSignalForScope(sess, scope, session.SignalBlock, &cfg.AdaptiveEnforcement, ep)
	recordAdaptiveSignalForScope(sess, scope, session.SignalBlock, &cfg.AdaptiveEnforcement, ep)

	if sess.BlockAll() {
		t.Fatal("scoped helper must not latch aggregate block_all")
	}

	sess.mu.Lock()
	st := sess.scopes[scope]
	scopedBlocked := st != nil && st.atBlockAll
	sess.mu.Unlock()
	if !scopedBlocked {
		t.Fatal("scoped helper did not latch block_all for the threatened destination")
	}
}

func TestInterceptRecordSignal_UsesDestinationScope(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	ic := &InterceptContext{
		TargetHost: adaptiveScopePollHost,
		Config:     cfg,
		Logger:     logger,
		Recorder:   sess,
		ClientIP:   adaptiveSessionKeyLoopback,
		RequestID:  "req-intercept-scope",
	}
	interceptRecordSignal(ic, session.SignalBlock)
	interceptRecordSignal(ic, session.SignalBlock)

	if got := interceptEscalationLevel(ic); got != 1 {
		t.Fatalf("poll intercept level = %d, want 1", got)
	}
	ic.TargetHost = adaptiveScopeSendHost
	if got := interceptEscalationLevel(ic); got != 0 {
		t.Fatalf("unrelated intercept level = %d, want 0", got)
	}

	sess.mu.Lock()
	authoritative := sess.globalSignalsAuthoritative
	sess.mu.Unlock()
	if authoritative {
		t.Fatal("intercept scoped signal should not make the aggregate lane authoritative")
	}
}

func TestAdaptiveScope_ScopedSnapshotsExposeAirlockState(t *testing.T) {
	cfg := adaptiveScopedAirlockConfig()
	p, logger := newAdaptiveScopeProxy(t, cfg)
	sess := scopedSession(t, p)

	recordPollThreat(p, logger, cfg, "req-threat-1")
	recordPollThreat(p, logger, cfg, "req-threat-2")

	snaps := sess.ScopedSnapshots()
	if len(snaps) != 1 {
		t.Fatalf("scoped snapshots = %d, want 1", len(snaps))
	}
	if snaps[0].Scope != adaptiveScopeForHost(adaptiveScopePollHost) {
		t.Fatalf("scope = %q, want %q", snaps[0].Scope, adaptiveScopeForHost(adaptiveScopePollHost))
	}
	if snaps[0].AirlockTier != config.AirlockTierHard {
		t.Fatalf("airlock tier = %q, want hard", snaps[0].AirlockTier)
	}
	if snaps[0].EscalationLevel != session.EscalationLabel(1) {
		t.Fatalf("escalation level = %q, want elevated", snaps[0].EscalationLevel)
	}
}
