// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const boundBurstAgent = "pi"

// cooperativeBurstScore is the per-session threat score a cooperative-tool
// caller accrues from crossing its own domain-burst threshold once in a window.
// It is the signal that distinguishes a caller whose own session was counted
// from one that had the shared IP counter leak other callers' domains into it.
const cooperativeBurstScore = 0.4

func TestAdaptiveBoundIdentityDoesNotEscalateOnHostBurst(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	hosts := []string{"a.example", "b.example", "c.example"}

	for _, host := range hosts {
		p.recordSessionActivityWithUserAgent(boundBurstOpts(host, envelope.ActorAuthBound, boundBurstAgent, cfg, logger))
	}

	rec := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(boundBurstAgent, adaptiveSessionKeyLoopback))
	if rec.EscalationLevel() != 0 {
		t.Fatalf("bound burst escalated to level %d with score %.2f", rec.EscalationLevel(), rec.ThreatScore())
	}
	if rec.ThreatScore() >= cfg.AdaptiveEnforcement.EscalationThreshold {
		t.Fatalf("bound burst score %.2f crossed threshold %.2f", rec.ThreatScore(), cfg.AdaptiveEnforcement.EscalationThreshold)
	}
	if rec.ThreatScore() != cooperativeBurstScore {
		t.Fatalf("bound burst score %.2f, want cooperative %.2f", rec.ThreatScore(), cooperativeBurstScore)
	}
}

func TestAdaptiveConfigDefaultIdentityDoesNotEscalateOnHostBurst(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	hosts := []string{"a.example", "b.example", "c.example"}

	for _, host := range hosts {
		p.recordSessionActivityWithUserAgent(boundBurstOpts(host, envelope.ActorAuthConfigDefault, boundBurstAgent, cfg, logger))
	}

	rec := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(boundBurstAgent, adaptiveSessionKeyLoopback))
	if rec.EscalationLevel() != 0 {
		t.Fatalf("config-default burst escalated to level %d with score %.2f", rec.EscalationLevel(), rec.ThreatScore())
	}
}

func TestAdaptiveSelfDeclaredStillTripsIPBurst(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()

	p.recordSessionActivityWithUserAgent(boundBurstOpts("a.example", envelope.ActorAuthSelfDeclared, agentAnonymous, cfg, logger))
	p.recordSessionActivityWithUserAgent(boundBurstOpts("b.example", envelope.ActorAuthSelfDeclared, agentAnonymous, cfg, logger))

	rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	if rec.EscalationLevel() == 0 {
		t.Fatalf("self-declared burst did not escalate; score %.2f threshold %.2f", rec.ThreatScore(), cfg.AdaptiveEnforcement.EscalationThreshold)
	}
}

func TestAdaptiveMatchedStillTripsIPBurst(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()

	p.recordSessionActivityWithUserAgent(boundBurstOpts("a.example", envelope.ActorAuthMatched, boundBurstAgent, cfg, logger))
	p.recordSessionActivityWithUserAgent(boundBurstOpts("b.example", envelope.ActorAuthMatched, boundBurstAgent, cfg, logger))

	rec := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(boundBurstAgent, adaptiveSessionKeyLoopback))
	if rec.EscalationLevel() == 0 {
		t.Fatalf("matched burst did not escalate; score %.2f", rec.ThreatScore())
	}
}

func TestAdaptiveUnknownAuthFromWrapperStillTripsIPBurst(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()

	p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "a.example", "req-1", scannerResultAllow(), cfg, logger, true)
	p.recordSessionActivity(adaptiveSessionKeyLoopback, agentAnonymous, "b.example", "req-2", scannerResultAllow(), cfg, logger, true)

	rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	if rec.EscalationLevel() == 0 {
		t.Fatalf("empty ActorAuth wrapper path did not escalate; score %.2f", rec.ThreatScore())
	}
}

func TestAdaptiveBoundBurstDoesNotPoisonCoLocatedSelfDeclared(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	hosts := []string{"a.example", "b.example", "c.example"}

	for _, host := range hosts {
		p.recordSessionActivityWithUserAgent(boundBurstOpts(host, envelope.ActorAuthBound, boundBurstAgent, cfg, logger))
	}

	p.recordSessionActivityWithUserAgent(boundBurstOpts("d.example", envelope.ActorAuthSelfDeclared, agentAnonymous, cfg, logger))

	rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
	if rec.EscalationLevel() != 0 {
		t.Fatalf("self-declared inherited IP-burst from bound traffic; level %d score %.2f", rec.EscalationLevel(), rec.ThreatScore())
	}
	if rec.ThreatScore() != 0 {
		t.Fatalf("self-declared scored %.2f from one fresh host after bound burst", rec.ThreatScore())
	}
}

// TestAdaptiveDistinctBoundAgentsOnOneIPDoNotMerge covers several distinct
// infrastructure-bound callers sharing one client IP: each stays in its own
// per-session bucket and none inherits the others' domain activity through a
// shared IP-level counter, so co-located bound agents each below the burst
// threshold do not false-positive as one bursting agent.
func TestAdaptiveDistinctBoundAgentsOnOneIPDoNotMerge(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()

	// Two distinct bound identities on the same IP, each touching two hosts -
	// below the burst threshold individually, but four domains combined.
	agents := []string{"alpha", "beta"}
	hostsFor := map[string][]string{
		"alpha": {"a.example", "b.example"},
		"beta":  {"c.example", "d.example"},
	}
	for _, agent := range agents {
		for _, host := range hostsFor[agent] {
			p.recordSessionActivityWithUserAgent(boundBurstOpts(host, envelope.ActorAuthBound, agent, cfg, logger))
		}
	}

	sm := p.sessionMgrPtr.Load()
	for _, agent := range agents {
		rec := sm.GetOrCreate(sessionKeyFor(agent, adaptiveSessionKeyLoopback))
		if rec.EscalationLevel() != 0 {
			t.Fatalf("bound agent %q escalated to level %d with score %.2f", agent, rec.EscalationLevel(), rec.ThreatScore())
		}
		// Each agent crosses only its OWN per-session domain burst (2 hosts >=
		// DomainBurst), cooperatively downweighted to 0.4. If the bound-identity
		// skip at the call site were removed, the shared IP-level counter would
		// pool both agents' four domains and add an ip_domain_burst contribution
		// to at least one agent's score. Exact-match so that regression fails
		// here rather than passing silently below the escalation threshold.
		if rec.ThreatScore() != cooperativeBurstScore {
			t.Fatalf("bound agent %q score %.2f, want cooperative per-session %.2f (shared IP counter leaked in?)",
				agent, rec.ThreatScore(), cooperativeBurstScore)
		}
	}
}

func boundBurstOpts(host string, auth envelope.ActorAuth, agent string, cfg *config.Config, logger *audit.Logger) sessionActivityOptions {
	return sessionActivityOptions{
		ClientIP:   adaptiveSessionKeyLoopback,
		Agent:      agent,
		Hostname:   host,
		RequestID:  "req-" + host,
		UserAgent:  cooperativeUAMozilla,
		ActorAuth:  auth,
		Result:     scannerResultAllow(),
		Config:     cfg,
		Logger:     logger,
		DeferClean: true,
	}
}

func scannerResultAllow() scanner.Result {
	return scanner.Result{Allowed: true}
}
