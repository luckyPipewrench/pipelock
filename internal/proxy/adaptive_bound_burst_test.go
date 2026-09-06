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
	if rec.ThreatScore() != 0.4 {
		t.Fatalf("bound burst score %.2f, want cooperative 0.4", rec.ThreatScore())
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
