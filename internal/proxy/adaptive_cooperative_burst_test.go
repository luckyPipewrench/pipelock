// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIsCooperativeToolBurstUserAgent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ua   string
		want bool
	}{
		{"yt-dlp/2026.3.17", true},
		{"python-requests/2.32.0", true},
		{"pip/26.0", true},
		{"npm/11.0.0", true},
		{"pnpm/10.0.0", true},
		{"apt/2.7.0", true},
		{"dnf/5.2.0", true},
		{"curl/8.7.1", true},
		{"git/2.45.0", true},
		{"Mozilla/5.0", false},
		{"evil yt-dlp/2026.3.17", false},
	}
	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			t.Parallel()
			if got := isCooperativeToolBurstUserAgent(tt.ua); got != tt.want {
				t.Errorf("isCooperativeToolBurstUserAgent(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}

func TestAdaptiveCooperativeToolBurstDownweightsDomainAnomalies(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	clientIP := adaptiveSessionKeyLoopback
	hosts := []string{
		"www.youtube.com",
		"youtubei.googleapis.com",
		"i.ytimg.com",
		"rr1---sn.googlevideo.com",
	}

	for i, host := range hosts {
		p.recordSessionActivityWithUserAgent(clientIP, agentAnonymous, host, "req-coop", "yt-dlp/2026.3.17", scanner.Result{Allowed: true}, cfg, logger, true)
		if i < len(hosts)-1 && p.sessionMgrPtr.Load().GetOrCreate(clientIP).EscalationLevel() > 0 {
			t.Fatalf("cooperative burst escalated early at host %s", host)
		}
	}

	rec := p.sessionMgrPtr.Load().GetOrCreate(clientIP)
	if rec.EscalationLevel() != 0 {
		t.Fatalf("cooperative burst escalated to level %d with score %.2f", rec.EscalationLevel(), rec.ThreatScore())
	}
	if rec.ThreatScore() >= cfg.AdaptiveEnforcement.EscalationThreshold {
		t.Fatalf("cooperative burst score %.2f crossed threshold %.2f", rec.ThreatScore(), cfg.AdaptiveEnforcement.EscalationThreshold)
	}
}

func TestAdaptiveNonCooperativeBurstStillEscalates(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	clientIP := adaptiveSessionKeyLoopback

	p.recordSessionActivityWithUserAgent(clientIP, agentAnonymous, "www.youtube.com", "req-1", "Mozilla/5.0", scanner.Result{Allowed: true}, cfg, logger, true)
	p.recordSessionActivityWithUserAgent(clientIP, agentAnonymous, "youtubei.googleapis.com", "req-2", "Mozilla/5.0", scanner.Result{Allowed: true}, cfg, logger, true)

	rec := p.sessionMgrPtr.Load().GetOrCreate(clientIP)
	if rec.EscalationLevel() == 0 {
		t.Fatalf("non-cooperative burst did not escalate; score %.2f threshold %.2f", rec.ThreatScore(), cfg.AdaptiveEnforcement.EscalationThreshold)
	}
}

func TestAdaptiveCooperativeDownweightCanBeDisabled(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	cfg.AdaptiveEnforcement.CooperativeToolDownweight = false
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	clientIP := adaptiveSessionKeyLoopback

	p.recordSessionActivityWithUserAgent(clientIP, agentAnonymous, "www.youtube.com", "req-1", "yt-dlp/2026.3.17", scanner.Result{Allowed: true}, cfg, logger, true)
	p.recordSessionActivityWithUserAgent(clientIP, agentAnonymous, "youtubei.googleapis.com", "req-2", "yt-dlp/2026.3.17", scanner.Result{Allowed: true}, cfg, logger, true)

	rec := p.sessionMgrPtr.Load().GetOrCreate(clientIP)
	if rec.EscalationLevel() == 0 {
		t.Fatalf("disabled cooperative downweight did not preserve full burst scoring; score %.2f", rec.ThreatScore())
	}
}

func TestAdaptiveExemptDomainBurstDoesNotScore(t *testing.T) {
	t.Parallel()
	cfg := cooperativeBurstTestConfig()
	cfg.AdaptiveEnforcement.ExemptDomains = []string{"www.youtube.com", "youtubei.googleapis.com"}
	p := newTestProxyWithConfig(t, cfg)
	logger := audit.NewNop()
	clientIP := adaptiveSessionKeyLoopback

	p.recordSessionActivityWithUserAgent(clientIP, agentAnonymous, "www.youtube.com", "req-1", "Mozilla/5.0", scanner.Result{Allowed: true}, cfg, logger, true)
	p.recordSessionActivityWithUserAgent(clientIP, agentAnonymous, "youtubei.googleapis.com", "req-2", "Mozilla/5.0", scanner.Result{Allowed: true}, cfg, logger, true)

	rec := p.sessionMgrPtr.Load().GetOrCreate(clientIP)
	if rec.ThreatScore() != 0 {
		t.Fatalf("adaptive-exempt burst scored %.2f, want 0", rec.ThreatScore())
	}
	if rec.EscalationLevel() != 0 {
		t.Fatalf("adaptive-exempt burst escalated to level %d", rec.EscalationLevel())
	}
}

func cooperativeBurstTestConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.AnomalyAction = config.ActionWarn
	cfg.SessionProfiling.DomainBurst = 2
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.MaxSessions = 100
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 60
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 5.0
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.5
	cfg.AdaptiveEnforcement.CooperativeToolDownweight = true
	cfg.ApplyDefaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return cfg
}
