// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// newAdaptiveWSRelay builds a wsRelay wired to a session escalated to the given
// level, with adaptive enforcement on and enforce=false (audit mode). In audit
// mode a warn-action finding is not hard-blocked, so the relay reaches the
// adaptive-upgrade branch where escalation flips warn -> block. Returns the
// relay plus its session manager and metrics for assertions.
func newAdaptiveWSRelay(t *testing.T, level int) (*wsRelay, *metrics.Metrics) {
	t.Helper()
	cfg := adaptiveConfig() // enforce=false, adaptive on, profiling on
	m := metrics.New()
	p := &Proxy{logger: audit.NewNop(), metrics: m}

	smCfg := &config.SessionProfiling{
		Enabled:                true,
		MaxSessions:            100,
		DomainBurst:            100,
		WindowMinutes:          5,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 600,
	}
	sm := NewSessionManager(smCfg, nil, m)
	t.Cleanup(sm.Close)
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)
	escalateRec(rec, level)

	relay := &wsRelay{
		clientConn:   discardConn{},
		upstreamConn: discardConn{},
		proxy:        p,
		cfg:          cfg,
		rec:          rec,
		agent:        agentAnonymous,
		clientIP:     adaptiveSessionKeyLoopback,
		requestID:    "req-adaptive",
		targetURL:    "ws://example.com/socket",
	}
	return relay, m
}

// adaptiveUpgradeTotal sums the pipelock_adaptive_upgrades_total counter across
// all label sets in the registry. Used to confirm an adaptive upgrade fired
// without depending on the exact from/to/level labels.
func adaptiveUpgradeTotal(t *testing.T, m *metrics.Metrics) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, fam := range families {
		if fam.GetName() != "pipelock_adaptive_upgrades_total" {
			continue
		}
		for _, mm := range fam.GetMetric() {
			total += mm.GetCounter().GetValue()
		}
	}
	return total
}

// TestWSRelay_HandleClientTextFindings_DLPAdaptiveUpgrade drives the relay DLP
// warn->block adaptive-upgrade branch: a non-critical DLP match in audit mode
// is upgraded to block because the session is escalated.
func TestWSRelay_HandleClientTextFindings_DLPAdaptiveUpgrade(t *testing.T) {
	relay, m := newAdaptiveWSRelay(t, 2)

	blocked := relay.handleClientTextFindings(audit.NewNop(), []scanner.TextDLPMatch{{
		PatternName: "Generic Secret",
		Severity:    config.SeverityMedium,
	}}, nil)

	if !blocked {
		t.Fatal("expected escalated DLP finding to block in audit mode")
	}
	if got := adaptiveUpgradeTotal(t, m); got != 1 {
		t.Errorf("adaptive upgrade count = %v, want 1", got)
	}
}

// TestWSRelay_HandleClientTextFindings_AddressAdaptiveUpgrade drives the relay
// address-protection warn->block adaptive-upgrade branch.
func TestWSRelay_HandleClientTextFindings_AddressAdaptiveUpgrade(t *testing.T) {
	relay, m := newAdaptiveWSRelay(t, 2)

	blocked := relay.handleClientTextFindings(audit.NewNop(), nil, []addressprotect.Finding{{
		Hit: addressprotect.Hit{
			Chain:      "eth",
			Normalized: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
		},
		Verdict:     addressprotect.VerdictLookalike,
		Action:      config.ActionWarn,
		MatchedAddr: "0x742d35...38f44e",
		Explanation: "lookalike payout address",
	}})

	if !blocked {
		t.Fatal("expected escalated address finding to block in audit mode")
	}
	if got := adaptiveUpgradeTotal(t, m); got != 1 {
		t.Errorf("adaptive upgrade count = %v, want 1", got)
	}
}

// TestWSRelay_HandleClientMessageBodyResult_AdaptiveUpgrade drives the relay
// request-body warn->block adaptive-upgrade branch.
func TestWSRelay_HandleClientMessageBodyResult_AdaptiveUpgrade(t *testing.T) {
	relay, m := newAdaptiveWSRelay(t, 2)

	blocked := relay.handleClientMessageBodyResult(audit.NewNop(), []byte(`{"prompt":"flagged"}`), BodyScanResult{
		Clean:  false,
		Action: config.ActionWarn,
		Reason: "body finding",
		DLPMatches: []scanner.TextDLPMatch{{
			PatternName: "Generic Secret",
			Severity:    config.SeverityMedium,
		}},
	})

	if !blocked {
		t.Fatal("expected escalated body finding to block in audit mode")
	}
	if got := adaptiveUpgradeTotal(t, m); got != 1 {
		t.Errorf("adaptive upgrade count = %v, want 1", got)
	}
}
