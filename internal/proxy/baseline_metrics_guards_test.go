// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestBaselineMetricsGuards covers the metric-native baseline entry points:
// safe no-ops when disabled / empty / invalid key, still-learning allow, and
// fail-closed block on an invalid key while enabled.
func TestBaselineMetricsGuards(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sm := NewSessionManager(&cfg.SessionProfiling, nil, metrics.New())
	t.Cleanup(sm.Close)

	m := session.BaselineMetrics{ToolCalls: 1, UniqueTools: 1, Requests: 1}

	// Disabled: check returns an empty decision; record is a no-op.
	if d := sm.CheckBaselineForMetrics("agent-x", m); d.Action != "" || d.Blocked {
		t.Fatalf("disabled CheckBaselineForMetrics = %+v, want empty", d)
	}
	sm.RecordBaselineMetrics("agent-x", m)

	bcfg := &config.BehavioralBaseline{
		Enabled: true, LearningWindow: 2, DeviationAction: config.ActionBlock,
		ProfileDir: t.TempDir(), SensitivitySigma: 2.0, SeasonalityMode: config.SeasonalityModeNone,
	}
	if err := sm.EnableBaseline(bcfg); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}

	// Empty and invalid keys must not record.
	sm.RecordBaselineMetrics("", m)
	sm.RecordBaselineMetrics("bad/../key", m)
	if agents := sm.BaselineManager().ListAgents(); len(agents) != 0 {
		t.Fatalf("guarded records created agent(s): %v", agents)
	}

	// Invalid key on the enabled check path fails closed (block), not allow.
	if d := sm.CheckBaselineForMetrics("bad/../key", m); !d.Blocked {
		t.Fatalf("invalid-key check should fail closed, got %+v", d)
	}

	// Valid key with no locked profile yet is still-learning: allow (no block).
	if d := sm.CheckBaselineForMetrics("agent-x", m); d.Blocked {
		t.Fatalf("still-learning check should not block, got %+v", d)
	}
}
