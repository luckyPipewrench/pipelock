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
	m := session.BaselineMetrics{ToolCalls: 1, UniqueTools: 1, Requests: 1}

	t.Run("disabled no-op", func(t *testing.T) {
		sm := newBaselineMetricsGuardSessionManager(t, nil)

		if d := sm.CheckBaselineForMetrics("agent-x", m); d.Action != "" || d.Blocked {
			t.Fatalf("disabled CheckBaselineForMetrics = %+v, want empty", d)
		}
		sm.RecordBaselineMetrics("agent-x", m)
	})

	t.Run("empty and invalid keys do not record", func(t *testing.T) {
		sm := newBaselineMetricsGuardSessionManager(t, baselineMetricsGuardConfig(t))

		sm.RecordBaselineMetrics("", m)
		sm.RecordBaselineMetrics("bad/../key", m)
		if agents := sm.BaselineManager().ListAgents(); len(agents) != 0 {
			t.Fatalf("guarded records created agent(s): %v", agents)
		}
	})

	t.Run("invalid key check fails closed", func(t *testing.T) {
		sm := newBaselineMetricsGuardSessionManager(t, baselineMetricsGuardConfig(t))

		if d := sm.CheckBaselineForMetrics("bad/../key", m); !d.Blocked || d.Action != config.ActionBlock {
			t.Fatalf("invalid-key check should fail closed, got %+v", d)
		}
	})

	t.Run("valid key still learning allows", func(t *testing.T) {
		sm := newBaselineMetricsGuardSessionManager(t, baselineMetricsGuardConfig(t))

		if d := sm.CheckBaselineForMetrics("agent-x", m); d.Blocked {
			t.Fatalf("still-learning check should not block, got %+v", d)
		}
	})
}

func newBaselineMetricsGuardSessionManager(t *testing.T, bcfg *config.BehavioralBaseline) *SessionManager {
	t.Helper()

	cfg := config.Defaults()
	cfg.Internal = nil
	sm := NewSessionManager(&cfg.SessionProfiling, nil, metrics.New())
	t.Cleanup(sm.Close)
	if bcfg != nil {
		if err := sm.EnableBaseline(bcfg); err != nil {
			t.Fatalf("EnableBaseline: %v", err)
		}
	}
	return sm
}

func baselineMetricsGuardConfig(t *testing.T) *config.BehavioralBaseline {
	t.Helper()

	return &config.BehavioralBaseline{
		Enabled:          true,
		LearningWindow:   2,
		DeviationAction:  config.ActionBlock,
		ProfileDir:       t.TempDir(),
		SensitivitySigma: 2.0,
		SeasonalityMode:  config.SeasonalityModeNone,
	}
}
