// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// nonSessionRecorder is a session.Recorder that is NOT a *SessionState, to
// exercise the type-assertion guard in RecordBaselineForRecorder.
type nonSessionRecorder struct{}

func (nonSessionRecorder) RecordSignal(session.SignalType, float64) (bool, string, string) {
	return false, "", ""
}
func (nonSessionRecorder) RecordClean(float64)  {}
func (nonSessionRecorder) EscalationLevel() int { return 0 }
func (nonSessionRecorder) ThreatScore() float64 { return 0 }

// TestBaselineWiringGuards exercises the fail-safe guard and lifecycle branches
// of the MCP baseline wiring: safe no-ops when disabled / invalid key / wrong
// recorder type, and the reconfigure disable + re-enable paths.
func TestBaselineWiringGuards(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sm := NewSessionManager(&cfg.SessionProfiling, nil, metrics.New())
	t.Cleanup(sm.Close)

	sess := sm.GetOrCreate("baseline-guard-session")

	// Baseline disabled: record + check are safe no-ops (nil snapshot).
	sm.RecordBaselineForAgent("agent-x", sess)
	if r := sm.CheckBaseline("agent-x", sess); r != nil {
		t.Fatalf("disabled baseline CheckBaseline = %+v, want nil", r)
	}

	bcfg := &config.BehavioralBaseline{
		Enabled: true, LearningWindow: 2, DeviationAction: config.ActionBlock,
		ProfileDir: t.TempDir(), SensitivitySigma: 2.0, SeasonalityMode: config.SeasonalityModeNone,
	}
	if err := sm.EnableBaseline(bcfg); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}

	// Invalid / empty identity key and nil session are no-ops (never panic, never record).
	sm.RecordBaselineForAgent("bad/../key", sess)
	sm.RecordBaselineForAgent("", sess)
	sm.RecordBaselineForAgent("agent-x", nil)
	if agents := sm.BaselineManager().ListAgents(); len(agents) != 0 {
		t.Fatalf("guarded records created agent(s): %v", agents)
	}

	// A recorder that is not a *SessionState is ignored.
	sm.RecordBaselineForRecorder("agent-x", nonSessionRecorder{})
	if agents := sm.BaselineManager().ListAgents(); len(agents) != 0 {
		t.Fatalf("non-SessionState recorder created agent(s): %v", agents)
	}

	// Reconfigure disable drops the manager.
	if err := sm.ReconfigureBaseline(&config.BehavioralBaseline{Enabled: false}); err != nil {
		t.Fatalf("ReconfigureBaseline disable: %v", err)
	}
	if sm.BaselineManager() != nil {
		t.Fatal("disable reconfigure should drop the baseline manager")
	}

	// Reconfigure from no-manager state re-enables (EnableBaseline fallback), warn action.
	if err := sm.ReconfigureBaseline(&config.BehavioralBaseline{
		Enabled: true, LearningWindow: 2, DeviationAction: config.ActionWarn,
		ProfileDir: t.TempDir(), SensitivitySigma: 2.0, SeasonalityMode: config.SeasonalityModeNone,
	}); err != nil {
		t.Fatalf("ReconfigureBaseline re-enable: %v", err)
	}
	if sm.BaselineManager() == nil {
		t.Fatal("re-enable reconfigure should create the baseline manager")
	}

	// In-place reconfigure (manager present) with ask action: snapshot swap + baselineActionOrDefault(ask).
	if err := sm.ReconfigureBaseline(&config.BehavioralBaseline{
		Enabled: true, LearningWindow: 3, DeviationAction: config.ActionAsk,
		ProfileDir: t.TempDir(), SensitivitySigma: 2.0, SeasonalityMode: config.SeasonalityModeNone,
	}); err != nil {
		t.Fatalf("ReconfigureBaseline in-place: %v", err)
	}

	// Empty deviation action exercises baselineActionOrDefault's default branch.
	if err := sm.ReconfigureBaseline(&config.BehavioralBaseline{
		Enabled: true, LearningWindow: 3, DeviationAction: "",
		ProfileDir: t.TempDir(), SensitivitySigma: 2.0, SeasonalityMode: config.SeasonalityModeNone,
	}); err != nil {
		t.Fatalf("ReconfigureBaseline empty-action: %v", err)
	}
}
