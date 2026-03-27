// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

const testAgent = "agent-1"

func normalMetrics() SessionMetrics {
	return SessionMetrics{
		ToolCalls:   4,
		UniqueTools: 2,
		Domains:     5,
		BytesTotal:  1000,
		DurationSec: 60,
		Requests:    10,
	}
}

func TestNewManager_Defaults(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if mgr.cfg.LearningWindow != 10 {
		t.Errorf("expected default LearningWindow=10, got %d", mgr.cfg.LearningWindow)
	}
	if mgr.cfg.SensitivitySigma != 2.0 {
		t.Errorf("expected default SensitivitySigma=2.0, got %f", mgr.cfg.SensitivitySigma)
	}
	if mgr.cfg.DeviationAction != "warn" {
		t.Errorf("expected default DeviationAction=warn, got %s", mgr.cfg.DeviationAction)
	}
	if mgr.cfg.SeasonalityMode != "none" {
		t.Errorf("expected default SeasonalityMode=none, got %s", mgr.cfg.SeasonalityMode)
	}
}

func TestBaseline_Learning(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Record 3 sessions with slightly varying tool calls.
	for i := range 3 {
		mgr.RecordSession(testAgent, SessionMetrics{
			ToolCalls: 3 + i, UniqueTools: 2, Domains: 5,
			BytesTotal: 1000, DurationSec: 60, Requests: 10,
		})
	}

	// Profile should be available but not ratified.
	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile after learning window")
	}
	if profile.Ratified {
		t.Error("profile should not be ratified yet")
	}
	if profile.SessionCount != 3 {
		t.Errorf("expected session count 3, got %d", profile.SessionCount)
	}

	// Mean of [3,4,5] = 4.0.
	if math.Abs(profile.Metrics.ToolCallsPerSession.Mean-4.0) > 0.1 {
		t.Errorf("expected mean ~4.0, got %f", profile.Metrics.ToolCallsPerSession.Mean)
	}
}

func TestBaseline_StateTransitions(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Initial state should be observe (no agent yet).
	if state := mgr.GetState(testAgent); state != StateObserve {
		t.Errorf("expected %q, got %q", StateObserve, state)
	}

	// Record 2 sessions: still in observe.
	for range 2 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if state := mgr.GetState(testAgent); state != StateObserve {
		t.Errorf("expected %q after 2 sessions, got %q", StateObserve, state)
	}

	// Record 3rd session: transitions to ratify (observe->learn->ratify).
	mgr.RecordSession(testAgent, normalMetrics())
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Errorf("expected %q after learning window, got %q", StateRatify, state)
	}

	// Ratify: transitions to locked.
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Errorf("expected %q after ratification, got %q", StateLocked, state)
	}

	// Profile should now be ratified.
	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("profile should not be nil after ratification")
	}
	if !profile.Ratified {
		t.Error("profile should be ratified")
	}
	if profile.RatifiedAt == nil {
		t.Error("ratified_at should be set")
	}
}

func TestBaseline_DeviationDetection(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		SensitivitySigma: 2.0,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Learn normal behavior (identical sessions = zero stddev).
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Normal session = no deviations.
	devs := mgr.Check(testAgent, normalMetrics())
	if len(devs) != 0 {
		t.Errorf("expected no deviations for normal session, got %d", len(devs))
	}

	// Anomalous session = deviations.
	anomalous := SessionMetrics{
		ToolCalls: 47, UniqueTools: 15, Domains: 50,
		BytesTotal: 100000, DurationSec: 60, Requests: 10,
	}
	devs = mgr.Check(testAgent, anomalous)
	if len(devs) == 0 {
		t.Error("expected deviations for anomalous session")
	}

	// Check explainability.
	for _, d := range devs {
		if d.Metric == "" {
			t.Error("deviation metric should not be empty")
		}
		if d.Severity == "" {
			t.Error("deviation severity should not be empty")
		}
		if d.Delta <= 0 {
			t.Errorf("deviation delta should be positive, got %f", d.Delta)
		}
	}
}

func TestBaseline_UnratifiedNoEnforcement(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// State is ratify but NOT locked. Check should return nil.
	devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 999})
	if len(devs) != 0 {
		t.Errorf("expected no deviations before ratification, got %d", len(devs))
	}
}

func TestBaseline_UnknownAgentCheck(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	devs := mgr.Check("nonexistent", normalMetrics())
	if devs != nil {
		t.Error("expected nil for unknown agent")
	}
}

func TestBaseline_Ratify_WrongState(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Try to ratify before learning.
	mgr.RecordSession(testAgent, normalMetrics())
	err = mgr.Ratify(testAgent)
	if err == nil {
		t.Error("expected error ratifying in observe state")
	}
}

func TestBaseline_Ratify_NotFound(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	err = mgr.Ratify("nonexistent")
	if err == nil {
		t.Error("expected error ratifying nonexistent agent")
	}
}

func TestBaseline_Reset(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("expected locked, got %q", state)
	}

	// Reset back to observe.
	if err := mgr.Reset(testAgent); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateObserve {
		t.Errorf("expected observe after reset, got %q", state)
	}
	if profile := mgr.GetProfile(testAgent); profile != nil {
		t.Error("profile should be nil after reset")
	}
}

func TestBaseline_Reset_NotFound(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	err = mgr.Reset("nonexistent")
	if err == nil {
		t.Error("expected error resetting nonexistent agent")
	}
}

func TestBaseline_PoisonResistance(t *testing.T) {
	// Use 10 normal sessions + 1 outlier. With enough normal data,
	// the outlier's z-score exceeds 3 sigma and gets trimmed.
	cfg := Config{
		Enabled: true, LearningWindow: 11, ProfileDir: t.TempDir(),
		PoisonResistance: true,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// 10 normal sessions with slight variation.
	for i := range 10 {
		mgr.RecordSession(testAgent, SessionMetrics{
			ToolCalls: 3 + (i % 3), UniqueTools: 2, Domains: 5,
			BytesTotal: 1000, DurationSec: 60, Requests: 10,
		})
	}
	// Poison session: extremely high tool calls.
	mgr.RecordSession(testAgent, SessionMetrics{
		ToolCalls: 100000, UniqueTools: 2, Domains: 5,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile after learning")
	}

	// The poison session should be trimmed. Mean should be close to 4 (normal).
	if profile.Metrics.ToolCallsPerSession.Mean > 10 {
		t.Errorf("poison session should be trimmed; mean=%f (expected ~4)", profile.Metrics.ToolCallsPerSession.Mean)
	}
}

func TestBaseline_PoisonResistance_AllOutliers(t *testing.T) {
	// If all sessions are outliers, use original data to avoid empty profile.
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		PoisonResistance: true,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// 3 identical sessions: zero stddev means nothing is an outlier.
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile")
	}
	if profile.SessionCount != 3 {
		t.Errorf("expected 3 sessions, got %d", profile.SessionCount)
	}
}

func TestBaseline_NoPoisonResistance(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 5, ProfileDir: t.TempDir(),
		PoisonResistance: false,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 4 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	mgr.RecordSession(testAgent, SessionMetrics{
		ToolCalls: 10000, UniqueTools: 2, Domains: 5,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile")
	}

	// Without poison resistance, the outlier inflates the mean.
	if profile.Metrics.ToolCallsPerSession.Mean < 100 {
		t.Errorf("without poison resistance, mean should be high; got %f", profile.Metrics.ToolCallsPerSession.Mean)
	}
}

func TestBaseline_LockDimensions(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		SensitivitySigma: 2.0,
		LockDimensions:   []string{"tool_calls"},
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Anomalous domains but only tool_calls is enforced.
	devs := mgr.Check(testAgent, SessionMetrics{
		ToolCalls: 4, UniqueTools: 2, Domains: 999,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})
	if len(devs) != 0 {
		t.Errorf("expected no deviations (domains not enforced), got %d: %v", len(devs), devs)
	}

	// Anomalous tool_calls IS enforced.
	devs = mgr.Check(testAgent, SessionMetrics{
		ToolCalls: 999, UniqueTools: 2, Domains: 5,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})
	if len(devs) == 0 {
		t.Error("expected deviation for anomalous tool_calls")
	}
}

func TestBaseline_AutoRatify(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		AutoRatify: true,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// Auto-ratify should skip StateRatify and go straight to locked.
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Errorf("expected %q with auto-ratify, got %q", StateLocked, state)
	}

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile with auto-ratify")
	}
	if !profile.Ratified {
		t.Error("profile should be auto-ratified")
	}
}

func TestBaseline_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Create and learn a profile.
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Verify file exists.
	profilePath := filepath.Join(dir, testAgent+profileFileExt)
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("profile file should exist: %v", err)
	}

	// Load a new manager and verify profile is restored.
	mgr2, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager (reload): %v", err)
	}

	profile := mgr2.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("profile should be loaded from disk")
	}
	if !profile.Ratified {
		t.Error("loaded profile should be ratified")
	}
	if profile.State != StateLocked {
		t.Errorf("loaded profile state should be %q, got %q", StateLocked, profile.State)
	}
}

func TestBaseline_Persistence_NoDir(t *testing.T) {
	// ProfileDir empty = no persistence (in-memory only).
	cfg := Config{Enabled: true, LearningWindow: 3}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// Should work fine without persistence.
	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile (in-memory)")
	}
}

func TestBaseline_Persistence_NonexistentDir(t *testing.T) {
	// ProfileDir set but doesn't exist = load returns no error (empty).
	cfg := Config{Enabled: true, ProfileDir: filepath.Join(t.TempDir(), "nonexistent")}
	_, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager should succeed with nonexistent dir: %v", err)
	}
}

func TestBaseline_ListAgents(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	mgr.RecordSession("agent-b", normalMetrics())
	mgr.RecordSession("agent-a", normalMetrics())

	agents := mgr.ListAgents()
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
	// Should be sorted.
	if agents[0] != "agent-a" || agents[1] != "agent-b" {
		t.Errorf("expected sorted list [agent-a, agent-b], got %v", agents)
	}
}

func TestBaseline_RecordSession_InLockedState(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Recording in locked state should be a no-op.
	mgr.RecordSession(testAgent, SessionMetrics{ToolCalls: 999})

	profile := mgr.GetProfile(testAgent)
	if profile.SessionCount != 3 {
		t.Errorf("session count should still be 3, got %d", profile.SessionCount)
	}
}

func TestBaseline_RecordSession_InRatifyState(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// State is ratify. Recording should be a no-op.
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Fatalf("expected ratify, got %q", state)
	}

	mgr.RecordSession(testAgent, SessionMetrics{ToolCalls: 999})

	profile := mgr.GetProfile(testAgent)
	if profile.SessionCount != 3 {
		t.Errorf("session count should still be 3, got %d", profile.SessionCount)
	}
}

func TestBaseline_DeviationSeverity(t *testing.T) {
	// Test severity levels based on sigma distance.
	tests := []struct {
		name     string
		baseline Range
		observed float64
		sigma    float64
		wantSev  string
	}{
		{
			name:     "low severity (just outside threshold, under 2 sigma from mean)",
			baseline: Range{Min: 0, Max: 10, Mean: 5, StdDev: 2},
			observed: 8.5, // 1.75 sigma from mean, but sensitivity=1.0, so distance>1.0 triggers.
			sigma:    1.0, // Trigger threshold: 1 sigma. Distance: 1.75. Under 2 sigma = low.
			wantSev:  severityLow,
		},
		{
			name:     "medium severity (between 2 and 3 sigma from mean)",
			baseline: Range{Min: 0, Max: 10, Mean: 5, StdDev: 1},
			observed: 7.5, // 2.5 sigma from mean.
			sigma:    1.0, // Trigger threshold: 1 sigma.
			wantSev:  severityMedium,
		},
		{
			name:     "high severity (beyond 3 sigma from mean)",
			baseline: Range{Min: 0, Max: 10, Mean: 5, StdDev: 1},
			observed: 9, // 4.0 sigma from mean.
			sigma:    1.0,
			wantSev:  severityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := checkDeviation("test_metric", tt.baseline, tt.observed, tt.sigma)
			if dev == nil {
				t.Fatal("expected deviation")
			}
			if dev.Severity != tt.wantSev {
				distance := math.Abs(tt.observed-tt.baseline.Mean) / tt.baseline.StdDev
				t.Errorf("severity=%q (want %q), distance=%.2f sigma", dev.Severity, tt.wantSev, distance)
			}
		})
	}
}

func TestBaseline_DeviationZeroStdDev(t *testing.T) {
	// Zero stddev: any difference is a deviation.
	baseline := Range{Min: 5, Max: 5, Mean: 5, StdDev: 0}

	// Same value: no deviation.
	dev := checkDeviation("test", baseline, 5, 2.0)
	if dev != nil {
		t.Error("expected no deviation for same value with zero stddev")
	}

	// Different value: deviation with high severity.
	dev = checkDeviation("test", baseline, 6, 2.0)
	if dev == nil {
		t.Fatal("expected deviation for different value with zero stddev")
	}
	if dev.Severity != severityHigh {
		t.Errorf("expected high severity, got %q", dev.Severity)
	}
}

func TestBaseline_WithinBounds(t *testing.T) {
	// Value within sigma threshold: no deviation.
	baseline := Range{Min: 3, Max: 7, Mean: 5, StdDev: 1}
	dev := checkDeviation("test", baseline, 6.5, 2.0)
	if dev != nil {
		t.Error("expected no deviation for value within 2 sigma")
	}
}

func TestBaseline_LoadCorruptProfile(t *testing.T) {
	dir := t.TempDir()

	// Write a corrupt profile file.
	corrupt := filepath.Join(dir, "corrupt-agent.json")
	if err := os.WriteFile(corrupt, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("writing corrupt file: %v", err)
	}

	cfg := Config{Enabled: true, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager should succeed even with corrupt profiles: %v", err)
	}

	// Corrupt profile should be silently skipped.
	agents := mgr.ListAgents()
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

func TestBaseline_LoadDirectoryEntry(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory (should be skipped).
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o750); err != nil {
		t.Fatalf("creating subdir: %v", err)
	}

	cfg := Config{Enabled: true, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	agents := mgr.ListAgents()
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

func TestBaseline_ProfileSerialization(t *testing.T) {
	profile := Profile{
		AgentKey:     testAgent,
		State:        StateLocked,
		SessionCount: 5,
		Ratified:     true,
		Metrics: ProfileMetrics{
			ToolCallsPerSession: Range{Min: 2, Max: 8, Mean: 5, StdDev: 1.5},
		},
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	var loaded Profile
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	if loaded.AgentKey != testAgent {
		t.Errorf("expected agent key %q, got %q", testAgent, loaded.AgentKey)
	}
	if loaded.State != StateLocked {
		t.Errorf("expected state %q, got %q", StateLocked, loaded.State)
	}
}

func TestBaseline_TrimOutliers_TooFewSessions(t *testing.T) {
	// With fewer than 3 sessions, outlier trimming returns all sessions.
	sessions := []SessionMetrics{
		{ToolCalls: 1},
		{ToolCalls: 1000},
	}

	result := trimOutliers(sessions)
	if len(result) != 2 {
		t.Errorf("expected 2 sessions (too few to trim), got %d", len(result))
	}
}

func TestComputeRange_Empty(t *testing.T) {
	r := computeRange(nil)
	if r.Min != 0 || r.Max != 0 || r.Mean != 0 || r.StdDev != 0 {
		t.Errorf("expected zero range for empty input, got %+v", r)
	}
}

func TestComputeRange_SingleValue(t *testing.T) {
	r := computeRange([]float64{42})
	if r.Min != 42 || r.Max != 42 || r.Mean != 42 {
		t.Errorf("unexpected range for single value: %+v", r)
	}
	if r.StdDev != 0 {
		t.Errorf("stddev should be 0 for single value, got %f", r.StdDev)
	}
}

func TestBaseline_LoadProfileWithEmptyAgentKey(t *testing.T) {
	dir := t.TempDir()

	// Write profile with empty agent_key. Should derive from filename.
	profile := Profile{
		AgentKey:     "",
		State:        StateLocked,
		SessionCount: 3,
		Ratified:     true,
		Metrics:      ProfileMetrics{},
	}
	data, _ := json.Marshal(profile)
	if err := os.WriteFile(filepath.Join(dir, "derived-agent.json"), data, 0o600); err != nil {
		t.Fatalf("writing profile: %v", err)
	}

	cfg := Config{Enabled: true, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Should be loaded with key derived from filename.
	p := mgr.GetProfile("derived-agent")
	if p == nil {
		t.Fatal("expected profile loaded from filename-derived key")
	}
}

func TestBaseline_NonJSONFileSkipped(t *testing.T) {
	dir := t.TempDir()

	// Write a non-JSON file (wrong extension).
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	cfg := Config{Enabled: true, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if len(mgr.ListAgents()) != 0 {
		t.Error("non-JSON files should be skipped")
	}
}

func TestBaseline_ResetDeletesFile(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	profilePath := filepath.Join(dir, testAgent+profileFileExt)
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("profile file should exist: %v", err)
	}

	if err := mgr.Reset(testAgent); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Error("profile file should be deleted after reset")
	}
}
