// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func testBaselineBlockConfig(t *testing.T) *config.BehavioralBaseline {
	t.Helper()
	return &config.BehavioralBaseline{
		Enabled:          true,
		LearningWindow:   1,
		DeviationAction:  config.ActionBlock,
		ProfileDir:       t.TempDir(),
		AutoRatify:       true,
		SensitivitySigma: 2.0,
		LockDimensions:   []string{"domains", "requests"},
		SeasonalityMode:  config.SeasonalityModeNone,
	}
}

func lockHTTPBaseline(t *testing.T, sm *SessionManager, agent string) {
	t.Helper()
	cfg := testSessionConfig()
	learned := sm.GetOrCreate(agent + "|10.0.0.1")
	learned.RecordRequest("steady.example", cfg)
	sm.recordSessionBaseline(learned)
	if state := sm.BaselineManager().GetState(agent); state != "locked" {
		t.Fatalf("baseline state = %q, want locked", state)
	}
}

func TestRecordSessionActivity_BaselineBlockAfterLock(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.AnomalyAction = config.ActionWarn
	cfg.BehavioralBaseline = *testBaselineBlockConfig(t)

	sm := NewSessionManager(&cfg.SessionProfiling, nil, metrics.New())
	t.Cleanup(sm.Close)
	if err := sm.EnableBaseline(&cfg.BehavioralBaseline); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}
	lockHTTPBaseline(t, sm, "agent-a")

	p := &Proxy{metrics: metrics.New()}
	p.sessionMgrPtr.Store(sm)
	log := audit.NewNop()
	clean := scanner.Result{Allowed: true}

	first := p.recordSessionActivityWithUserAgent(sessionActivityOptions{
		ClientIP: "10.0.0.99", Agent: "agent-a", Hostname: "steady.example",
		RequestID: "req-1", Result: clean, Config: cfg, Logger: log,
	})
	if first.Blocked {
		t.Fatalf("first request blocked before deviation: %+v", first)
	}

	second := p.recordSessionActivityWithUserAgent(sessionActivityOptions{
		ClientIP: "10.0.0.99", Agent: "agent-a", Hostname: "deviant.example",
		RequestID: "req-2", Result: clean, Config: cfg, Logger: log,
	})
	if !second.Blocked {
		t.Fatalf("deviating locked profile allowed: %+v", second)
	}
}

func TestSessionManager_CheckBaselineInvalidAgentKeyFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	t.Cleanup(sm.Close)
	if err := sm.EnableBaseline(testBaselineBlockConfig(t)); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}
	sess := sm.GetOrCreate("agent-bad|10.0.0.1")
	sess.RecordRequest("steady.example", cfg)

	result := sm.CheckBaselineFailClosed("../agent-bad", sess)
	if result == nil || !result.Blocked || result.Action != config.ActionBlock || result.Err == nil {
		t.Fatalf("expected invalid agent key to fail closed, got %#v", result)
	}
}

func TestSessionManager_RecordBaselineForAgentInvalidKeyAndLockedNoOp(t *testing.T) {
	t.Parallel()

	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	t.Cleanup(sm.Close)
	bb := testBaselineBlockConfig(t)
	bb.AutoRatify = false
	bb.LockDimensions = []string{"tool_calls"}
	if err := sm.EnableBaseline(bb); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}

	invalid := sm.GetOrCreate("mcp-http-invalid")
	invalid.RecordToolCall("steady_tool")
	sm.RecordBaselineForAgent("../agent-bad", invalid)
	if agents := sm.BaselineManager().ListAgents(); len(agents) != 0 {
		t.Fatalf("invalid identity key created baseline agents: %v", agents)
	}

	const agent = "agent-locked"
	learned := sm.GetOrCreate("mcp-http-learn")
	learned.RecordToolCall("steady_tool")
	sm.RecordBaselineForAgent(agent, learned)
	if state := sm.BaselineManager().GetState(agent); state != "ratify" {
		t.Fatalf("baseline state = %q, want ratify", state)
	}
	if err := sm.BaselineManager().Ratify(agent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	deviant := sm.GetOrCreate("mcp-http-deviant")
	deviant.RecordToolCall("steady_tool")
	deviant.RecordToolCall("second_tool")
	sm.RecordBaselineForAgent(agent, deviant)

	profile := sm.BaselineManager().GetProfile(agent)
	if profile == nil {
		t.Fatal("locked profile missing")
	}
	if profile.Metrics.ToolCallsPerSession.Mean != 1 {
		t.Fatalf("locked profile mutated after record: tool_calls mean = %.2f, want 1.00", profile.Metrics.ToolCallsPerSession.Mean)
	}
}

func TestSessionManager_ReconfigureBaselinePreservesLockedProfile(t *testing.T) {
	t.Parallel()

	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	t.Cleanup(sm.Close)
	bb := testBaselineBlockConfig(t)
	if err := sm.EnableBaseline(bb); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}
	lockHTTPBaseline(t, sm, "agent-b")

	reloaded := *bb
	reloaded.DeviationAction = config.ActionWarn
	if err := sm.ReconfigureBaseline(&reloaded); err != nil {
		t.Fatalf("ReconfigureBaseline: %v", err)
	}

	deviant := sm.GetOrCreate("agent-b|10.0.0.99")
	deviant.RecordRequest("one.example", cfg)
	deviant.RecordRequest("two.example", cfg)
	result := sm.CheckBaseline("agent-b", deviant)
	if result == nil {
		t.Fatal("locked profile did not survive reload")
	}
	if result.Action != config.ActionWarn || result.Blocked {
		t.Fatalf("baseline result after reload = %+v, want warn non-blocking", result)
	}
}

func TestSessionManager_CheckBaselineRaceWithReconfigure(t *testing.T) {
	t.Parallel()

	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	t.Cleanup(sm.Close)
	bb := testBaselineBlockConfig(t)
	if err := sm.EnableBaseline(bb); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}
	lockHTTPBaseline(t, sm, "agent-race")
	deviant := sm.GetOrCreate("agent-race|10.0.0.99")
	deviant.RecordRequest("one.example", cfg)
	deviant.RecordRequest("two.example", cfg)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = sm.CheckBaselineFailClosed("agent-race", deviant)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				next := *bb
				if (i+j)%2 == 0 {
					next.DeviationAction = config.ActionWarn
				}
				next.SensitivitySigma = float64((i+j)%3) + 1
				if err := sm.ReconfigureBaseline(&next); err != nil {
					t.Errorf("ReconfigureBaseline: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	if result := sm.CheckBaselineFailClosed("agent-race", deviant); result == nil {
		t.Fatal("locked profile missing after concurrent reconfigure/check")
	}
}
