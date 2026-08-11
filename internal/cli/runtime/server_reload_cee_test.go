// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func TestReloadMCPCEE_DisableRetiresBufferedState(t *testing.T) {
	if got := reloadMCPCEE(nil, nil, metrics.New()); got != nil {
		t.Fatalf("disabled reload without live CEE = %p, want nil", got)
	}

	cfg := config.Defaults()
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 8
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 64
	cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
	cee := buildMCPCEE(cfg, metrics.New())
	tracker, buffer := cee.Components()
	tracker.Record("session", []byte("secret"))
	buffer.Append("session", []byte("split-secret"))

	if got := reloadMCPCEE(cee, nil, metrics.New()); got != nil {
		t.Fatalf("disabled reload returned %p, want nil", got)
	}
	if tracker.CurrentUsage("session") != 0 || buffer.TotalBufferBytes() != 0 {
		t.Fatal("disabled reload retained CEE request state")
	}
}

func TestServerReload_PreservesMCPCEEState(t *testing.T) {
	s, _ := newTestServer(t, nil)
	reload := func(cfg *config.Config) error {
		s.lastReloadAt = time.Time{}
		return s.Reload(cfg)
	}

	firstCfg := s.proxy.CurrentConfig().Clone()
	firstCfg.CrossRequestDetection.Enabled = true
	firstCfg.CrossRequestDetection.Action = config.ActionBlock
	firstCfg.CrossRequestDetection.EntropyBudget.Enabled = true
	firstCfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 8
	firstCfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	firstCfg.CrossRequestDetection.EntropyBudget.Action = config.ActionBlock
	firstCfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	firstCfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 12
	firstCfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
	if err := reload(firstCfg); err != nil {
		t.Fatalf("first CEE reload: %v", err)
	}

	cee := s.currentMCPCEE()
	if cee == nil {
		t.Fatal("first CEE load returned nil, want tracker and buffer")
	}
	tracker, buffer := cee.Components()
	if tracker == nil || buffer == nil {
		t.Fatalf("first CEE load = %+v, want tracker and buffer", cee)
	}
	tracker.Record("mcp-session", []byte("abc"))
	buffer.Append("mcp-session", []byte("first-"))
	if tracker.BudgetExceeded("mcp-session") {
		t.Fatal("first MCP message unexpectedly exhausted the entropy budget")
	}

	// An unrelated setting change is the simplest reload-cycle evasion attempt.
	// The active MCP session must retain the first message's accounting.
	unrelated := s.proxy.CurrentConfig().Clone()
	unrelated.KillSwitch.Message = "reload without clearing MCP history"
	if err := reload(unrelated); err != nil {
		t.Fatalf("unrelated reload: %v", err)
	}
	cee = s.currentMCPCEE()
	gotTracker, gotBuffer := cee.Components()
	if gotTracker != tracker || gotBuffer != buffer {
		t.Fatal("unrelated reload replaced MCP CEE state")
	}
	tracker.Record("mcp-session", []byte("abc"))
	if !tracker.BudgetExceeded("mcp-session") {
		t.Fatal("MCP entropy history was cleared by unrelated reload")
	}

	// New limits apply to the retained state, rather than replacing it.
	tuned := s.proxy.CurrentConfig().Clone()
	tuned.CrossRequestDetection.EntropyBudget.BitsPerWindow = 6
	tuned.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 8
	if err := reload(tuned); err != nil {
		t.Fatalf("CEE limit reload: %v", err)
	}
	cee = s.currentMCPCEE()
	gotTracker, gotBuffer = cee.Components()
	if gotTracker != tracker || gotBuffer != buffer {
		t.Fatal("CEE limit reload replaced MCP CEE state")
	}
	if got := tracker.Budget(); got != 6 {
		t.Fatalf("reloaded entropy budget = %v, want 6", got)
	}
	buffer.Append("mcp-session", []byte("second"))
	if got := buffer.TotalBufferBytes(); got > 8 {
		t.Fatalf("reloaded fragment limit retained %d bytes, want at most 8", got)
	}

	// A reload may not disable this live security control. The runtime rejects
	// the downgrade and leaves the existing MCP window intact.
	disabled := s.proxy.CurrentConfig().Clone()
	disabled.CrossRequestDetection.Enabled = false
	err := reload(disabled)
	if err == nil {
		t.Fatal("CEE disable reload succeeded")
	}
	if !strings.Contains(err.Error(), "cross_request_detection.enabled disabled") {
		t.Fatalf("CEE disable rejected for the wrong reason: %v", err)
	}
	if got := s.currentMCPCEE(); got == nil {
		t.Fatal("rejected CEE downgrade replaced MCP CEE state")
	} else if gotTracker, gotBuffer := got.Components(); gotTracker != tracker || gotBuffer != buffer {
		t.Fatal("rejected CEE downgrade replaced MCP CEE components")
	}
}

func TestServerReload_FailedReloadKeepsMCPCEEState(t *testing.T) {
	s, _ := newTestServer(t, nil)
	reload := func(cfg *config.Config) error {
		s.lastReloadAt = time.Time{}
		return s.Reload(cfg)
	}

	cfg := s.proxy.CurrentConfig().Clone()
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 8
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	if err := reload(cfg); err != nil {
		t.Fatalf("enable CEE: %v", err)
	}
	before := s.currentMCPCEE()
	beforeTracker, _ := before.Components()
	beforeTracker.Record("mcp-session", []byte("abc"))

	broken := s.proxy.CurrentConfig().Clone()
	broken.MediationEnvelope.Enabled = true
	broken.MediationEnvelope.Sign = true
	broken.MediationEnvelope.SigningKeyPath = "/definitely/missing-signing-key"
	if err := reload(broken); err == nil {
		t.Fatal("malformed reload succeeded")
	}
	if got := s.currentMCPCEE(); got != before {
		t.Fatal("failed reload replaced MCP CEE state")
	} else if gotTracker, _ := got.Components(); gotTracker != beforeTracker {
		t.Fatal("failed reload replaced MCP CEE tracker")
	}
	beforeTracker.Record("mcp-session", []byte("abc"))
	if !beforeTracker.BudgetExceeded("mcp-session") {
		t.Fatal("failed reload cleared MCP entropy history")
	}
}

func TestServerReload_PreservesMCPToolChainStateOnConfigChange(t *testing.T) {
	s, _ := newTestServer(t, nil)
	reload := func(cfg *config.Config) error {
		s.lastReloadAt = time.Time{}
		return s.Reload(cfg)
	}

	firstCfg := s.proxy.CurrentConfig().Clone()
	firstCfg.ToolChainDetection.Enabled = true
	firstCfg.ToolChainDetection.Action = config.ActionWarn
	firstCfg.ToolChainDetection.WindowSize = 20
	firstCfg.ToolChainDetection.WindowSeconds = 60
	if err := reload(firstCfg); err != nil {
		t.Fatalf("enable tool-chain detection: %v", err)
	}

	matcher := s.currentMCPChainMatcher()
	if matcher == nil {
		t.Fatal("enabled reload did not create MCP chain matcher")
	}
	const session = "mcp-reload-chain"
	if got := matcher.Record(session, "list_issues"); got.Matched {
		t.Fatalf("untrusted-source prefix = %+v, want no match", got)
	}
	if got := matcher.Record(session, "read_private_repo"); got.Matched {
		t.Fatalf("two-step trifecta prefix = %+v, want no match", got)
	}

	tuned := s.proxy.CurrentConfig().Clone()
	tuned.ToolChainDetection.WindowSeconds = 120
	tuned.ToolChainDetection.PatternOverrides = map[string]string{
		"lethal-trifecta": config.ActionBlock,
	}
	if err := reload(tuned); err != nil {
		t.Fatalf("reconfigure tool-chain detection: %v", err)
	}
	if got := s.currentMCPChainMatcher(); got != matcher {
		t.Fatal("tool-chain config reload replaced matcher and cleared active sessions")
	}

	got := matcher.Record(session, "create_pull_request")
	if !got.Matched || got.PatternName != "lethal-trifecta" || got.Action != config.ActionBlock {
		t.Fatalf("completion after tool-chain reload = %+v, want blocking lethal trifecta", got)
	}
}
