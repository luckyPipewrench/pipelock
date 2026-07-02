// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/proxy/baseline"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMCPBehavioralBaselineRealStdioProxyLearnsAndBlocksUnderIdentityKey(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	sm := proxy.NewSessionManager(&cfg.SessionProfiling, nil, metrics.New())
	t.Cleanup(sm.Close)
	baselineCfg := &config.BehavioralBaseline{
		Enabled:          true,
		LearningWindow:   2,
		DeviationAction:  config.ActionBlock,
		ProfileDir:       t.TempDir(),
		AutoRatify:       false,
		SensitivitySigma: 2.0,
		LockDimensions:   []string{"tool_calls", "unique_tools"},
		SeasonalityMode:  config.SeasonalityModeNone,
	}
	if err := sm.EnableBaseline(baselineCfg); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}

	const identityKey = "identity-k"
	for i := 0; i < baselineCfg.LearningWindow; i++ {
		stdout, stderr := runMCPStdioBaselineInvocation(t, sc, sm, identityKey, "steady_tool")
		if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
			t.Fatalf("learning invocation %d unexpectedly blocked\nstdout=%s\nstderr=%s", i, stdout, stderr)
		}
	}

	mgr := sm.BaselineManager()
	if state := mgr.GetState(identityKey); state != baseline.StateRatify {
		t.Fatalf("identity-key profile state = %q, want %q", state, baseline.StateRatify)
	}
	assertNoInvocationBaselineAgents(t, mgr)
	assertBaselineAgents(t, mgr, identityKey)

	if err := mgr.Ratify(identityKey); err != nil {
		t.Fatalf("Ratify(%q): %v", identityKey, err)
	}
	if state := mgr.GetState(identityKey); state != baseline.StateLocked {
		t.Fatalf("identity-key profile state after ratify = %q, want %q", state, baseline.StateLocked)
	}

	stdout, stderr := runMCPStdioBaselineInvocation(t, sc, sm, identityKey, "steady_tool", "deviant_tool")
	if !strings.Contains(stdout, `"error"`) {
		t.Fatalf("deviating invocation under locked identity was allowed\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "baseline deviation") {
		t.Fatalf("deviating invocation did not log baseline block\nstdout=%s\nstderr=%s", stdout, stderr)
	}

	const otherIdentityKey = "identity-other"
	otherStdout, otherStderr := runMCPStdioBaselineInvocation(t, sc, sm, otherIdentityKey, "steady_tool", "deviant_tool")
	if strings.Contains(otherStdout, `"error"`) || strings.Contains(otherStderr, "baseline deviation") {
		t.Fatalf("still-learning identity unexpectedly blocked\nstdout=%s\nstderr=%s", otherStdout, otherStderr)
	}
	assertNoInvocationBaselineAgents(t, mgr)
}

func runMCPStdioBaselineInvocation(t *testing.T, sc *scanner.Scanner, sm *proxy.SessionManager, identityKey string, toolNames ...string) (string, string) {
	t.Helper()

	var stdin strings.Builder
	for i, toolName := range toolNames {
		_, _ = fmt.Fprintf(&stdin, `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`+"\n", i+1, toolName)
	}

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := mcp.RunProxy(ctx, strings.NewReader(stdin.String()), &stdout, &stderr, []string{os.Args[0], "-test.run=TestMCPBaselineHelperProcess", "--"}, mcp.MCPProxyOpts{
		Scanner:                sc,
		Store:                  sm.AsStore(),
		Baseline:               sm,
		AddressProtectionAgent: identityKey,
		Transport:              "mcp_stdio",
	}, "PIPELOCK_MCP_BASELINE_HELPER=1")
	if err != nil {
		t.Fatalf("RunProxy: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String()
}

func TestMCPBaselineHelperProcess(t *testing.T) {
	if os.Getenv("PIPELOCK_MCP_BASELINE_HELPER") != "1" {
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil || len(req.ID) == 0 {
			req.ID = json.RawMessage("null")
		}
		_, _ = fmt.Fprintf(os.Stdout, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`+"\n", req.ID)
	}
	os.Exit(0)
}

func assertBaselineAgents(t *testing.T, mgr *baseline.Manager, want ...string) {
	t.Helper()
	got := strings.Join(mgr.ListAgents(), ",")
	wantJoined := strings.Join(want, ",")
	if got != wantJoined {
		t.Fatalf("baseline agents = %q, want %q", got, wantJoined)
	}
}

func assertNoInvocationBaselineAgents(t *testing.T, mgr *baseline.Manager) {
	t.Helper()
	for _, agent := range mgr.ListAgents() {
		if strings.HasPrefix(agent, "mcp-stdio-") || strings.HasPrefix(agent, "mcp-http-") || strings.HasPrefix(agent, "mcp-ws-") {
			t.Fatalf("baseline learned under invocation key %q; want identity key only", agent)
		}
	}
}
