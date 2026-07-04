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
	"slices"
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

func TestMCPA2ABehavioralBaselineLearnsLocksAndReloads(t *testing.T) {
	testCases := []struct {
		name   string
		reload bool
	}{
		{name: "locked manager", reload: false},
		{name: "reloaded locked manager", reload: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			sc := scanner.New(cfg)
			t.Cleanup(sc.Close)

			profileDir := t.TempDir()
			sm := proxy.NewSessionManager(&cfg.SessionProfiling, nil, metrics.New())
			t.Cleanup(sm.Close)
			baselineCfg := &config.BehavioralBaseline{
				Enabled:          true,
				LearningWindow:   2,
				DeviationAction:  config.ActionBlock,
				ProfileDir:       profileDir,
				AutoRatify:       false,
				SensitivitySigma: 2.0,
				LockDimensions:   []string{"tool_calls", "unique_tools"},
				SeasonalityMode:  config.SeasonalityModeNone,
			}
			if err := sm.EnableBaseline(baselineCfg); err != nil {
				t.Fatalf("EnableBaseline: %v", err)
			}

			const identityKey = "agent-a"
			for i := 0; i < baselineCfg.LearningWindow; i++ {
				stdout, stderr := runMCPStdioBaselineMessages(t, sc, sm, identityKey, a2aSendMessageRequest(i+1))
				if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
					t.Fatalf("learning A2A invocation %d unexpectedly blocked\nstdout=%s\nstderr=%s", i, stdout, stderr)
				}
			}

			mgr := sm.BaselineManager()
			if state := mgr.GetState(identityKey); state != baseline.StateRatify {
				t.Fatalf("identity-key profile state = %q, want %q", state, baseline.StateRatify)
			}
			profile := mgr.GetProfile(identityKey)
			if profile == nil || !slices.Contains(profile.ToolIdentities, "a2a:SendMessage") {
				t.Fatalf("learned profile identities = %v, want a2a:SendMessage", profile)
			}
			if err := mgr.Ratify(identityKey); err != nil {
				t.Fatalf("Ratify(%q): %v", identityKey, err)
			}

			activeSM := sm
			if tc.reload {
				reloaded := proxy.NewSessionManager(&cfg.SessionProfiling, nil, metrics.New())
				t.Cleanup(reloaded.Close)
				if err := reloaded.EnableBaseline(baselineCfg); err != nil {
					t.Fatalf("EnableBaseline after reload: %v", err)
				}
				activeSM = reloaded
				reloadedProfile := activeSM.BaselineManager().GetProfile(identityKey)
				if reloadedProfile == nil || !slices.Contains(reloadedProfile.ToolIdentities, "a2a:SendMessage") {
					t.Fatalf("reloaded profile identities = %v, want a2a:SendMessage", reloadedProfile)
				}
			}

			allowedStdout, allowedStderr := runMCPStdioBaselineMessages(t, sc, activeSM, identityKey, a2aSendMessageRequest(10))
			if strings.Contains(allowedStdout, `"error"`) || strings.Contains(allowedStderr, "baseline deviation") {
				t.Fatalf("learned A2A method was blocked\nstdout=%s\nstderr=%s", allowedStdout, allowedStderr)
			}

			blockedStdout, blockedStderr := runMCPStdioBaselineMessages(t, sc, activeSM, identityKey, a2aGetTaskRequest(11))
			if !strings.Contains(blockedStdout, `"error"`) {
				t.Fatalf("unlearned A2A method was allowed\nstdout=%s\nstderr=%s", blockedStdout, blockedStderr)
			}
			if !strings.Contains(blockedStderr, "baseline deviation") {
				t.Fatalf("unlearned A2A method did not log baseline block\nstdout=%s\nstderr=%s", blockedStdout, blockedStderr)
			}

			notificationStdout, notificationStderr := runMCPStdioBaselineMessages(t, sc, activeSM, identityKey, a2aGetTaskNotification())
			if strings.Contains(notificationStdout, `"result"`) {
				t.Fatalf("unlearned A2A notification was forwarded\nstdout=%s\nstderr=%s", notificationStdout, notificationStderr)
			}
			if !strings.Contains(notificationStderr, "baseline deviation") {
				t.Fatalf("unlearned A2A notification did not log baseline block\nstdout=%s\nstderr=%s", notificationStdout, notificationStderr)
			}
		})
	}
	t.Run("unrelated config reload preserves locked A2A identities", func(t *testing.T) {
		sc, sm, baselineCfg, identityKey := newLockedA2ABaselineHarness(t)
		baselineCfg.SensitivitySigma = 3.5
		if err := sm.ReconfigureBaseline(baselineCfg); err != nil {
			t.Fatalf("ReconfigureBaseline unrelated change: %v", err)
		}
		reloadedProfile := sm.BaselineManager().GetProfile(identityKey)
		if reloadedProfile == nil || !slices.Contains(reloadedProfile.ToolIdentities, "a2a:SendMessage") {
			t.Fatalf("reloaded profile identities = %v, want a2a:SendMessage", reloadedProfile)
		}
		allowedStdout, allowedStderr := runMCPStdioBaselineMessages(t, sc, sm, identityKey, a2aSendMessageRequest(20))
		if strings.Contains(allowedStdout, `"error"`) || strings.Contains(allowedStderr, "baseline deviation") {
			t.Fatalf("unrelated reload lost learned A2A method\nstdout=%s\nstderr=%s", allowedStdout, allowedStderr)
		}
		blockedStdout, blockedStderr := runMCPStdioBaselineMessages(t, sc, sm, identityKey, a2aGetTaskRequest(21))
		if !strings.Contains(blockedStdout, `"error"`) || !strings.Contains(blockedStderr, "baseline deviation") {
			t.Fatalf("unrelated reload did not preserve locked enforcement\nstdout=%s\nstderr=%s", blockedStdout, blockedStderr)
		}
	})

	t.Run("disabled reload revokes locked A2A enforcement", func(t *testing.T) {
		sc, sm, baselineCfg, identityKey := newLockedA2ABaselineHarness(t)
		disabled := *baselineCfg
		disabled.Enabled = false
		if err := sm.ReconfigureBaseline(&disabled); err != nil {
			t.Fatalf("ReconfigureBaseline disabled: %v", err)
		}
		if sm.BaselineManager() != nil {
			t.Fatal("disabled baseline reload left a manager installed")
		}
		stdout, stderr := runMCPStdioBaselineMessages(t, sc, sm, identityKey, a2aGetTaskRequest(22))
		if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
			t.Fatalf("disabled baseline reload still blocked A2A request\nstdout=%s\nstderr=%s", stdout, stderr)
		}
	})

	t.Run("profile dir reload drops stale in-memory A2A identities", func(t *testing.T) {
		sc, sm, baselineCfg, identityKey := newLockedA2ABaselineHarness(t)
		changed := *baselineCfg
		changed.ProfileDir = t.TempDir()
		if err := sm.ReconfigureBaseline(&changed); err != nil {
			t.Fatalf("ReconfigureBaseline profile dir change: %v", err)
		}
		if profile := sm.BaselineManager().GetProfile(identityKey); profile != nil {
			t.Fatalf("profile dir change kept stale profile identities: %v", profile.ToolIdentities)
		}
		stdout, stderr := runMCPStdioBaselineMessages(t, sc, sm, identityKey, a2aGetTaskRequest(23))
		if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
			t.Fatalf("profile dir change served stale locked A2A identity\nstdout=%s\nstderr=%s", stdout, stderr)
		}
	})
}

func newLockedA2ABaselineHarness(t *testing.T) (*scanner.Scanner, *proxy.SessionManager, *config.BehavioralBaseline, string) {
	t.Helper()

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

	const identityKey = "agent-a"
	for i := 0; i < baselineCfg.LearningWindow; i++ {
		stdout, stderr := runMCPStdioBaselineMessages(t, sc, sm, identityKey, a2aSendMessageRequest(i+1))
		if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
			t.Fatalf("learning A2A invocation %d unexpectedly blocked\nstdout=%s\nstderr=%s", i, stdout, stderr)
		}
	}
	mgr := sm.BaselineManager()
	profile := mgr.GetProfile(identityKey)
	if profile == nil || !slices.Contains(profile.ToolIdentities, "a2a:SendMessage") {
		t.Fatalf("learned profile identities = %v, want a2a:SendMessage", profile)
	}
	if err := mgr.Ratify(identityKey); err != nil {
		t.Fatalf("Ratify(%q): %v", identityKey, err)
	}
	return sc, sm, baselineCfg, identityKey
}

func TestMCPBehavioralBaselineToolCallNameBehaviorUnchanged(t *testing.T) {
	testCases := []struct {
		name     string
		toolName string
	}{
		{name: "ordinary different tool", toolName: "different_tool"},
		{name: "a2a-prefixed tool name", toolName: "a2a:GetTask"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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

			const identityKey = "agent-a"
			for i := 0; i < baselineCfg.LearningWindow; i++ {
				stdout, stderr := runMCPStdioBaselineInvocation(t, sc, sm, identityKey, "steady_tool")
				if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
					t.Fatalf("learning tool invocation %d unexpectedly blocked\nstdout=%s\nstderr=%s", i, stdout, stderr)
				}
			}
			if err := sm.BaselineManager().Ratify(identityKey); err != nil {
				t.Fatalf("Ratify(%q): %v", identityKey, err)
			}

			stdout, stderr := runMCPStdioBaselineInvocation(t, sc, sm, identityKey, tc.toolName)
			if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
				t.Fatalf("single different tool call %q changed behavior; expected existing count-based allow\nstdout=%s\nstderr=%s", tc.toolName, stdout, stderr)
			}
		})
	}
}

func TestMCPA2ABehavioralBaselineToolNameCannotTeachA2AMethod(t *testing.T) {
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

	const identityKey = "agent-a"
	for i := 0; i < baselineCfg.LearningWindow; i++ {
		stdout, stderr := runMCPStdioBaselineInvocation(t, sc, sm, identityKey, "a2a:SendMessage")
		if strings.Contains(stdout, `"error"`) || strings.Contains(stderr, "baseline deviation") {
			t.Fatalf("learning namespaced tool invocation %d unexpectedly blocked\nstdout=%s\nstderr=%s", i, stdout, stderr)
		}
	}
	if err := sm.BaselineManager().Ratify(identityKey); err != nil {
		t.Fatalf("Ratify(%q): %v", identityKey, err)
	}

	stdout, stderr := runMCPStdioBaselineMessages(t, sc, sm, identityKey, a2aSendMessageRequest(10))
	if !strings.Contains(stdout, `"error"`) {
		t.Fatalf("A2A method was allowed by profile learned from same-named tool\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "baseline deviation") {
		t.Fatalf("A2A method collision did not log baseline block\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}

func runMCPStdioBaselineInvocation(t *testing.T, sc *scanner.Scanner, sm *proxy.SessionManager, identityKey string, toolNames ...string) (string, string) {
	t.Helper()

	messages := make([]string, 0, len(toolNames))
	for i, toolName := range toolNames {
		messages = append(messages, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, i+1, toolName))
	}
	return runMCPStdioBaselineMessages(t, sc, sm, identityKey, messages...)
}

func runMCPStdioBaselineMessages(t *testing.T, sc *scanner.Scanner, sm *proxy.SessionManager, identityKey string, messages ...string) (string, string) {
	t.Helper()

	var stdin strings.Builder
	for _, message := range messages {
		stdin.WriteString(message)
		stdin.WriteByte('\n')
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

func a2aSendMessageRequest(id int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"SendMessage","params":{"message":{"parts":[{"text":"hello peer"}]}}}`, id)
}

func a2aGetTaskRequest(id int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"GetTask","params":{"id":"task-a"}}`, id)
}

func a2aGetTaskNotification() string {
	return `{"jsonrpc":"2.0","method":"GetTask","params":{"id":"task-a"}}`
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
