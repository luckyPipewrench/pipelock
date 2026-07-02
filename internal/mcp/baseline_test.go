// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const baselineDeferToolCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"text":"hello"}}}`

type baselineTestRecorder struct {
	toolCalls int
	tools     map[string]struct{}
}

func (r *baselineTestRecorder) BaselineMetrics() session.BaselineMetrics {
	return session.BaselineMetrics{
		ToolCalls:   r.toolCalls,
		UniqueTools: len(r.tools),
	}
}

func (r *baselineTestRecorder) ProvisionalToolCallMetrics(toolName string) session.BaselineMetrics {
	uniqueTools := len(r.tools)
	if _, ok := r.tools[toolName]; !ok {
		uniqueTools++
	}
	return session.BaselineMetrics{
		ToolCalls:   r.toolCalls + 1,
		UniqueTools: uniqueTools,
	}
}

func (r *baselineTestRecorder) RecordToolCall(toolName string) {
	if r.tools == nil {
		r.tools = make(map[string]struct{})
	}
	r.toolCalls++
	r.tools[toolName] = struct{}{}
}

func (r *baselineTestRecorder) RecordSignal(session.SignalType, float64) (bool, string, string) {
	return false, "", ""
}

func (r *baselineTestRecorder) RecordClean(float64) {}

func (r *baselineTestRecorder) EscalationLevel() int { return 0 }

func (r *baselineTestRecorder) ThreatScore() float64 { return 0 }

type identityBaselineChecker struct {
	t               *testing.T
	wantAgentKey    string
	blockedAgentKey string
	checks          int
	records         []session.BaselineMetrics
}

func (c *identityBaselineChecker) CheckBaselineForRecorder(agentKey string, rec session.Recorder) session.BaselineDecision {
	c.t.Helper()
	if agentKey != c.wantAgentKey {
		c.t.Fatalf("baseline checked agent key %q, want identity key %q", agentKey, c.wantAgentKey)
	}
	if agentKey == c.blockedAgentKey {
		return session.BaselineDecision{Blocked: true, Action: config.ActionBlock, Detail: "baseline deviation: tool_calls"}
	}
	return session.BaselineDecision{}
}

func (c *identityBaselineChecker) RecordBaselineForRecorder(string, session.Recorder) {}

func (c *identityBaselineChecker) CheckBaselineForMetrics(agentKey string, metrics session.BaselineMetrics) session.BaselineDecision {
	c.t.Helper()
	c.checks++
	if agentKey != c.wantAgentKey {
		c.t.Fatalf("baseline checked agent key %q, want identity key %q", agentKey, c.wantAgentKey)
	}
	if metrics.ToolCalls != 1 {
		c.t.Fatalf("baseline checked with tool_calls=%d, want provisional 1", metrics.ToolCalls)
	}
	if metrics.UniqueTools != 1 {
		c.t.Fatalf("baseline checked with unique_tools=%d, want provisional 1", metrics.UniqueTools)
	}
	if agentKey == c.blockedAgentKey {
		return session.BaselineDecision{Blocked: true, Action: config.ActionBlock, Detail: "baseline deviation: tool_calls"}
	}
	return session.BaselineDecision{}
}

func (c *identityBaselineChecker) RecordBaselineMetrics(_ string, metrics session.BaselineMetrics) {
	c.records = append(c.records, metrics)
}

func TestMCPBaselineCheckUsesProvisionalToolCallWithoutCommitting(t *testing.T) {
	t.Parallel()

	rec := &baselineTestRecorder{}
	checker := &identityBaselineChecker{
		t:            t,
		wantAgentKey: "identity-k",
	}
	decision := checkMCPToolCallBaselineAttempt(MCPProxyOpts{
		Baseline:               checker,
		AddressProtectionAgent: "identity-k",
	}, rec, "read_file")
	if decision.Action != "" {
		t.Fatalf("baseline decision = %+v, want allow/no decision", decision)
	}
	if checker.checks != 1 {
		t.Fatalf("baseline checks = %d, want 1", checker.checks)
	}
	if got := rec.BaselineMetrics().ToolCalls; got != 0 {
		t.Fatalf("committed tool calls after provisional check = %d, want 0", got)
	}
}

func TestMCPBehavioralBaselineUsesIdentityKeyNotInvocationKey(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	rec := &baselineTestRecorder{}
	checker := &identityBaselineChecker{
		t:               t,
		wantAgentKey:    "identity-k",
		blockedAgentKey: "identity-k",
	}
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}`)
	blocked := scanHTTPInput(msg, io.Discard, "mcp-http-42", "mcp-http-42", MCPProxyOpts{
		Scanner:                sc,
		Rec:                    rec,
		Baseline:               checker,
		AddressProtectionAgent: "identity-k",
		Transport:              "mcp_http_listener",
	})

	if blocked == nil {
		t.Fatal("MCP baseline deviation was allowed; want JSON-RPC block")
	}
}

func TestForwardScannedInput_BlockedPolicyToolCallDoesNotCommitBehavioralBaseline(t *testing.T) {
	t.Parallel()

	sc := testInputScanner(t)
	rec := &baselineTestRecorder{}
	policyCfg := buildPolicyConfig(config.ActionBlock, []config.ToolPolicyRule{
		{
			Name:        "block dangerous tool",
			ToolPattern: `^dangerous_tool$`,
			Action:      config.ActionBlock,
		},
	})

	var serverIn bytes.Buffer
	var logBuf bytes.Buffer
	blockedCh := make(chan BlockedRequest, 1)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(jsonToolsCallDangerous+"\n")),
		transport.NewStdioWriter(&serverIn),
		&logBuf,
		config.ActionBlock,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		MCPProxyOpts{Scanner: sc, Rec: rec, PolicyCfg: policyCfg},
	)

	if serverIn.Len() != 0 {
		t.Fatalf("policy-blocked request was forwarded: %s", serverIn.String())
	}
	if got := rec.BaselineMetrics().ToolCalls; got != 0 {
		t.Fatalf("committed tool calls after policy block = %d, want 0", got)
	}
	select {
	case <-blockedCh:
	default:
		t.Fatal("expected blocked policy request")
	}
}

func TestScanHTTPInputDecision_BlockedPolicyToolCallDoesNotCommitBehavioralBaseline(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	rec := &baselineTestRecorder{}
	policyCfg := buildPolicyConfig(config.ActionBlock, []config.ToolPolicyRule{
		{
			Name:        "block dangerous tool",
			ToolPattern: `^dangerous_tool$`,
			Action:      config.ActionBlock,
		},
	})

	decision := scanHTTPInputDecision([]byte(jsonToolsCallDangerous), io.Discard, "sess", "sess", MCPProxyOpts{
		Scanner:   sc,
		Rec:       rec,
		PolicyCfg: policyCfg,
	})
	if decision.Blocked == nil {
		t.Fatal("expected policy block")
	}
	if got := rec.BaselineMetrics().ToolCalls; got != 0 {
		t.Fatalf("committed tool calls after HTTP policy block = %d, want 0", got)
	}
}

func TestMCPDeferredDeniedDoesNotCommitBehavioralBaseline(t *testing.T) {
	t.Parallel()

	rec, serverIn := runDeferredBaselineScenario(t, config.ActionBlock)
	if serverIn.String() != "" {
		t.Fatalf("deferred-denied request was forwarded: %s", serverIn.String())
	}
	if got := rec.BaselineMetrics().ToolCalls; got != 0 {
		t.Fatalf("committed tool calls after deferred denial = %d, want 0", got)
	}
}

func TestMCPDeferredAllowedCommitsBehavioralBaselineOnce(t *testing.T) {
	t.Parallel()

	rec, _ := runDeferredBaselineScenario(t, config.ActionAllow)
	if got := rec.BaselineMetrics().ToolCalls; got != 1 {
		t.Fatalf("committed tool calls after deferred allow = %d, want 1", got)
	}
}

func runDeferredBaselineScenario(t *testing.T, finalDecision string) (*baselineTestRecorder, *syncBuffer) {
	t.Helper()

	sc := testInputScanner(t)
	rec := &baselineTestRecorder{}
	manager := newBaselineTestDeferManager(t)
	policyCfg := baselineDeferPolicy()
	receiptEmitter, receiptRecorder, _ := newTestReceiptEmitter(t)
	t.Cleanup(func() {
		if err := receiptRecorder.Close(); err != nil {
			t.Errorf("receipt recorder close: %v", err)
		}
	})

	inputR, inputW := io.Pipe()
	var serverIn syncBuffer
	var logBuf syncBuffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardScannedInput(
			transport.NewStdioReader(inputR),
			transport.NewStdioWriter(&serverIn),
			&logBuf,
			config.ActionWarn,
			config.ActionBlock,
			make(chan BlockedRequest, 1),
			nil,
			nil,
			MCPProxyOpts{
				Scanner:        sc,
				Rec:            rec,
				PolicyCfg:      policyCfg,
				DeferManager:   manager,
				Transport:      deferred.SurfaceMCPStdio,
				ReceiptEmitter: receiptEmitter,
			},
		)
	}()
	if _, err := inputW.Write([]byte(baselineDeferToolCall + "\n")); err != nil {
		t.Fatalf("write input: %v", err)
	}
	testwait.For(t, time.Second, func() bool {
		return len(manager.Snapshot()) == 1
	}, "deferred hold to be created; log=%s", &logBuf)

	held := manager.Snapshot()
	if len(held) != 1 {
		t.Fatalf("held actions = %d, want 1; log=%s", len(held), logBuf.String())
	}
	if err := manager.Resolve(held[0].DeferID, finalDecision, deferred.SourceApproval); err != nil {
		t.Fatalf("Resolve %s: %v", finalDecision, err)
	}
	if finalDecision == config.ActionAllow {
		testwait.For(t, time.Second, func() bool {
			return strings.Contains(serverIn.String(), "send_tool")
		}, "deferred-allowed request to be forwarded; log=%s", &logBuf)
	}
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	<-done
	return rec, &serverIn
}

func TestRunHTTPListenerProxy_BehavioralBaselineRecordsDiscretePerRequestSamples(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	checker := &identityBaselineChecker{
		t:            t,
		wantAgentKey: "identity-k",
	}
	adaptiveRec := &baselineTestRecorder{}
	for range 2 {
		baselineRec := newMCPRequestBaselineRecorder()
		opts := MCPProxyOpts{
			Scanner:                sc,
			Rec:                    adaptiveRec,
			BaselineRec:            baselineRec,
			Baseline:               checker,
			AddressProtectionAgent: "identity-k",
			Transport:              "mcp_http_listener",
		}
		decision := scanHTTPInputDecision([]byte(jsonToolsCallDangerous), io.Discard, "sess", "sess", opts)
		if decision.Blocked != nil {
			t.Fatalf("listener-equivalent scan blocked: %+v", decision.Blocked)
		}
		commitMCPToolCall(baselineRec, "dangerous_tool")
		recordMCPBaselineSample(opts, nil)
	}

	if len(checker.records) != 2 {
		t.Fatalf("baseline records = %d, want 2", len(checker.records))
	}
	for i, metrics := range checker.records {
		if metrics.ToolCalls != 1 {
			t.Fatalf("record %d tool_calls = %d, want discrete sample of 1", i, metrics.ToolCalls)
		}
		if metrics.Requests != 1 {
			t.Fatalf("record %d requests = %d, want per-request sample of 1", i, metrics.Requests)
		}
	}
	if got := adaptiveRec.BaselineMetrics().ToolCalls; got != 0 {
		t.Fatalf("adaptive host recorder tool_calls = %d, want 0 baseline commits", got)
	}
}

func baselineDeferPolicy() *policy.Config {
	resolutionPolicy := config.DeferResolutionPolicy{
		AllowOn: config.DeferAllowOn{Approval: true},
	}
	return &policy.Config{
		Action: config.ActionWarn,
		Rules: []*policy.CompiledRule{
			{
				Name:             "defer dangerous tool",
				ToolPattern:      regexp.MustCompile(`^send_tool$`),
				Action:           config.ActionDefer,
				ResolutionPolicy: resolutionPolicy,
			},
		},
	}
}

func newBaselineTestDeferManager(t *testing.T) *deferred.Manager {
	t.Helper()
	return deferred.NewManager(deferred.Config{
		Enabled:              true,
		Timeout:              time.Minute,
		MaxPending:           4,
		MaxPendingPerSession: 4,
		MaxPendingBytes:      4096,
	})
}
