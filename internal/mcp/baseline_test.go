// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

type baselineTestRecorder struct {
	toolCalls int
}

func (r *baselineTestRecorder) RecordToolCall(string) {
	r.toolCalls++
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
}

func (c *identityBaselineChecker) CheckBaselineForRecorder(agentKey string, rec session.Recorder) session.BaselineDecision {
	if agentKey != c.wantAgentKey {
		c.t.Fatalf("baseline checked agent key %q, want identity key %q", agentKey, c.wantAgentKey)
	}
	r, ok := rec.(*baselineTestRecorder)
	if !ok {
		c.t.Fatalf("baseline checked with recorder %T, want *baselineTestRecorder", rec)
	}
	if r.toolCalls != 1 {
		c.t.Fatalf("baseline checked before recording tool call: tool_calls=%d", r.toolCalls)
	}
	if agentKey == c.blockedAgentKey {
		return session.BaselineDecision{Blocked: true, Action: config.ActionBlock, Detail: "baseline deviation: tool_calls"}
	}
	return session.BaselineDecision{}
}

func (c *identityBaselineChecker) RecordBaselineForRecorder(string, session.Recorder) {}

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
