// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const testFrozenSessionKey = "test-session"

// stubToolFreezer is a session.ToolFreezer test double. Allowed names
// are treated as permitted; anything else fails the IsToolAllowed
// check. When frozen is false IsFrozen returns false so the gate is
// a no-op.
type stubToolFreezer struct {
	frozen  bool
	allowed map[string]bool
}

func (s *stubToolFreezer) IsFrozen(_ string) bool { return s.frozen }
func (s *stubToolFreezer) IsToolAllowed(_ string, tool string) bool {
	return s.allowed[tool]
}

func TestEvaluateMCPInputGatesStdio_BatchBindingPreCheck(t *testing.T) {
	// Even though the stdio caller rejects batches before calling the
	// helper, the defense-in-depth gate populates BindingAction/Reason
	// so the caller's capture-observe side effect survives if the
	// early reject is ever removed.
	t.Parallel()

	sc := testInputScanner(t)
	tb := tools.NewToolBaseline()
	tb.SetKnownTools([]string{"read_file"})

	bindingCfg := &SessionBindingConfig{
		Baseline:          tb,
		UnknownToolAction: config.ActionBlock,
		NoBaselineAction:  config.ActionBlock,
	}

	batch := []byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`)
	frame := ParseMCPFrame(batch)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		batch,
		batch, // trimmedLine starts with '['
		bindingCfg,
		testOpts(sc),
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BindingReason != bindingReasonBatchRequest {
		t.Errorf("BindingReason = %q, want %s", eval.BindingReason, bindingReasonBatchRequest)
	}
	if eval.BindingAction != config.ActionBlock {
		t.Errorf("BindingAction = %q, want block", eval.BindingAction)
	}
	if eval.BlockingGate != "" {
		t.Errorf("BlockingGate = %q, want empty (pre-check never short-circuits)", eval.BlockingGate)
	}
}

func TestEvaluateMCPInputGatesStdio_FrozenToolBlocksUnknownTool(t *testing.T) {
	t.Parallel()

	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.ToolFreezer = &stubToolFreezer{frozen: true, allowed: map[string]bool{"read_file": true}}
	opts.FrozenToolStableKey = testFrozenSessionKey

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_command","arguments":{"cmd":"ls"}}}`)
	frame := ParseMCPFrame(msg)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		msg,
		msg,
		nil,
		opts,
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BlockingGate != blockingGateFrozenTool {
		t.Errorf("BlockingGate = %q, want %s", eval.BlockingGate, blockingGateFrozenTool)
	}
	if eval.FrozenToolName != "exec_command" {
		t.Errorf("FrozenToolName = %q, want exec_command", eval.FrozenToolName)
	}
}

// TestEvaluateMCPInputGatesStdio_FrozenSessionAllowsNonToolCallMethods
// pins the Gate 7 scoping fix: when a session is frozen, MCP protocol
// messages that carry no tool name (tools/list, initialize,
// notifications/*) must continue to flow. Without the method filter
// they would hit the fail-closed branch (toolCallName == "") and
// block, breaking handshake, discovery, and session recovery.
func TestEvaluateMCPInputGatesStdio_FrozenSessionAllowsNonToolCallMethods(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		msg  []byte
	}{
		{"tools/list", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)},
		{"initialize", []byte(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)},
		{"notification", []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sc := testInputScanner(t)
			opts := testOpts(sc)
			// Freeze the session to only one tool. Non-tools/call
			// methods carry no tool name; they must NOT be blocked.
			opts.ToolFreezer = &stubToolFreezer{frozen: true, allowed: map[string]bool{"read_file": true}}
			opts.FrozenToolStableKey = testFrozenSessionKey

			frame := ParseMCPFrame(tc.msg)
			eval := EvaluateMCPInputGatesStdio(
				context.Background(),
				frame,
				tc.msg,
				tc.msg,
				nil,
				opts,
				config.ActionWarn,
				config.ActionBlock,
			)

			if eval.BlockingGate == blockingGateFrozenTool {
				t.Errorf("frozen session must not block non-tools/call method %q; "+
					"Gate 7 should scope to methodToolsCall (breaks MCP handshake/discovery/recovery otherwise)", tc.name)
			}
		})
	}
}

func TestEvaluateMCPInputGatesStdio_FrozenToolAllowsKnownTool(t *testing.T) {
	t.Parallel()

	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.ToolFreezer = &stubToolFreezer{frozen: true, allowed: map[string]bool{"read_file": true}}
	opts.FrozenToolStableKey = testFrozenSessionKey

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`)
	frame := ParseMCPFrame(msg)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		msg,
		msg,
		nil,
		opts,
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BlockingGate != "" {
		t.Errorf("BlockingGate = %q, want empty for allowed tool", eval.BlockingGate)
	}
}

func TestEvaluateMCPInputGatesStdio_TaintBlock(t *testing.T) {
	// Hostile external taint + sensitive write resolves to PolicyBlock
	// directly (no approval dialog). Short-circuits on "taint_block".
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalHostile,
		},
	})

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/middleware.go","content":"x"}}}`)
	frame := ParseMCPFrame(msg)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		msg,
		msg,
		nil,
		MCPProxyOpts{
			Scanner:  sc,
			Rec:      rec,
			TaintCfg: &cfg.Taint,
		},
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BlockingGate != blockingGateTaintBlock {
		t.Errorf("BlockingGate = %q, want %s", eval.BlockingGate, blockingGateTaintBlock)
	}
	if !eval.TaintAuditDecisionSet {
		t.Error("TaintAuditDecisionSet = false, want true (pre-approval snapshot)")
	}
}

func TestEvaluateMCPInputGatesStdio_TaintAskDeniedWithoutApprover(t *testing.T) {
	// Untrusted external taint + protected write resolves to PolicyAsk.
	// Without an Approver configured, taintDecisionRequiresApproval
	// returns false, so the helper short-circuits on taint_ask_denied.
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/middleware.go","content":"x"}}}`)
	frame := ParseMCPFrame(msg)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		msg,
		msg,
		nil,
		MCPProxyOpts{
			Scanner:  sc,
			Rec:      rec,
			TaintCfg: &cfg.Taint,
		},
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BlockingGate != blockingGateTaintAskDenied {
		t.Errorf("BlockingGate = %q, want %s", eval.BlockingGate, blockingGateTaintAskDenied)
	}
}

func TestEvaluateMCPInputGatesStdio_TaintAskApproved(t *testing.T) {
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/middleware.go","content":"x"}}}`)
	frame := ParseMCPFrame(msg)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		msg,
		msg,
		nil,
		MCPProxyOpts{
			Scanner:   sc,
			Rec:       rec,
			TaintCfg:  &cfg.Taint,
			Approver:  testApproverForMCP(t, "y\n"),
			Transport: "mcp_stdio",
		},
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BlockingGate != "" {
		t.Errorf("BlockingGate = %q, want empty after approval", eval.BlockingGate)
	}
	if !eval.TaintApproved {
		t.Error("TaintApproved = false, want true")
	}
	if !eval.TaintAuditDecisionSet {
		t.Error("TaintAuditDecisionSet = false, want true (snapshot captured pre-approval)")
	}
}

func TestEvaluateMCPInputGatesStdio_DoWWarnDoesNotShortCircuit(t *testing.T) {
	// DoW with warn action populates DoWAction/DoWReason/DoWBudgetType
	// but does NOT set BlockingGate, leaving the caller to log the
	// diagnostic + anomaly + near-miss signal before forwarding.
	t.Parallel()

	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.DoWCheck = func(_ string, _ string) (bool, string, string, string) {
		return false, config.ActionWarn, testDoWBudgetReason, "per_tool"
	}

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`)
	frame := ParseMCPFrame(msg)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		msg,
		msg,
		nil,
		opts,
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BlockingGate != "" {
		t.Errorf("BlockingGate = %q, want empty (warn does not short-circuit)", eval.BlockingGate)
	}
	if eval.DoWAllowed {
		t.Error("DoWAllowed = true, want false")
	}
	if eval.DoWAction != config.ActionWarn {
		t.Errorf("DoWAction = %q, want warn", eval.DoWAction)
	}
	if eval.DoWReason != testDoWBudgetReason {
		t.Errorf("DoWReason = %q, want %s", eval.DoWReason, testDoWBudgetReason)
	}
}

func TestEvaluateMCPInputGatesStdio_ParseErrorShortCircuit(t *testing.T) {
	// Force ContentVerdict.Error via invalid JSON. The frame will
	// have ParseErr set and ScanRequest returns a parse-error verdict.
	t.Parallel()

	sc := testInputScanner(t)

	msg := []byte(`not json at all`)
	frame := ParseMCPFrame(msg)

	eval := EvaluateMCPInputGatesStdio(
		context.Background(),
		frame,
		msg,
		msg,
		nil,
		testOpts(sc),
		config.ActionWarn,
		config.ActionBlock,
	)

	if eval.BlockingGate != blockingGateParseError {
		t.Errorf("BlockingGate = %q, want %s", eval.BlockingGate, blockingGateParseError)
	}
	if eval.ContentVerdict.Error == "" {
		t.Error("ContentVerdict.Error is empty, expected parse-error reason")
	}
}
