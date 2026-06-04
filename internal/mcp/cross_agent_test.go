// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// signalRiskRecorder implements both session.Recorder (tracking recorded
// signals + score) and session.RiskState (real taint folding), so a test can
// contaminate a session AND assert which adaptive signals fired.
type signalRiskRecorder struct {
	mu      sync.Mutex
	risk    session.SessionRisk
	signals []session.SignalType
	score   float64
}

func (r *signalRiskRecorder) RecordSignal(sig session.SignalType, _ float64) (bool, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signals = append(r.signals, sig)
	r.score += session.SignalPoints[sig]
	return false, "", ""
}
func (r *signalRiskRecorder) RecordClean(_ float64) {}
func (r *signalRiskRecorder) EscalationLevel() int  { return 0 }

func (r *signalRiskRecorder) ThreatScore() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.score
}

func (r *signalRiskRecorder) RiskSnapshot() session.SessionRisk {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.risk.Snapshot()
}

func (r *signalRiskRecorder) ObserveRisk(o session.RiskObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.risk.Observe(o)
}

func (r *signalRiskRecorder) hasSignal(want session.SignalType) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.signals {
		if s == want {
			return true
		}
	}
	return false
}

// crossAgentSources returns the cross_agent taint sources recorded on a
// recorder's risk snapshot, for assertions.
func crossAgentSources(rec *taintRecorder) []session.TaintSourceRef {
	var out []session.TaintSourceRef
	for _, s := range rec.RiskSnapshot().Sources {
		if s.Kind == session.TaintSourceKindCrossAgent {
			out = append(out, s)
		}
	}
	return out
}

// contaminateRecorder marks the session externally untrusted. promptHit
// escalates the folded level to hostile, matching a prompt-injection ingest.
func contaminateRecorder(rec *taintRecorder, promptHit bool) {
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://attacker.example/inject",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
		PromptHit:  promptHit,
		MaxSources: 10,
	})
}

const toolsCallReadMsg = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_files","arguments":{}}}`

// Done-state #1: a contaminated session emitting an MCP tool call records a
// cross_agent taint source and keeps the session contaminated.
func TestEvaluateMCPInputGates_CrossAgentToolCallRecordsTaint(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	contaminateRecorder(rec, false)

	msg := []byte(toolsCallReadMsg)
	frame := ParseMCPFrame(msg)
	eval := EvaluateMCPInputGates(context.Background(), frame, msg, "sess-1",
		MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint},
		config.ActionWarn, config.ActionBlock, true)

	if !rec.RiskSnapshot().Contaminated {
		t.Fatal("session must remain contaminated")
	}
	srcs := crossAgentSources(rec)
	if len(srcs) != 1 {
		t.Fatalf("want 1 cross_agent source, got %d", len(srcs))
	}
	if srcs[0].MatchReason != "cross_agent_mcp_tool_call" {
		t.Fatalf("match reason = %q, want cross_agent_mcp_tool_call", srcs[0].MatchReason)
	}
	// Untrusted (non-hostile) propagation records evidence but does not escalate.
	if eval.CrossAgentEscalate {
		t.Fatal("untrusted propagation must not request escalation")
	}
}

// Done-state #2: hostile cross-agent propagation requests adaptive escalation.
func TestEvaluateMCPInputGates_CrossAgentHostileEscalates(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	contaminateRecorder(rec, true) // promptHit -> hostile

	msg := []byte(toolsCallReadMsg)
	frame := ParseMCPFrame(msg)
	eval := EvaluateMCPInputGates(context.Background(), frame, msg, "sess-1",
		MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint},
		config.ActionWarn, config.ActionBlock, true)

	if !eval.CrossAgentEscalate {
		t.Fatal("hostile propagation must request escalation")
	}
	if len(crossAgentSources(rec)) != 1 {
		t.Fatal("hostile propagation must still record evidence")
	}
}

// A2A parity: a contaminated session emitting an A2A request records a
// cross_agent source tagged with the a2a_request boundary.
func TestEvaluateMCPInputGates_CrossAgentA2ARequest(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	cfg.A2AScanning.Enabled = true
	rec := &taintRecorder{}
	contaminateRecorder(rec, false)

	// Clean A2A SendMessage body so no content gate interferes.
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"parts":[{"text":"hello peer"}]}}}`)
	frame := ParseMCPFrame(msg)
	_ = EvaluateMCPInputGates(context.Background(), frame, msg, "sess-1",
		MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint, A2ACfg: &cfg.A2AScanning},
		config.ActionWarn, config.ActionWarn, true)

	srcs := crossAgentSources(rec)
	if len(srcs) != 1 {
		t.Fatalf("want 1 cross_agent source, got %d", len(srcs))
	}
	if srcs[0].MatchReason != "cross_agent_a2a_request" {
		t.Fatalf("match reason = %q, want cross_agent_a2a_request", srcs[0].MatchReason)
	}
}

// stdio parity: the stdio gate records cross-agent taint on a tool call.
func TestEvaluateMCPInputGatesStdio_CrossAgentToolCall(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	contaminateRecorder(rec, false)

	msg := []byte(toolsCallReadMsg)
	frame := ParseMCPFrame(msg)
	_ = EvaluateMCPInputGatesStdio(context.Background(), frame, msg, msg, nil,
		MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint},
		config.ActionWarn, config.ActionBlock)

	srcs := crossAgentSources(rec)
	if len(srcs) != 1 || srcs[0].MatchReason != "cross_agent_mcp_tool_call" {
		t.Fatalf("stdio cross-agent source = %+v", srcs)
	}
}

// Done-state #5b: taint laundering — clean intermediary hops do NOT reset
// contamination. After a hostile ingest, repeated clean tool calls keep the
// session contaminated at hostile level and preserve the cross_agent evidence.
func TestEvaluateMCPInputGates_CrossAgentLaunderingDoesNotResetTaint(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	contaminateRecorder(rec, true) // hostile

	msg := []byte(toolsCallReadMsg)
	frame := ParseMCPFrame(msg)
	for i := 0; i < 5; i++ {
		_ = EvaluateMCPInputGates(context.Background(), frame, msg, "sess-1",
			MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint},
			config.ActionWarn, config.ActionBlock, true)
	}

	snap := rec.RiskSnapshot()
	if !snap.Contaminated {
		t.Fatal("contamination must survive clean intermediary hops")
	}
	if snap.Level != session.TaintExternalHostile {
		t.Fatalf("level = %v, want hostile preserved (no laundering)", snap.Level)
	}
	// Consecutive same-boundary refs dedupe to bound source-list dilution.
	if got := len(crossAgentSources(rec)); got != 1 {
		t.Fatalf("cross_agent refs = %d, want 1 (deduped)", got)
	}
}

// Done-state #2 (HTTP caller end-to-end): driving a hostile-contaminated
// session through the full scanHTTPInput path records the cross-agent
// escalation signal on the adaptive recorder.
func TestScanHTTPInput_CrossAgentEscalationFires(t *testing.T) {
	t.Parallel()
	sc := newAdaptiveTestScanner()
	defer sc.Close()
	cfg := config.Defaults()
	rec := &signalRiskRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://attacker.example/inject",
			Kind:  "http_response",
			Level: session.TaintExternalHostile,
		},
		MaxSources: 10,
	})

	var logBuf bytes.Buffer
	msg := []byte(toolsCallReadMsg)
	_ = scanHTTPInput(msg, &logBuf, "sess-1", "sess-1", MCPProxyOpts{
		Scanner:     sc,
		InputCfg:    newHTTPInputCfg(config.ActionWarn),
		Rec:         rec,
		AdaptiveCfg: adaptiveCfgEnabled(),
		TaintCfg:    &cfg.Taint,
	})

	if !rec.hasSignal(session.SignalCrossAgentContamination) {
		t.Fatal("hostile cross-agent emit must record SignalCrossAgentContamination through the HTTP caller")
	}
}

// Done-state #2 (stdio caller end-to-end): driving a hostile-contaminated
// session through the full ForwardScannedInput path records the cross-agent
// escalation signal on the adaptive recorder.
func TestForwardScannedInput_CrossAgentEscalationFires(t *testing.T) {
	t.Parallel()
	sc := newAdaptiveTestScanner()
	defer sc.Close()
	cfg := config.Defaults()
	rec := &signalRiskRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://attacker.example/inject",
			Kind:  "http_response",
			Level: session.TaintExternalHostile,
		},
		MaxSources: 10,
	})

	var serverBuf, logBuf bytes.Buffer
	blockedCh := make(chan BlockedRequest, 20)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(toolsCallReadMsg+"\n")),
		transport.NewStdioWriter(&serverBuf),
		&logBuf,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil, // bindingCfg
		nil, // tracker
		MCPProxyOpts{Scanner: sc, Rec: rec, AdaptiveCfg: adaptiveCfgEnabled(), TaintCfg: &cfg.Taint},
	)

	if !rec.hasSignal(session.SignalCrossAgentContamination) {
		t.Fatal("hostile cross-agent emit must record SignalCrossAgentContamination through the stdio caller")
	}
}

// Regression: cross-agent evidence + escalation must be recorded even when a
// LATER short-circuit gate (here DoW) blocks the tool call. The contaminated
// session still attempted cross-agent propagation, which is the security event.
func TestEvaluateMCPInputGates_CrossAgentRecordedWhenLaterGateBlocks(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	contaminateRecorder(rec, true) // hostile

	// A DoW check that blocks every tool call — runs after the cross-agent
	// observe and short-circuits the evaluation.
	dow := func(_, _ string) (bool, string, string, string) {
		return false, config.ActionBlock, "dow: budget exceeded", "calls"
	}

	msg := []byte(toolsCallReadMsg)
	frame := ParseMCPFrame(msg)
	eval := EvaluateMCPInputGates(context.Background(), frame, msg, "sess-1",
		MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint, DoWCheck: dow},
		config.ActionWarn, config.ActionBlock, true)

	if eval.BlockingGate != blockingGateDoW {
		t.Fatalf("expected DoW block, got %q", eval.BlockingGate)
	}
	if len(crossAgentSources(rec)) != 1 {
		t.Fatal("cross_agent evidence must be recorded even when a later gate blocks")
	}
	if !eval.CrossAgentEscalate {
		t.Fatal("hostile cross-agent escalation must be set even when a later gate blocks")
	}
}

// stdio parity for the later-gate-block regression.
func TestEvaluateMCPInputGatesStdio_CrossAgentRecordedWhenLaterGateBlocks(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	contaminateRecorder(rec, true) // hostile

	dow := func(_, _ string) (bool, string, string, string) {
		return false, config.ActionBlock, "dow: budget exceeded", "calls"
	}

	msg := []byte(toolsCallReadMsg)
	frame := ParseMCPFrame(msg)
	eval := EvaluateMCPInputGatesStdio(context.Background(), frame, msg, msg, nil,
		MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint, DoWCheck: dow},
		config.ActionWarn, config.ActionBlock)

	if eval.BlockingGate != blockingGateDoW {
		t.Fatalf("expected DoW block, got %q", eval.BlockingGate)
	}
	if len(crossAgentSources(rec)) != 1 {
		t.Fatal("cross_agent evidence must be recorded even when a later gate blocks (stdio)")
	}
	if !eval.CrossAgentEscalate {
		t.Fatal("hostile cross-agent escalation must be set even when a later gate blocks (stdio)")
	}
}

// Control: a clean (uncontaminated) session never records cross-agent taint.
func TestEvaluateMCPInputGates_CleanSessionNoCrossAgent(t *testing.T) {
	t.Parallel()
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}

	msg := []byte(toolsCallReadMsg)
	frame := ParseMCPFrame(msg)
	eval := EvaluateMCPInputGates(context.Background(), frame, msg, "sess-1",
		MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint},
		config.ActionWarn, config.ActionBlock, true)

	if len(crossAgentSources(rec)) != 0 {
		t.Fatal("clean session must not record cross-agent taint")
	}
	if eval.CrossAgentEscalate {
		t.Fatal("clean session must not request escalation")
	}
}
