// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestPickAttribution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		eval              MCPInputEvaluation
		wantLayer         string
		wantPattern       string
		wantSeverity      string
		wantEmptySeverity bool
	}{
		{
			name: "chain block",
			eval: MCPInputEvaluation{
				BlockingGate:     blockingGateChain,
				ChainPatternName: "tool-bounce",
				ChainSeverity:    config.SeverityCritical,
			},
			wantLayer:    mcpReceiptLayerChain,
			wantPattern:  "tool-bounce",
			wantSeverity: config.SeverityCritical,
		},
		{
			name: "policy match",
			eval: MCPInputEvaluation{
				PolicyVerdict: policy.Verdict{Matched: true, Rules: []string{"dangerous-shell"}},
			},
			wantLayer:    mcpReceiptLayerPolicy,
			wantPattern:  "dangerous-shell",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "binding violation",
			eval: MCPInputEvaluation{
				BindingReason: "session_binding:unknown_tool",
			},
			wantLayer:    mcpReceiptLayerSessionBind,
			wantPattern:  "session_binding:unknown_tool",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "taint block",
			eval: MCPInputEvaluation{
				BlockingGate: blockingGateTaintBlock,
				TaintDecision: taintDecision{
					Result: session.PolicyDecisionResult{
						Decision: session.PolicyBlock,
						Reason:   "protected_write_after_untrusted_external_exposure",
					},
				},
			},
			wantLayer:    mcpReceiptLayerTaint,
			wantPattern:  "protected_write_after_untrusted_external_exposure",
			wantSeverity: config.SeverityCritical,
		},
		{
			name: "content scan fallback",
			eval: MCPInputEvaluation{
				ContentVerdict: InputVerdict{
					Clean: false,
					Matches: []scanner.TextDLPMatch{{
						PatternName: "anthropic-key",
						Severity:    config.SeverityCritical,
					}},
				},
			},
			wantLayer:    mcpReceiptLayerInput,
			wantPattern:  "anthropic-key",
			wantSeverity: config.SeverityCritical,
		},
		{
			name: "a2a body block via BlockingGate",
			eval: MCPInputEvaluation{
				BlockingGate: blockingGateA2ABody,
				A2AResult:    A2AScanResult{Reason: "embedded prompt injection"},
			},
			wantLayer:    mcpReceiptLayerA2A,
			wantPattern:  "embedded prompt injection",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "dow block via BlockingGate",
			eval: MCPInputEvaluation{
				BlockingGate: blockingGateDoW,
				DoWReason:    "budget_exceeded",
			},
			wantLayer:    mcpReceiptLayerDoW,
			wantPattern:  "budget_exceeded",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "frozen tool block",
			eval: MCPInputEvaluation{
				BlockingGate:   blockingGateFrozenTool,
				FrozenToolName: "exec",
			},
			wantLayer:    mcpReceiptLayerToolInventory,
			wantPattern:  "exec",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "parse error block",
			eval: MCPInputEvaluation{
				BlockingGate:   blockingGateParseError,
				ContentVerdict: InputVerdict{Error: "malformed JSON"},
			},
			wantLayer:    mcpReceiptLayerInput,
			wantPattern:  "malformed JSON",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "taint ask denied",
			eval: MCPInputEvaluation{
				BlockingGate: blockingGateTaintAskDenied,
				TaintDecision: taintDecision{
					Result: session.PolicyDecisionResult{
						Decision: session.PolicyAsk,
						Reason:   "high_risk_pending_approval",
					},
				},
			},
			wantLayer:    mcpReceiptLayerTaint,
			wantPattern:  "high_risk_pending_approval",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "a2a fallback when BlockingGate empty",
			eval: MCPInputEvaluation{
				A2AResult: A2AScanResult{Clean: false, Reason: "tool_poisoning"},
			},
			wantLayer:    mcpReceiptLayerA2A,
			wantPattern:  "tool_poisoning",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "dow fallback when BlockingGate empty",
			eval: MCPInputEvaluation{
				DoWAction:  config.ActionBlock,
				DoWAllowed: false,
				DoWReason:  "ratelimit_exceeded",
			},
			wantLayer:    mcpReceiptLayerDoW,
			wantPattern:  "ratelimit_exceeded",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "content scan injection fallback",
			eval: MCPInputEvaluation{
				ContentVerdict: InputVerdict{
					Inject: []scanner.ResponseMatch{{PatternName: "ignore-previous"}},
				},
			},
			wantLayer:    mcpReceiptLayerInput,
			wantPattern:  "ignore-previous",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "content scan address fallback",
			eval: MCPInputEvaluation{
				ContentVerdict: InputVerdict{
					AddressFindings: []addressprotect.Finding{{Explanation: "swapped_btc_addr"}},
				},
			},
			wantLayer:    mcpReceiptLayerInput,
			wantPattern:  "address:swapped_btc_addr",
			wantSeverity: config.SeverityHigh,
		},
		{
			name: "content scan error fallback",
			eval: MCPInputEvaluation{
				ContentVerdict: InputVerdict{Error: "scan_failed"},
			},
			wantLayer:    mcpReceiptLayerInput,
			wantPattern:  "scan_failed",
			wantSeverity: config.SeverityHigh,
		},
		{
			name:              "clean eval",
			eval:              MCPInputEvaluation{ContentVerdict: InputVerdict{Clean: true}},
			wantEmptySeverity: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotLayer, gotPattern, gotSeverity := pickAttribution(tc.eval)
			if gotLayer != tc.wantLayer {
				t.Fatalf("layer = %q, want %q", gotLayer, tc.wantLayer)
			}
			if gotPattern != tc.wantPattern {
				t.Fatalf("pattern = %q, want %q", gotPattern, tc.wantPattern)
			}
			if gotSeverity != tc.wantSeverity {
				t.Fatalf("severity = %q, want %q", gotSeverity, tc.wantSeverity)
			}
			if tc.wantEmptySeverity && gotSeverity != "" {
				t.Fatalf("severity = %q, want empty", gotSeverity)
			}
		})
	}
}

func TestRedactionBlockAttribution(t *testing.T) {
	t.Parallel()
	layer, pattern, severity := redactionBlockAttribution(&redact.BlockError{Reason: redact.ReasonOverflow})
	if layer != mcpReceiptLayerRedaction {
		t.Fatalf("layer = %q, want mcp_input_redaction", layer)
	}
	if pattern != string(redact.ReasonOverflow) {
		t.Fatalf("pattern = %q, want %q", pattern, redact.ReasonOverflow)
	}
	if severity != config.SeverityHigh {
		t.Fatalf("severity = %q, want %q", severity, config.SeverityHigh)
	}

	_, pattern, _ = redactionBlockAttribution(errors.New("plain failure"))
	if pattern != string(redact.ReasonInternalError) {
		t.Fatalf("plain pattern = %q, want %q", pattern, redact.ReasonInternalError)
	}
}

func TestEmitMCPToolReceiptIncludesAttribution(t *testing.T) {
	emitter, _, dir, _ := newReceiptTestHarness(t)
	emitMCPToolReceipt(mcpToolReceiptOpts{
		Emitter:   emitter,
		Transport: transportMCPStdio,
		ActionID:  "mcp-tool-attribution-1",
		MCPMethod: methodToolsCall,
		ToolName:  "shell",
		Verdict:   config.ActionBlock,
		Layer:     mcpReceiptLayerPolicy,
		Pattern:   "dangerous-shell",
		Severity:  config.SeverityHigh,
		Decision: taintDecision{
			Authority: session.AuthorityUserBroad,
			Result: session.PolicyDecisionResult{
				Decision: session.PolicyBlock,
				Reason:   "policy",
			},
		},
	})

	receipts := readActionReceipts(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("receipts = %d, want 1", len(receipts))
	}
	record := receipts[0].ActionRecord
	if record.Layer != mcpReceiptLayerPolicy {
		t.Fatalf("layer = %q, want mcp_tool_policy", record.Layer)
	}
	if record.Pattern != "dangerous-shell" {
		t.Fatalf("pattern = %q, want dangerous-shell", record.Pattern)
	}
	if record.Severity != config.SeverityHigh {
		t.Fatalf("severity = %q, want %q", record.Severity, config.SeverityHigh)
	}
}

func TestEmitMCPToolReceiptLogsV2EmitError(t *testing.T) {
	emitter, _, _, _ := newReceiptTestHarness(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: failingMCPV2Recorder{},
		Signer:   proxydecision.NewKeyedSigner(priv),
	})
	if v2 == nil {
		t.Fatal("expected v2 emitter")
	}

	var log bytes.Buffer
	emitMCPToolReceipt(mcpToolReceiptOpts{
		Emitter:    emitter,
		V2Emitter:  v2,
		Log:        &log,
		Transport:  transportMCPStdio,
		ActionID:   "mcp-tool-v2-error",
		MCPMethod:  methodToolsCall,
		ToolName:   "shell",
		Verdict:    config.ActionBlock,
		Layer:      mcpReceiptLayerPolicy,
		Pattern:    "dangerous-shell",
		Severity:   config.SeverityHigh,
		PolicyHash: mcpTestPolicyHash,
	})
	if !strings.Contains(log.String(), "receipt emission failed") ||
		!strings.Contains(log.String(), "v2 record failed") {
		t.Fatalf("log = %q, want v2 receipt failure", log.String())
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		inputs []string
		want   string
	}{
		{name: "first non-empty", inputs: []string{"a", "b"}, want: "a"},
		{name: "skip empty then return", inputs: []string{"", "b"}, want: "b"},
		{name: "skip whitespace-only then return", inputs: []string{"   ", "\t", "real"}, want: "real"},
		{name: "all empty or whitespace", inputs: []string{"", "  ", "\n"}, want: ""},
		{name: "no inputs", inputs: nil, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := firstNonEmpty(tc.inputs...)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFirstPolicyRule(t *testing.T) {
	t.Parallel()
	if got := firstPolicyRule(nil); got != mcpReceiptPatternPolicyDefault {
		t.Fatalf("nil rules = %q, want %q", got, mcpReceiptPatternPolicyDefault)
	}
	if got := firstPolicyRule([]string{}); got != mcpReceiptPatternPolicyDefault {
		t.Fatalf("empty rules = %q, want %q", got, mcpReceiptPatternPolicyDefault)
	}
	if got := firstPolicyRule([]string{"   "}); got != mcpReceiptPatternPolicyDefault {
		t.Fatalf("whitespace-only rule = %q, want %q", got, mcpReceiptPatternPolicyDefault)
	}
	if got := firstPolicyRule([]string{"shell-exec", "extra"}); got != "shell-exec" {
		t.Fatalf("first concrete rule = %q, want shell-exec", got)
	}
}

func TestTaintReceiptSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dec  session.PolicyDecision
		want string
	}{
		{name: "block maps to critical", dec: session.PolicyBlock, want: config.SeverityCritical},
		{name: "ask maps to high", dec: session.PolicyAsk, want: config.SeverityHigh},
		{name: "allow maps to medium", dec: session.PolicyAllow, want: config.SeverityMedium},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := taintReceiptSeverity(taintDecision{
				Result: session.PolicyDecisionResult{Decision: tc.dec},
			})
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
