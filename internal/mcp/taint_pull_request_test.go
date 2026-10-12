// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestPullRequestReadTaintConsumers(t *testing.T) {
	for _, transport := range []string{transportMCPStdio, transportMCPHTTP} {
		for _, tc := range []struct {
			tool, args string
			class      session.ActionClass
			policy     session.PolicyDecision
		}{
			{"list_pull_requests", `{"owner":"example","repo":"example"}`, session.ActionClassRead, session.PolicyAllow},
			{"search_pull_requests", `{"query":"repo:example/example"}`, session.ActionClassRead, session.PolicyAllow},
			{"pull_request_read", `{"method":"get","owner":"example","repo":"example","pullNumber":1}`, session.ActionClassRead, session.PolicyAllow},
			{"pull_request_read", `{"method":"DELETE"}`, session.ActionClassPublish, session.PolicyAsk},
			{"request_copilot_review", `{}`, session.ActionClassPublish, session.PolicyAsk},
		} {
			t.Run(transport+"/"+tc.tool+"/"+tc.args, func(t *testing.T) {
				cfg := config.Defaults()
				rec := &taintRecorder{}
				opts := MCPProxyOpts{Scanner: testScannerWithAction(t, config.ActionWarn), Rec: rec, TaintCfg: &cfg.Taint, TaintExternalSource: true, Transport: transport}
				observeMCPResponseTaint(opts, false)
				decision := evaluateMCPTaint(opts, tc.tool, tc.args)
				if decision.ActionClass != tc.class || decision.Result.Decision != tc.policy || !decision.Risk.Contaminated || decision.Risk.Level != session.TaintExternalUntrusted {
					t.Fatalf("unexpected decision: %+v", decision)
				}
				msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tc.tool + `","arguments":` + tc.args + `}}`)
				if transport == transportMCPStdio {
					eval := EvaluateMCPInputGatesStdio(context.Background(), ParseMCPFrame(msg), msg, msg, nil, opts, config.ActionWarn, config.ActionBlock)
					wantGate := ""
					if tc.policy != session.PolicyAllow {
						wantGate = blockingGateTaintAskDenied
					}
					if eval.BlockingGate != wantGate || eval.TaintDecision.ActionClass != tc.class || eval.TaintDecision.Result.Decision != tc.policy {
						t.Fatalf("unexpected stdio enforcement: %+v", eval)
					}
					decision = eval.TaintDecision
				} else {
					blocked := scanHTTPInput(msg, &bytes.Buffer{}, "sess", "sess", opts)
					if (blocked != nil) != (tc.policy != session.PolicyAllow) {
						t.Fatalf("block=%+v, policy=%v", blocked, tc.policy)
					}
					if blocked != nil && blocked.ErrorMessage != "pipelock: external_publish_after_untrusted_external_exposure" {
						t.Fatalf("unexpected denial: %+v", blocked)
					}
				}
				wantCapture := "read"
				if tc.class == session.ActionClassPublish {
					wantCapture = "write"
				}
				if got := captureMCPFrameActionClass(tc.tool, methodToolsCall, tc.args); got != wantCapture {
					t.Fatalf("capture class=%q, want %q", got, wantCapture)
				}
				emitter, _, dir, _ := newReceiptTestHarness(t)
				verdict := config.ActionAllow
				if tc.policy != session.PolicyAllow {
					verdict = config.ActionBlock
				}
				if err := emitMCPToolReceipt(mcpToolReceiptOpts{
					Emitter: emitter, ActionID: "pull-request-decision", MCPMethod: methodToolsCall, ToolName: tc.tool,
					Transport: transport, Verdict: verdict, Decision: decision,
				}); err != nil {
					t.Fatal(err)
				}
				receipts := readActionReceipts(t, dir)
				if len(receipts) != 1 {
					t.Fatalf("receipts=%d, want 1", len(receipts))
				}
				record := receipts[0].ActionRecord
				if record.TaintDecision != tc.policy.String() || record.TaintDecisionReason != decision.Result.Reason || !record.SessionContaminated || record.SessionTaintLevel != session.TaintExternalUntrusted.String() || record.Transport != transport {
					t.Fatalf("receipt lost taint evidence: %+v", record)
				}
			})
		}
	}
}

func TestPullRequestReadTaintOverrides(t *testing.T) {
	cfg := config.Defaults()
	rec := &taintRecorder{}
	opts := MCPProxyOpts{Rec: rec, TaintCfg: &cfg.Taint, TaintExternalSource: true}
	observeMCPResponseTaint(opts, false)
	cfg.Taint.FailSafeClassification = true
	args := `{"method":"get"}`
	if got := evaluateMCPTaint(opts, "pull_request_read", args); got.Result.Decision != session.PolicyAsk || got.Result.Reason != "fail_safe_low_confidence_read_after_untrusted_exposure" {
		t.Fatalf("fail-safe changed: %+v", got)
	}
	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{Scope: "action", ActionMatch: "mcp:pull_request_read", ExpiresAt: nowPlusHour(t)}}
	if got := evaluateMCPTaint(opts, "pull_request_read", args); got.Result.Decision != session.PolicyAllow || got.Result.Reason != "taint_trust_override" {
		t.Fatalf("override lost: %+v", got)
	}
	if got := evaluateMCPTaint(opts, "request_copilot_review", `{}`); got.Result.Decision != session.PolicyAsk {
		t.Fatalf("override broadened: %+v", got)
	}
	cfg.Taint.TrustOverrides = nil
	cfg.Taint.FailSafeClassification = false
	// The tool inventory's hint is not consulted by the taint classifier.
	if got := evaluateMCPTaint(opts, "pull_request_read", `{"method":"DELETE","readOnlyHint":true}`); got.Result.Decision != session.PolicyAsk {
		t.Fatalf("untrusted hint authorized mutation: %+v", got)
	}
}
