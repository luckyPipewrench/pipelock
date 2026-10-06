// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const contractRefusedPolicyHash = mcpTestPolicyHash

// contractRefusedLoaderFn returns no loader for the startup gate, so the proxy
// starts, and from then on a loader whose tool rule admits the call while its
// HTTP rules do not cover the upstream. That is a contract promoted while the
// session runs: the input scan allows the call and writes its intent, then the
// per-message upstream gate refuses it. withHTTPRules=false leaves the upstream
// gate nothing to evaluate against and makes it fail instead of deny.
func contractRefusedLoaderFn(t *testing.T, withHTTPRules bool) func() *contractruntime.Loader {
	t.Helper()
	loader := mcpLiveLockLoader(t, contractruntime.ModeLive, mcpToolRule("r-allow", nil))
	if withHTTPRules {
		loader = mcpLiveLockLoader(t, contractruntime.ModeLive,
			mcpToolRule("r-allow", nil),
			contractruntimetest.HTTPEnforceRule("r-other", "api.vendor.example", "/", http.MethodPost))
	}
	var calls atomic.Int32
	return func() *contractruntime.Loader {
		if calls.Add(1) == 1 {
			return nil
		}
		return loader
	}
}

func contractRefusedOpts(t *testing.T, h *mcpDecisionReceiptHarness, withHTTPRules bool) MCPProxyOpts {
	t.Helper()
	opts := MCPProxyOpts{
		ContractLoaderFn: contractRefusedLoaderFn(t, withHTTPRules),
		ContractAgent:    mcpLiveLockAgent,
		ContractServer:   mcpLiveLockServer,
		ReceiptEmitter:   h.v1,
		V2ReceiptEmitter: h.v2,
		RequireReceipts:  true,
		PolicyHash:       contractRefusedPolicyHash,
	}
	if withHTTPRules {
		opts.Scanner = testScannerForHTTP(t)
	}
	return opts
}

// assertContractRefusedChain checks the v1 chain holds exactly one allowed
// intent for the refused call and one blocked outcome under the same action
// ID, with no allow outcome, and returns that action ID.
func assertContractRefusedChain(t *testing.T, records []receipt.Receipt, wantReason string) string {
	t.Helper()
	var intent, outcome *receipt.ActionRecord
	for i := range records {
		ar := &records[i].ActionRecord
		t.Logf("record %d: action=%s phase=%q verdict=%s layer=%s pattern=%q rule=%q", i, ar.ActionID, ar.DecisionPhase, ar.Verdict, ar.Layer, ar.Pattern, ar.ContractRuleID)
		switch ar.DecisionPhase {
		case receipt.DecisionPhaseIntent:
			if intent != nil {
				t.Fatalf("more than one intent receipt")
			}
			intent = ar
		case receipt.DecisionPhaseOutcome:
			if outcome != nil {
				t.Fatalf("more than one outcome receipt")
			}
			outcome = ar
		default:
			t.Fatalf("unexpected record without intent/outcome phase: %+v", *ar)
		}
	}
	if intent == nil || outcome == nil {
		t.Fatalf("intent=%v outcome=%v, want both", intent != nil, outcome != nil)
	}
	if intent.Verdict != config.ActionAllow {
		t.Fatalf("intent verdict = %s, want allow", intent.Verdict)
	}
	if outcome.ActionID != intent.ActionID {
		t.Fatalf("outcome action %s does not close intent %s", outcome.ActionID, intent.ActionID)
	}
	if outcome.Verdict != config.ActionBlock {
		t.Fatalf("outcome verdict = %s, want block for a call that was never sent", outcome.Verdict)
	}
	if outcome.Layer != mcpContractReceiptLayer {
		t.Fatalf("outcome layer = %q, want %q", outcome.Layer, mcpContractReceiptLayer)
	}
	if !strings.Contains(outcome.Pattern, "status=blocked") || !strings.Contains(outcome.Pattern, "reason="+wantReason) {
		t.Fatalf("outcome pattern = %q, want status=blocked and reason=%s", outcome.Pattern, wantReason)
	}
	return intent.ActionID
}

// v2Verdicts closes the recorder and returns the proxy_decision verdicts in
// chain order.
func v2Verdicts(t *testing.T, h *mcpDecisionReceiptHarness) []string {
	t.Helper()
	var out []string
	for _, r := range mcpV2Receipts(t, h) {
		var payload struct {
			Verdict string `json:"verdict"`
		}
		if err := json.Unmarshal(r.Payload, &payload); err != nil {
			t.Fatalf("unmarshal v2 payload: %v", err)
		}
		out = append(out, payload.Verdict)
	}
	return out
}

func TestRunHTTPProxyLiveLock_PerMessageUpstreamDenialRecordsBlockedOutcome(t *testing.T) {
	for _, tc := range []struct {
		name          string
		message       string
		withHTTPRules bool
		wantReason    string
		wantResponse  bool
	}{
		{
			name:          "request denied",
			message:       mcpToolCall(mcpAllowedTool, ""),
			withHTTPRules: true,
			wantReason:    mcpContractDeniedReason,
			wantResponse:  true,
		},
		{
			name:          "request gate evaluation failed",
			message:       mcpToolCall(mcpAllowedTool, ""),
			withHTTPRules: false,
			wantReason:    mcpContractEvaluationFailedReason,
			wantResponse:  true,
		},
		{
			// A tool call sent as a notification still executes upstream, so
			// its intent is recorded and must be closed even though no
			// response may be written.
			name:          "notification denied",
			message:       `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + mcpAllowedTool + `","arguments":{}}}`,
			withHTTPRules: true,
			wantReason:    mcpContractDeniedReason,
		},
		{
			name:          "notification gate evaluation failed",
			message:       `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + mcpAllowedTool + `","arguments":{}}}`,
			withHTTPRules: false,
			wantReason:    mcpContractEvaluationFailedReason,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				upstreamHits.Add(1)
			}))
			defer upstream.Close()

			h := newMCPDecisionReceiptHarness(t)
			var stdout, stderr strings.Builder
			err := RunHTTPProxy(context.Background(), strings.NewReader(tc.message+"\n"), &stdout, &stderr, upstream.URL, nil,
				contractRefusedOpts(t, h, tc.withHTTPRules))
			if err != nil {
				t.Fatalf("RunHTTPProxy: %v", err)
			}
			if upstreamHits.Load() != 0 {
				t.Fatalf("upstream hits = %d, want 0", upstreamHits.Load())
			}
			if strings.Contains(stderr.String(), "receipt emission failed") {
				t.Fatalf("receipt emission failed: %s", stderr.String())
			}
			if got := strings.TrimSpace(stdout.String()) != ""; got != tc.wantResponse {
				t.Fatalf("client response written = %v, want %v: %s", got, tc.wantResponse, stdout.String())
			}
			if got := strings.Join(v2Verdicts(t, h), ","); got != "allow,block" {
				t.Fatalf("v2 verdicts = %s, want allow,block", got)
			}
			assertContractRefusedChain(t, readActionReceipts(t, h.dir), tc.wantReason)
		})
	}
}

func TestRunHTTPListenerProxyLiveLock_PerRequestUpstreamDenialClosesIntent(t *testing.T) {
	for _, tc := range []struct {
		name          string
		withHTTPRules bool
		wantReason    string
		wantBlock     blockreason.Reason
	}{
		// The listener refuses a request before the gate when no scanner is
		// configured, so the gate's only evaluation error is unreachable here;
		// both gate branches share emitListenerBlockDecision and its intent.
		{name: "denied", withHTTPRules: true, wantReason: mcpContractDeniedReason, wantBlock: blockreason.ContractDefaultDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				upstreamHits.Add(1)
			}))
			defer upstream.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			h := newMCPDecisionReceiptHarness(t)
			var logs syncBuffer
			done := make(chan error, 1)
			go func() {
				done <- RunHTTPListenerProxy(ctx, ln, upstream.URL, &logs, contractRefusedOpts(t, h, tc.withHTTPRules))
			}()
			stopped := false
			stop := func() {
				if stopped {
					return
				}
				stopped = true
				cancel()
				_ = ln.Close()
				<-done
			}
			t.Cleanup(stop)

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String(), strings.NewReader(mcpToolCall(mcpAllowedTool, "")))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			data := decodeRPCError(t, string(body))
			if got := data[mcpBlockReasonKey]; got != string(tc.wantBlock) {
				t.Fatalf("%s = %v, want %s", mcpBlockReasonKey, got, tc.wantBlock)
			}
			if upstreamHits.Load() != 0 {
				t.Fatalf("upstream hits = %d, want 0", upstreamHits.Load())
			}
			stop()
			if strings.Contains(logs.String(), "receipt emission failed") {
				t.Fatalf("receipt emission failed: %s", logs.String())
			}
			if got := strings.Join(v2Verdicts(t, h), ","); got != "allow,block" {
				t.Fatalf("v2 verdicts = %s, want allow,block", got)
			}
			actionID := assertContractRefusedChain(t, readActionReceipts(t, h.dir), tc.wantReason)
			if got := resp.Header.Get(blockreason.HeaderReceipt); got != actionID {
				t.Fatalf("block header receipt = %q, want the refused call's action %q", got, actionID)
			}
		})
	}
}

// TestEmitMCPOutcomeV2Only covers a setup with only the v2 emitter: the
// outcome that closes an intent must still be recorded, for a sent call and
// for a refused one.
func TestEmitMCPOutcomeV2Only(t *testing.T) {
	opts := receipt.EmitOpts{
		ActionID:   "mcp-v2-only-outcome",
		Transport:  transportMCPStdio,
		Target:     mcpAllowedTool,
		MCPMethod:  methodToolsCall,
		ToolName:   mcpAllowedTool,
		PolicyHash: mcpTestPolicyHash,
	}
	for _, tc := range []struct {
		name string
		emit func(*mcpDecisionReceiptHarness, io.Writer)
		want string
	}{
		{
			name: "sent",
			emit: func(h *mcpDecisionReceiptHarness, logW io.Writer) {
				emitMCPOutcomeReceipt(nil, h.v2, logW, opts, "200", 10, "complete")
			},
			want: config.ActionAllow,
		},
		{
			name: "refused",
			emit: func(h *mcpDecisionReceiptHarness, logW io.Writer) {
				refused := opts
				refused.Layer = mcpContractReceiptLayer
				emitMCPBlockedOutcomeReceipt(nil, h.v2, logW, refused, 0, mcpContractDeniedReason, true)
			},
			want: config.ActionBlock,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMCPDecisionReceiptHarness(t)
			var logs strings.Builder
			tc.emit(h, &logs)
			if logs.Len() != 0 {
				t.Fatalf("emit logged: %s", logs.String())
			}
			if got := strings.Join(v2Verdicts(t, h), ","); got != tc.want {
				t.Fatalf("v2 verdicts = %q, want %q", got, tc.want)
			}
		})
	}
}
