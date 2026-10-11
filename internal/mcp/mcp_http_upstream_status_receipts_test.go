// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestHTTPListener_UpstreamRefusalClosesIntent(t *testing.T) {
	const errorBody = `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid request"}}`
	tests := []struct {
		name, body         string
		status, wantStatus int
	}{
		{"200 control", errorBody, http.StatusOK, http.StatusOK},
		{"400 correlated error", errorBody, http.StatusBadRequest, http.StatusBadRequest},
		{"401 OAuth error", `{"error":"invalid_token"}`, http.StatusUnauthorized, http.StatusUnauthorized},
		{"withheld injection", `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"` + upstreamStatusInjection + `"}}`, http.StatusBadRequest, http.StatusBadGateway},
		{"withheld body encoding", string([]byte{0xff}), http.StatusBadRequest, http.StatusBadGateway},
		{"withheld framing", `{"jsonrpc":"2.0","id":999,"error":{"code":-32600,"message":"wrong ID"}}`, http.StatusBadRequest, http.StatusBadGateway},
		{"withheld 407", `{"error":"proxy credentials required"}`, http.StatusProxyAuthRequired, http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newMCPDecisionReceiptHarness(t)
			upstream := newUpstreamStatusServer(t, upstreamStatusReply{status: tt.status, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(tt.body)})
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
				Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock),
				ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2, PolicyHash: mcpTestPolicyHash, RequireReceipts: true,
			})
			resp, body := doListenerRequest(t, http.MethodPost, baseURL+"/", jsonToolsCallEcho, nil)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", resp.StatusCode, body, tt.wantStatus)
			}
			if err := h.rec.Close(); err != nil {
				t.Fatal(err)
			}
			var intentID string
			outcomes := 0
			for _, r := range readActionReceipts(t, h.dir) {
				switch r.ActionRecord.DecisionPhase {
				case receipt.DecisionPhaseIntent:
					intentID = r.ActionRecord.ActionID
				case receipt.DecisionPhaseOutcome:
					outcomes++
					if r.ActionRecord.ActionID != intentID || intentID == "" {
						t.Fatalf("outcome does not pair with intent: %+v", r.ActionRecord)
					}
					if !strings.Contains(r.ActionRecord.Pattern, "status=error") || strings.Contains(r.ActionRecord.Pattern, upstreamStatusInjection) {
						t.Fatalf("outcome did not record a sanitized error: %s", r.ActionRecord.Pattern)
					}
				}
			}
			if intentID == "" || outcomes != 1 {
				t.Fatalf("upstream status %d: intent=%q outcomes=%d, want one paired outcome", tt.status, intentID, outcomes)
			}
		})
	}
}

// A notification is never tracked, so a failed send closes its intent from the
// input decision directly instead of leaving it unpaired.
func TestRunHTTPProxy_FailedNotificationClosesIntent(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	upstream := newUpstreamStatusServer(t, upstreamStatusReply{status: http.StatusBadRequest, header: http.Header{"Content-Type": {"text/plain"}}, body: []byte("refused")})
	notification := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	var stdout, stderr bytes.Buffer
	err := RunHTTPProxy(context.Background(), strings.NewReader(notification+"\n"), &stdout, &stderr, upstream.URL, nil, MCPProxyOpts{
		Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock),
		ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2, PolicyHash: mcpTestPolicyHash, RequireReceipts: true,
	})
	if err != nil {
		t.Fatalf("RunHTTPProxy: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("stdout = %q, want no reply to a notification", stdout.String())
	}
	if err := h.rec.Close(); err != nil {
		t.Fatal(err)
	}
	var intentID string
	outcomes := 0
	for _, r := range readActionReceipts(t, h.dir) {
		switch r.ActionRecord.DecisionPhase {
		case receipt.DecisionPhaseIntent:
			intentID = r.ActionRecord.ActionID
		case receipt.DecisionPhaseOutcome:
			outcomes++
			if r.ActionRecord.ActionID != intentID || !strings.Contains(r.ActionRecord.Pattern, "status=error") {
				t.Fatalf("outcome does not close the intent with an error: %+v", r.ActionRecord)
			}
		}
	}
	if intentID == "" || outcomes != 1 {
		t.Fatalf("intent=%q outcomes=%d, want one paired outcome", intentID, outcomes)
	}
}
