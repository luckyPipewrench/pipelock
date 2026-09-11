// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// cleanToolsCallRequest is a benign tools/call that passes input scanning, so the
// only thing standing between the request and the upstream is the receipt gate.
const cleanToolsCallRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`

const cleanToolsCallResponse = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`

// receiptBoundaryUpstream returns an httptest-style handler that counts hits and
// answers a tools/call with either a JSON or an SSE response. The hit counter is
// the ordering probe: an upstream hit can only happen AFTER the listener's
// require_receipts gate ran, because the gate is inside scanHTTPInputDecision,
// which returns before the listener builds or sends the upstream request.
func receiptBoundaryUpstream(hits *atomic.Int32, sse bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: " + cleanToolsCallResponse + "\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, cleanToolsCallResponse)
	}
}

func postToolsCall(t *testing.T, baseURL string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(cleanToolsCallRequest))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return resp.StatusCode, string(body)
}

// TestHTTPListener_RequireReceiptsGatesUpstreamForward proves the require_receipts
// fail-closed gate precedes the upstream forward at the MCP HTTP reverse listener
// boundary: a clean tools/call reaches the upstream only when its required
// receipt records, and the recorder's failure (or an absent emitter) blocks the
// forward. With require_receipts off, a failing recorder stays best-effort and
// the request still forwards (the documented availability behavior). The upstream
// hit counter is the ordering witness - it is non-zero only when the gate passed.
func TestHTTPListener_RequireReceiptsGatesUpstreamForward(t *testing.T) {
	tests := []struct {
		name            string
		requireReceipts bool
		withEmitter     bool
		closeRecorder   bool // simulate a failing recorder
		wantForwarded   bool
	}{
		{name: "require on, working emitter, forwards after receipt", requireReceipts: true, withEmitter: true, wantForwarded: true},
		{name: "require on, emitter absent, fails closed", requireReceipts: true, withEmitter: false, wantForwarded: false},
		{name: "require on, recorder failing, fails closed", requireReceipts: true, withEmitter: true, closeRecorder: true, wantForwarded: false},
		{name: "require off, recorder failing, still forwards", requireReceipts: false, withEmitter: true, closeRecorder: true, wantForwarded: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(receiptBoundaryUpstream(&hits, false))
			defer upstream.Close()

			opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), RequireReceipts: tt.requireReceipts}
			var rec interface{ Close() error }
			var dir string
			if tt.withEmitter {
				emitter, r, d, _ := newReceiptTestHarness(t)
				opts.ReceiptEmitter = emitter
				rec, dir = r, d
				if tt.closeRecorder {
					if err := r.Close(); err != nil {
						t.Fatalf("recorder.Close: %v", err)
					}
				}
			}

			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			status, body := postToolsCall(t, baseURL)

			if tt.wantForwarded {
				if hits.Load() != 1 {
					t.Fatalf("upstream hits = %d, want 1 (request should have forwarded)", hits.Load())
				}
				if !strings.Contains(body, "ok") {
					t.Fatalf("forwarded response missing upstream result: status=%d body=%s", status, body)
				}
			} else {
				if hits.Load() != 0 {
					t.Fatalf("upstream hits = %d, want 0 (gate must block before forward)", hits.Load())
				}
				if strings.Contains(body, `"result"`) {
					t.Fatalf("blocked request leaked an upstream result: body=%s", body)
				}
			}

			// Case (a): confirm a receipt actually recorded, so "forwarded" means
			// "forwarded after a durable receipt" rather than "forwarded, receipt
			// unknown". A closed recorder records nothing.
			if tt.withEmitter && !tt.closeRecorder && rec != nil {
				_ = rec.Close()
				if got := len(readActionReceipts(t, dir)); got == 0 {
					t.Fatal("require_receipts forward recorded no receipt")
				}
			}
		})
	}
}

// TestHTTPListener_RequireReceiptsGatesSSEUpstreamForward is the SSE-response
// boundary: the same require_receipts gate precedes the forward even when the
// upstream answers as text/event-stream. The gate runs on the request before the
// response transport is known, so a clean forward reaches the SSE upstream only
// after its receipt records. The fail-closed directions are response-type
// independent (the upstream is never contacted) and are covered by the JSON table
// above; this pins the one case where the response transport differs.
func TestHTTPListener_RequireReceiptsGatesSSEUpstreamForward(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(receiptBoundaryUpstream(&hits, true))
	defer upstream.Close()

	emitter, rec, dir, _ := newReceiptTestHarness(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:         testScannerForHTTP(t),
		RequireReceipts: true,
		ReceiptEmitter:  emitter,
	})

	status, body := postToolsCall(t, baseURL)
	if hits.Load() != 1 {
		t.Fatalf("SSE upstream hits = %d, want 1", hits.Load())
	}
	if !strings.Contains(body, "ok") {
		t.Fatalf("SSE forward missing upstream result: status=%d body=%s", status, body)
	}
	_ = rec.Close()
	if got := len(readActionReceipts(t, dir)); got == 0 {
		t.Fatal("require_receipts SSE forward recorded no receipt")
	}
}
