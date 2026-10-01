// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// killSwitchDenialCases is shared by the WebSocket proxy and HTTP listener
// tests: a refused tool call or A2A request is receipted, while tools/list and
// notifications are not, matching stdio and the HTTP forward bridge.
var killSwitchDenialCases = []struct {
	name       string
	line       string
	wantTarget string
}{
	{"tools/call", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"x"}}}`, "read_file"},
	{"a2a request", `{"jsonrpc":"2.0","id":9,"method":"message/send","params":{}}`, "message/send"},
	{"tools/list", `{"jsonrpc":"2.0","id":8,"method":"tools/list"}`, ""},
	{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, ""},
}

func killSwitchDenialController() *killswitch.Controller {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "test kill"
	return killswitch.New(cfg)
}

func requireKillSwitchDenialReceipts(t *testing.T, got *allReceipts, wantTarget string) {
	t.Helper()
	recs := got.snapshot()
	if wantTarget == "" {
		if len(recs) != 0 {
			t.Fatalf("receipts = %+v, want none", recs)
		}
		return
	}
	if len(recs) != 1 {
		t.Fatalf("receipts = %d, want exactly one kill-switch block", len(recs))
	}
	rec := recs[0]
	if rec.Verdict != config.ActionBlock || rec.Layer != mcpReceiptLayerKillSwitch || rec.Target != wantTarget {
		t.Fatalf("receipt = verdict %q layer %q target %q, want block %q %q",
			rec.Verdict, rec.Layer, rec.Target, mcpReceiptLayerKillSwitch, wantTarget)
	}
}

func TestWSProxyKillSwitchDenialIsReceipted(t *testing.T) {
	for _, tt := range killSwitchDenialCases {
		t.Run(tt.name, func(t *testing.T) {
			srv, upstreamFrames := wsDrainServer(t)
			defer srv.Close()

			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := RunWSProxy(ctx, strings.NewReader(tt.line+"\n"), &stdout, &stderr, wsURL(srv), MCPProxyOpts{
				Scanner: testInputScanner(t), ReceiptEmitter: emitter, KillSwitch: killSwitchDenialController(),
			})
			if err != nil {
				t.Fatalf("RunWSProxy: %v", err)
			}
			if n := upstreamFrames.Load(); n != 0 {
				t.Fatalf("killed message reached upstream (%d frames)", n)
			}
			requireKillSwitchDenialReceipts(t, got, tt.wantTarget)
		})
	}
}

func TestHTTPListenerKillSwitchDenialIsReceipted(t *testing.T) {
	for _, tt := range killSwitchDenialCases {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				upstreamCalls.Add(1)
			}))
			defer upstream.Close()

			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
				Scanner: testScannerForHTTP(t), ReceiptEmitter: emitter, KillSwitch: killSwitchDenialController(),
			})

			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(tt.line))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if _, err := io.ReadAll(resp.Body); err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if n := upstreamCalls.Load(); n != 0 {
				t.Fatalf("killed message reached upstream (%d calls)", n)
			}
			requireKillSwitchDenialReceipts(t, got, tt.wantTarget)
		})
	}
}
