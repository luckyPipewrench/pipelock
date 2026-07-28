// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A routing header names what the upstream will act on. When the body carries
// no comparable value, that is not agreement: Pipelock has nothing to scan or
// apply policy to while the upstream still routes on the header. Treating a
// missing body value as agreement is a fail-open, not a tolerance.
func TestHTTPListener_RoutingHeaderWithoutComparableBodyValue(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})

	post := func(body string, headers map[string]string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	t.Run("tools/call naming a tool the body does not", func(t *testing.T) {
		before := upstreamCalls.Load()
		got := post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`,
			map[string]string{listenerMCPMethod: "tools/call", listenerMCPName: "dangerous_tool"})
		if got != http.StatusBadRequest {
			t.Errorf("status = %d, want 400: upstream would route dangerous_tool while Pipelock saw no tool", got)
		}
		if reached := upstreamCalls.Load() - before; reached != 0 {
			t.Errorf("%d request(s) reached upstream, want 0", reached)
		}
	})

	t.Run("method header against a body with no method", func(t *testing.T) {
		before := upstreamCalls.Load()
		got := post(`{"jsonrpc":"2.0","id":1,"result":{}}`,
			map[string]string{listenerMCPMethod: "tools/call"})
		if got != http.StatusBadRequest {
			t.Errorf("status = %d, want 400: header names a method the body does not carry", got)
		}
		if reached := upstreamCalls.Load() - before; reached != 0 {
			t.Errorf("%d request(s) reached upstream, want 0", reached)
		}
	})

	// A single routing header cannot describe several calls. Batches are
	// refused earlier today, so this is defence in depth: if batch support
	// ever lands, the agreement invariant must not already be exempt.
	t.Run("batch carrying a routing header", func(t *testing.T) {
		if !routingHeaderMatchesFrame(http.Header{}, MCPFrame{IsBatch: true}) {
			t.Error("batch with no routing header should be left to the batch handler")
		}
		hdr := http.Header{}
		hdr.Set(listenerMCPMethod, "tools/call")
		if routingHeaderMatchesFrame(hdr, MCPFrame{IsBatch: true}) {
			t.Error("batch carrying a routing header must not be treated as agreeing")
		}
	})
}

// trustedDoWSubjectKey returned an empty key on a below-minimum grade whether or
// not enforcement was on, while the gate only fail-closes on an empty key when
// enforcement IS on. With denial-of-wallet live but enforcement off, that
// combination billed the request to the manager's shared bucket, which is the
// precise outcome the empty key exists to prevent: one caller spending
// everyone else's allowance.
func TestTrustedDoWSubjectKeyNeverBlanksSubjectWithEnforcementOff(t *testing.T) {
	opts := MCPProxyOpts{
		DoWEnforceSubjectTrust: false,
		DoWMinSubjectTrust:     config.DoWTrustPrincipal,
		DoWSubjectAgent:        "agent-a",
		DoWCheck: func(string, string, string) (bool, string, string, string) {
			return true, config.ActionBlock, "", ""
		},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.10:5555"

	if got := trustedDoWSubjectKey(req, opts); got == "" {
		t.Fatal("empty subject key with enforcement off: the gate will not refuse it, so it bills the shared bucket")
	}
}
