// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestHTTPListener_DefaultAllowsStatefulRequestWithoutToken(t *testing.T) {
	var upstreamCalls atomic.Int32
	baseURL := startStatefulListener(t, nil, &upstreamCalls)

	body := postStatefulListenerJSON(t, baseURL, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`)
	if strings.Contains(body, "authenticated principal") {
		t.Fatalf("default listener refused an unauthenticated stateful request: %s", body)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestHTTPListener_DefaultUsesLegacySessionPartitionForStatefulScanning(t *testing.T) {
	var upstreamCalls atomic.Int32
	baseURL := startStatefulListener(t, nil, &upstreamCalls)
	const legacySessionID = "legacy-client-state"

	first := postStatefulListenerJSONWithSession(t, baseURL, "", legacySessionID,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`)
	if strings.Contains(first, "chain pattern") {
		t.Fatalf("first legacy-session request was unexpectedly blocked: %s", first)
	}
	second := postStatefulListenerJSONWithSession(t, baseURL, "", legacySessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"id"}}}`)
	if !strings.Contains(second, "chain pattern") {
		t.Fatalf("legacy session state did not retain the configured chain control: %s", second)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1; blocked second request must not be forwarded", got)
	}
}

func TestHTTPListener_RequireStateTokenOptInRefusesUnauthenticatedCall(t *testing.T) {
	required := true
	var upstreamCalls atomic.Int32
	baseURL := startStatefulListener(t, &required, &upstreamCalls)

	body, headers := postStatefulListenerJSONHeaders(t, baseURL, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`)
	if !strings.Contains(body, "authenticated principal") {
		t.Fatalf("opt-in requirement did not refuse the request: %s", body)
	}
	if got := headers.Get(blockreason.HeaderReason); got != string(blockreason.SessionBinding) {
		t.Fatalf("block reason = %q, want %q", got, blockreason.SessionBinding)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
}

func TestHTTPListener_RequireStateTokenReloadsLive(t *testing.T) {
	var required atomic.Pointer[bool]
	off := false
	on := true
	required.Store(&off)
	var upstreamCalls atomic.Int32
	baseURL := startStatefulListenerWithFn(t, func() *bool { return required.Load() }, &upstreamCalls)

	allowed := postStatefulListenerJSON(t, baseURL, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`)
	if strings.Contains(allowed, "authenticated principal") {
		t.Fatalf("pre-reload request was refused: %s", allowed)
	}

	required.Store(&on)
	denied := postStatefulListenerJSON(t, baseURL, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`)
	if !strings.Contains(denied, "authenticated principal") {
		t.Fatalf("post-reload request was not refused: %s", denied)
	}

	required.Store(&on)
	stillDenied := postStatefulListenerJSON(t, baseURL, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`)
	if !strings.Contains(stillDenied, "authenticated principal") {
		t.Fatalf("reload-without-change dropped the requirement: %s", stillDenied)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func startStatefulListener(t *testing.T, required *bool, calls *atomic.Int32) string {
	t.Helper()
	return startStatefulListenerWithFn(t, nil, calls, required)
}

func startStatefulListenerWithFn(t *testing.T, fn func() *bool, calls *atomic.Int32, static ...*bool) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			ID int `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("Decode(upstream request): %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{}}`, request.ID)
	}))
	t.Cleanup(upstream.Close)

	opts := MCPProxyOpts{
		Scanner:                      testScannerForHTTP(t),
		InputCfg:                     newHTTPInputCfg(config.ActionBlock),
		ChainMatcher:                 buildBlockChainMatcher(),
		ListenerStateTokenRequiredFn: fn,
	}
	if len(static) > 0 {
		opts.listenerStateTokenRequired = static[0]
	}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	return baseURL
}

func postStatefulListenerJSON(t *testing.T, baseURL, body string) string {
	t.Helper()
	payload, _ := postStatefulListenerJSONHeaders(t, baseURL, body)
	return payload
}

func postStatefulListenerJSONWithSession(t *testing.T, baseURL, token, sessionID, body string) string {
	t.Helper()
	payload, _ := postStatefulListenerJSONHeadersWithSession(t, baseURL, token, sessionID, body)
	return payload
}

func postStatefulListenerJSONHeaders(t *testing.T, baseURL, body string) (string, http.Header) {
	t.Helper()
	return postStatefulListenerJSONHeadersWithSession(t, baseURL, "", "", body)
}

func postStatefulListenerJSONHeadersWithSession(t *testing.T, baseURL, token, sessionID, body string) (string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(listenerSessionTokenHeader, token)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(payload), resp.Header
}
