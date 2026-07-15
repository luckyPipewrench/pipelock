// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHTTPListener_TokenlessLoopbackRejectsReboundHost(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})

	request := func(path, host string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+path, strings.NewReader(jsonToolsList))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	authority := strings.TrimPrefix(baseURL, "http://")
	_, port, err := net.SplitHostPort(authority)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", authority, err)
	}
	if got := request("/", "localhost:"+port); got != http.StatusOK {
		t.Fatalf("localhost status = %d, want 200", got)
	}
	if got := request("/", "rebound.attacker.example:"+port); got != http.StatusForbidden {
		t.Fatalf("rebound Host status = %d, want 403", got)
	}
	if got := request("/", "127.0.0.1:1"); got != http.StatusForbidden {
		t.Fatalf("wrong-port Host status = %d, want 403", got)
	}

	healthReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequest health: %v", err)
	}
	healthReq.Host = "rebound.attacker.example:" + port
	healthResp, err := http.DefaultClient.Do(healthReq)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusForbidden {
		t.Fatalf("rebound health status = %d, want 403", healthResp.StatusCode)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want only the allowed localhost request", got)
	}
}

func TestHTTPListener_RejectsAmbiguousOrMalformedProtocolHeaders(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t)})

	request := func(setHeaders func(http.Header)) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		setHeaders(req.Header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	for _, version := range []string{"2025-02-30", "1999-01-01-DOWNGRADE", "1e999"} {
		if got := request(func(h http.Header) { h.Set(listenerProtocolVersion, version) }); got != http.StatusBadRequest {
			t.Errorf("protocol version %q status = %d, want 400", version, got)
		}
	}
	if got := request(func(h http.Header) {
		h.Add(listenerProtocolVersion, "2025-03-26")
		h.Add(listenerProtocolVersion, "2025-06-18")
	}); got != http.StatusBadRequest {
		t.Errorf("duplicate protocol version status = %d, want 400", got)
	}
	if got := request(func(h http.Header) {
		h.Add("Mcp-Session-Id", "one")
		h.Add("Mcp-Session-Id", "two")
	}); got != http.StatusBadRequest {
		t.Errorf("duplicate session status = %d, want 400", got)
	}
	if got := request(func(h http.Header) {
		h.Add("A2A-Extensions", "https://one.example/ext")
		h.Add("A2A-Extensions", "https://two.example/ext")
	}); got != http.StatusBadRequest {
		t.Errorf("duplicate A2A extensions status = %d, want 400", got)
	}
	for _, version := range []string{"1", "1.0.1", "latest", "1.-1"} {
		if got := request(func(h http.Header) { h.Set("A2A-Version", version) }); got != http.StatusBadRequest {
			t.Errorf("A2A version %q status = %d, want 400", version, got)
		}
	}
	for _, extensions := range []string{"relative/path", "https://valid.example/ext,", ",https://valid.example/ext"} {
		if got := request(func(h http.Header) { h.Set("A2A-Extensions", extensions) }); got != http.StatusBadRequest {
			t.Errorf("A2A extensions %q status = %d, want 400", extensions, got)
		}
	}
	if got := request(func(h http.Header) { h["Mcp-Session-Id"] = []string{""} }); got != http.StatusBadRequest {
		t.Errorf("empty session status = %d, want 400", got)
	}
	if got := request(func(h http.Header) { h.Set(listenerProtocolVersion, "2025-06-18") }); got != http.StatusOK {
		t.Errorf("valid protocol version status = %d, want 200", got)
	}
	if got := request(func(h http.Header) {
		h.Set("A2A-Version", "1.0")
		h.Set("A2A-Extensions", "https://one.example/ext, urn:example:extension")
	}); got != http.StatusOK {
		t.Errorf("valid A2A service headers status = %d, want 200", got)
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want only the two valid requests", got)
	}
}

func TestHTTPListener_RejectsInvalidOperatorServiceHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		want    string
	}{
		{"protocol version", http.Header{listenerProtocolVersion: []string{"latest"}}, "valid YYYY-MM-DD"},
		{"A2A version", http.Header{"A2A-Version": []string{"latest"}}, "Major.Minor"},
		{"A2A extensions", http.Header{"A2A-Extensions": []string{"relative/path"}}, "absolute URI"},
		{"empty authorization", http.Header{listenerAuthorization: []string{""}}, "non-empty visible ASCII"},
		{"duplicate authorization", http.Header{listenerAuthorization: []string{"Bearer one", "Bearer two"}}, "at most once"},
		{"mixed-case duplicate A2A version", http.Header{"A2A-Version": []string{"1.0"}, "a2a-version": []string{"2.0"}}, "at most once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer func() { _ = ln.Close() }()
			err = RunHTTPListenerProxy(context.Background(), ln, "http://127.0.0.1:1", io.Discard, MCPProxyOpts{UpstreamHeaders: tc.headers})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RunHTTPListenerProxy error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateListenerUpstreamHeaders(t *testing.T) {
	t.Parallel()

	valid := canonicalizeListenerUpstreamHeaders(http.Header{
		"X-Trace":             []string{"one", "two"},
		listenerAuthorization: []string{"Bearer upstream"},
		listenerProtocolVersion: []string{
			"2025-06-18",
		},
		"A2A-Version":    []string{"1.0"},
		"A2A-Extensions": []string{"https://one.example/ext, urn:example:extension"},
	})
	if err := validateListenerUpstreamHeaders(valid); err != nil {
		t.Fatalf("valid operator headers rejected: %v", err)
	}

	for _, tc := range []struct {
		name    string
		headers http.Header
		want    string
	}{
		{"duplicate authorization", http.Header{listenerAuthorization: []string{"Bearer one", "Bearer two"}}, "at most once"},
		{"duplicate protocol version", http.Header{listenerProtocolVersion: []string{"2025-03-26", "2025-06-18"}}, "at most once"},
		{"duplicate A2A version", http.Header{"A2A-Version": []string{"0.3", "1.0"}}, "at most once"},
		{"duplicate A2A extensions", http.Header{"A2A-Extensions": []string{"urn:one", "urn:two"}}, "at most once"},
		{"malformed protocol version", http.Header{listenerProtocolVersion: []string{"latest"}}, "valid YYYY-MM-DD"},
		{"malformed A2A version", http.Header{"A2A-Version": []string{"latest"}}, "Major.Minor"},
		{"relative A2A extension", http.Header{"A2A-Extensions": []string{"relative/path"}}, "absolute URI"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			headers := canonicalizeListenerUpstreamHeaders(tc.headers)
			if err := validateListenerUpstreamHeaders(headers); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateListenerUpstreamHeaders(%v) error = %v, want containing %q", headers, err, tc.want)
			}
		})
	}
}
