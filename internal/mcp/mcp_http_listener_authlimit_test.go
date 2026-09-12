// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/authlimit"
)

// TestHTTPListener_FailedBearerAttemptsAreRateLimited pins the reverse
// listener's online-guessing bound. Every request in this test arrives from
// the same loopback address, which is the shape an attacker on the operator's
// network segment presents: once the budget is spent the listener refuses
// further credentials unevaluated, including the correct one, until the window
// passes. A challenge round trip with no credential is not counted.
func TestHTTPListener_FailedBearerAttemptsAreRateLimited(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:             testScannerForHTTP(t),
		ListenerBearerToken: "listener-secret",
	})

	request := func(proxyAuth string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(listenerProtocolVersion, "2025-06-18")
		if proxyAuth != "" {
			req.Header.Set(listenerProxyAuthorization, proxyAuth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}

	// Credential-less challenges are never counted, however many.
	for i := range authlimit.DefaultMaxFailures + 5 {
		if got, _ := request(""); got != http.StatusProxyAuthRequired {
			t.Fatalf("challenge %d: status = %d, want 407", i, got)
		}
	}
	// A correct token still works after those challenges.
	if got, _ := request("Bearer listener-secret"); got != http.StatusOK {
		t.Fatalf("correct token after challenges: status = %d, want 200", got)
	}

	for i := range authlimit.DefaultMaxFailures {
		if got, _ := request("Bearer guess"); got != http.StatusProxyAuthRequired {
			t.Fatalf("guess %d: status = %d, want 407", i, got)
		}
	}
	got, retryAfter := request("Bearer guess")
	if got != http.StatusTooManyRequests {
		t.Fatalf("over-budget guess: status = %d, want 429", got)
	}
	if retryAfter == "" {
		t.Fatal("429 without Retry-After")
	}
	// Refused before the compare: the correct token is refused too.
	if got, _ := request("Bearer listener-secret"); got != http.StatusTooManyRequests {
		t.Fatalf("correct token from blocked address: status = %d, want 429", got)
	}
}

// TestHTTPListener_ValidBearerClearsEarlierFailures pins that an operator who
// mistypes the token a few times and then gets it right is not carried toward
// the limit by their own earlier mistakes.
func TestHTTPListener_ValidBearerClearsEarlierFailures(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:             testScannerForHTTP(t),
		ListenerBearerToken: "listener-secret",
	})
	request := func(proxyAuth string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(listenerProtocolVersion, "2025-06-18")
		req.Header.Set(listenerProxyAuthorization, proxyAuth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	for range authlimit.DefaultMaxFailures - 1 {
		if got := request("Bearer typo"); got != http.StatusProxyAuthRequired {
			t.Fatalf("typo: status = %d, want 407", got)
		}
	}
	if got := request("Bearer listener-secret"); got != http.StatusOK {
		t.Fatalf("correct token under budget: status = %d, want 200", got)
	}
	if got := request("Bearer typo"); got != http.StatusProxyAuthRequired {
		t.Fatalf("mistake after success: status = %d, want 407 (budget was reset)", got)
	}
	if got := request("Bearer listener-secret"); got != http.StatusOK {
		t.Fatalf("correct token after reset: status = %d, want 200", got)
	}
}

// TestHTTPListener_ResolverPrincipalSurvivesSpentBearerBudget pins that a
// verified resolver-backed principal (the mTLS/OAuth seam) is still admitted
// from an address whose bearer budget a co-located guesser has spent, while
// the guesser's bearer attempts stay refused.
func TestHTTPListener_ResolverPrincipalSurvivesSpentBearerBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	var verified atomic.Bool
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:             testScannerForHTTP(t),
		ListenerBearerToken: "listener-secret",
		ListenerPrincipalResolver: func(*http.Request) (ListenerPrincipal, error) {
			if verified.Load() {
				return ListenerPrincipal{Provider: "test", Subject: "alice"}, nil
			}
			return ListenerPrincipal{}, nil
		},
	})
	request := func(proxyAuth string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(listenerProtocolVersion, "2025-06-18")
		req.Header.Set(listenerProxyAuthorization, proxyAuth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	for range authlimit.DefaultMaxFailures {
		if got := request("Bearer guess"); got != http.StatusProxyAuthRequired {
			t.Fatalf("guess: status = %d, want 407", got)
		}
	}
	if got := request("Bearer guess"); got != http.StatusTooManyRequests {
		t.Fatalf("over-budget guess: status = %d, want 429", got)
	}
	verified.Store(true)
	if got := request("Bearer guess"); got != http.StatusOK {
		t.Fatalf("verified principal from the blocked address: status = %d, want 200", got)
	}
	verified.Store(false)
	if got := request("Bearer guess"); got != http.StatusTooManyRequests {
		t.Fatalf("unverified guess after principal request: status = %d, want 429 (budget must not be released by a principal)", got)
	}
}
