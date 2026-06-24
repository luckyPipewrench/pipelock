// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTurnstileVerifier_Verify(t *testing.T) {
	t.Parallel()
	var got url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if gotCT := r.Header.Get("Content-Type"); gotCT != "application/x-www-form-urlencoded" {
			t.Fatalf("content-type = %q", gotCT)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		got = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(ts.Close)

	verifier := TurnstileVerifier{Secret: "secret", VerifyURL: ts.URL, Client: ts.Client()}
	if err := verifier.Verify(context.Background(), "token", "198.51.100.7"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Get("secret") != "secret" || got.Get("response") != "token" || got.Get("remoteip") != "198.51.100.7" {
		t.Fatalf("siteverify form = %v", got)
	}
}

type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network blocked")
}

func TestTurnstileVerifier_FailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		token   string
		handler http.HandlerFunc
	}{
		{
			name:  "rejected",
			token: "token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":     false,
					"error-codes": []string{"timeout-or-duplicate"},
				})
			},
		},
		{
			name:  "bad_status",
			token: "token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "bad gateway", http.StatusBadGateway)
			},
		},
		{
			name:  "bad_json",
			token: "token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("{"))
			},
		},
		{
			name:  "rejected_without_error_codes",
			token: "token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false})
			},
		},
		{
			name:  "empty_token",
			token: "",
			handler: func(http.ResponseWriter, *http.Request) {
				t.Fatal("siteverify should not be called for an empty token")
			},
		},
		{
			name:  "oversized_token",
			token: strings.Repeat("x", maxTurnstileTokenBytes+1),
			handler: func(http.ResponseWriter, *http.Request) {
				t.Fatal("siteverify should not be called for an oversized token")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(tc.handler)
			t.Cleanup(ts.Close)
			verifier := TurnstileVerifier{Secret: "secret", VerifyURL: ts.URL, Client: ts.Client()}
			if err := verifier.Verify(context.Background(), tc.token, "198.51.100.7"); err == nil {
				t.Fatal("Verify succeeded, want fail closed")
			}
		})
	}
}

func TestTurnstileVerifier_RequestBuildAndNetworkErrorsFailClosed(t *testing.T) {
	t.Parallel()
	if err := (TurnstileVerifier{Secret: "secret", VerifyURL: "://bad"}).Verify(context.Background(), "token", ""); err == nil {
		t.Fatal("invalid verify URL should fail closed")
	}
	verifier := TurnstileVerifier{
		Secret:    "secret",
		VerifyURL: "https://turnstile.example/verify",
		Client:    &http.Client{Transport: errRoundTripper{}},
	}
	if err := verifier.Verify(context.Background(), "token", ""); err == nil {
		t.Fatal("network error should fail closed")
	}
}

func TestTurnstileVerifier_EmptySecretFailsClosed(t *testing.T) {
	t.Parallel()
	if err := (TurnstileVerifier{}).Verify(context.Background(), "token", "198.51.100.7"); err == nil {
		t.Fatal("Verify with empty secret succeeded, want fail closed")
	}
}

func TestSeenTokens_Defaults(t *testing.T) {
	t.Parallel()
	seen := NewSeenTokens(0, nil)
	if seen.ttl != defaultSeenTokenTTL {
		t.Fatalf("ttl = %v, want default %v", seen.ttl, defaultSeenTokenTTL)
	}
	if seen.now == nil {
		t.Fatal("now func is nil")
	}
	if !seen.CheckAndMark("default-token") {
		t.Fatal("default seen-token cache should accept first token")
	}
}

func TestSeenTokens_ReplayRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	seen := NewSeenTokens(defaultSeenTokenTTL, clock)

	if !seen.CheckAndMark("tok-a") {
		t.Fatal("first CheckAndMark should accept")
	}
	if seen.CheckAndMark("tok-a") {
		t.Fatal("second CheckAndMark for same token should reject")
	}
	// A different token is fine.
	if !seen.CheckAndMark("tok-b") {
		t.Fatal("different token should be accepted")
	}
}

func TestSeenTokens_ExpiredTokenAllowed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	seen := NewSeenTokens(2*time.Minute, clock)

	if !seen.CheckAndMark("tok-expire") {
		t.Fatal("first CheckAndMark should accept")
	}
	// Advance clock past TTL.
	now = now.Add(3 * time.Minute)
	if !seen.CheckAndMark("tok-expire") {
		t.Fatal("token should be accepted again after TTL expires")
	}
}

func TestSeenTokens_CapFailsClosedUntilExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	seen := NewSeenTokens(2*time.Minute, clock)
	seen.max = 2

	if !seen.CheckAndMark("tok-a") || !seen.CheckAndMark("tok-b") {
		t.Fatal("initial tokens should be accepted")
	}
	if seen.CheckAndMark("tok-c") {
		t.Fatal("cache at capacity should reject new tokens fail-closed")
	}
	now = now.Add(3 * time.Minute)
	if !seen.CheckAndMark("tok-c") {
		t.Fatal("cache should accept after expired entries are evicted")
	}
}

func TestSeenTokens_ConcurrentRace(t *testing.T) {
	t.Parallel()
	seen := NewSeenTokens(time.Minute, nil)
	const token = "race-token"
	const goroutines = 50
	accepted := make(chan bool, goroutines)
	start := make(chan struct{})
	for range goroutines {
		go func() {
			<-start
			accepted <- seen.CheckAndMark(token)
		}()
	}
	close(start)
	wins := 0
	for range goroutines {
		if <-accepted {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent CheckAndMark accepted %d, want exactly 1", wins)
	}
}

func TestReplayGuardVerifier_BlocksReplayBeforeNetwork(t *testing.T) {
	t.Parallel()
	var siteverifyCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		siteverifyCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(ts.Close)

	inner := TurnstileVerifier{Secret: "secret", VerifyURL: ts.URL, Client: ts.Client()}
	guard := &ReplayGuardVerifier{
		Inner: inner,
		Seen:  NewSeenTokens(time.Minute, nil),
	}

	// First call succeeds and reaches Siteverify.
	if err := guard.Verify(context.Background(), "replay-tok", "198.51.100.7"); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if siteverifyCalls != 1 {
		t.Fatalf("siteverify calls = %d, want 1", siteverifyCalls)
	}
	// Second call with same token is rejected WITHOUT a Siteverify call.
	if err := guard.Verify(context.Background(), "replay-tok", "198.51.100.7"); err == nil {
		t.Fatal("replayed token should be rejected")
	}
	if siteverifyCalls != 1 {
		t.Fatalf("siteverify calls after replay = %d, want still 1 (no network call)", siteverifyCalls)
	}
}

func TestReplayGuardVerifier_InvalidTokenDoesNotPopulateSeenCache(t *testing.T) {
	t.Parallel()
	var siteverifyCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		siteverifyCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(ts.Close)

	seen := NewSeenTokens(time.Minute, nil)
	inner := TurnstileVerifier{Secret: "secret", VerifyURL: ts.URL, Client: ts.Client()}
	guard := &ReplayGuardVerifier{
		Inner: inner,
		Seen:  seen,
	}

	for _, token := range []string{"", strings.Repeat("x", maxTurnstileTokenBytes+1)} {
		if err := guard.Verify(context.Background(), token, "198.51.100.7"); err == nil {
			t.Fatal("invalid token Verify succeeded, want fail closed")
		}
	}
	if siteverifyCalls != 0 {
		t.Fatalf("siteverify calls = %d, want 0 for invalid tokens", siteverifyCalls)
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	if len(seen.m) != 0 {
		t.Fatalf("seen-token cache len = %d, want 0 after invalid tokens", len(seen.m))
	}
}
