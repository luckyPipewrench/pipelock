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
	"sync/atomic"
	"testing"
	"time"
)

const (
	testSecretVal = "secret-val"
	testRemoteIP  = "198.51.100.7"
)

// turnstileSuccessHandler returns a handler that responds with configurable
// Siteverify fields. Missing fields use Cloudflare-realistic defaults.
func turnstileSuccessHandler(t *testing.T, overrides map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"success":      true,
			"hostname":     "playground.pipelab.org",
			"action":       "session-create",
			"challenge_ts": time.Now().UTC().Format(time.RFC3339),
		}
		for k, v := range overrides {
			resp[k] = v
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

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

	verifier := TurnstileVerifier{Secret: testSecretVal, VerifyURL: ts.URL, Client: ts.Client()}
	if err := verifier.Verify(context.Background(), "tok-value", testRemoteIP); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Get("secret") != testSecretVal || got.Get("response") != "tok-value" || got.Get("remoteip") != testRemoteIP {
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
			verifier := TurnstileVerifier{Secret: testSecretVal, VerifyURL: ts.URL, Client: ts.Client()}
			if err := verifier.Verify(context.Background(), tc.token, testRemoteIP); err == nil {
				t.Fatal("Verify succeeded, want fail closed")
			}
		})
	}
}

func TestTurnstileVerifier_RequestBuildAndNetworkErrorsFailClosed(t *testing.T) {
	t.Parallel()
	if err := (TurnstileVerifier{Secret: testSecretVal, VerifyURL: "://bad"}).Verify(context.Background(), "token", ""); err == nil {
		t.Fatal("invalid verify URL should fail closed")
	}
	verifier := TurnstileVerifier{
		Secret:    testSecretVal,
		VerifyURL: "https://turnstile.example/verify",
		Client:    &http.Client{Transport: errRoundTripper{}},
	}
	if err := verifier.Verify(context.Background(), "token", ""); err == nil {
		t.Fatal("network error should fail closed")
	}
}

func TestTurnstileVerifier_EmptySecretFailsClosed(t *testing.T) {
	t.Parallel()
	if err := (TurnstileVerifier{}).Verify(context.Background(), "token", testRemoteIP); err == nil {
		t.Fatal("Verify with empty secret succeeded, want fail closed")
	}
}

// --- Post-success response validation (Issue A) ---

func TestTurnstileVerifier_HostnameActionFreshness(t *testing.T) {
	t.Parallel()

	freshTS := time.Now().UTC().Format(time.RFC3339)
	staleTS := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	fixedNow := time.Now().UTC()
	clock := func() time.Time { return fixedNow }

	tests := []struct {
		name      string
		verifier  TurnstileVerifier
		overrides map[string]any
		wantErr   bool
	}{
		{
			name: "success_matching_hostname_action_fresh",
			verifier: TurnstileVerifier{
				ExpectedHostname: "playground.pipelab.org",
				ExpectedAction:   "session-create",
				MaxAge:           5 * time.Minute,
				Now:              clock,
			},
			overrides: map[string]any{
				"hostname":     "playground.pipelab.org",
				"action":       "session-create",
				"challenge_ts": freshTS,
			},
			wantErr: false,
		},
		{
			name: "wrong_hostname_rejected",
			verifier: TurnstileVerifier{
				ExpectedHostname: "playground.pipelab.org",
			},
			overrides: map[string]any{
				"hostname": "evil.attacker.com",
			},
			wantErr: true,
		},
		{
			name: "wrong_action_rejected",
			verifier: TurnstileVerifier{
				ExpectedAction: "session-create",
			},
			overrides: map[string]any{
				"action": "wrong-action",
			},
			wantErr: true,
		},
		{
			name: "stale_challenge_ts_rejected",
			verifier: TurnstileVerifier{
				MaxAge: 5 * time.Minute,
				Now:    clock,
			},
			overrides: map[string]any{
				"challenge_ts": staleTS,
			},
			wantErr: true,
		},
		{
			name: "missing_challenge_ts_with_max_age_fails_closed",
			verifier: TurnstileVerifier{
				MaxAge: 5 * time.Minute,
				Now:    clock,
			},
			overrides: map[string]any{
				"challenge_ts": "",
			},
			wantErr: true,
		},
		{
			name: "unparseable_challenge_ts_with_max_age_fails_closed",
			verifier: TurnstileVerifier{
				MaxAge: 5 * time.Minute,
				Now:    clock,
			},
			overrides: map[string]any{
				"challenge_ts": "not-a-timestamp",
			},
			wantErr: true,
		},
		{
			name: "hostname_case_insensitive",
			verifier: TurnstileVerifier{
				ExpectedHostname: "Playground.Pipelab.Org",
			},
			overrides: map[string]any{
				"hostname": "playground.pipelab.org",
			},
			wantErr: false,
		},
		{
			name:     "no_validation_fields_set_allows_on_success",
			verifier: TurnstileVerifier{},
			overrides: map[string]any{
				"hostname": "anything.example",
				"action":   "whatever",
			},
			wantErr: false,
		},
		{
			name: "max_age_zero_skips_freshness",
			verifier: TurnstileVerifier{
				MaxAge: 0,
			},
			overrides: map[string]any{
				"challenge_ts": staleTS,
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(turnstileSuccessHandler(t, tc.overrides))
			t.Cleanup(ts.Close)

			v := tc.verifier
			v.Secret = testSecretVal
			v.VerifyURL = ts.URL
			v.Client = ts.Client()

			err := v.Verify(context.Background(), "test-token", testRemoteIP)
			if tc.wantErr && err == nil {
				t.Fatal("Verify succeeded, want fail closed")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			// Verify that error messages don't leak which check failed.
			if tc.wantErr && err != nil && !errors.Is(err, errTurnstileRejected) {
				t.Fatalf("error should be generic errTurnstileRejected, got: %v", err)
			}
		})
	}
}

// --- SeenTokens unit tests ---

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
	const tok = "race-token"
	const goroutines = 50
	accepted := make(chan bool, goroutines)
	start := make(chan struct{})
	for range goroutines {
		go func() {
			<-start
			accepted <- seen.CheckAndMark(tok)
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

func TestSeenTokens_IsSeenAndMarkSeen(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	seen := NewSeenTokens(2*time.Minute, clock)

	if seen.IsSeen("tok-x") {
		t.Fatal("unseen token should not be seen")
	}
	if !seen.MarkSeen("tok-x") {
		t.Fatal("MarkSeen should succeed")
	}
	if seen.MarkSeen("tok-x") {
		t.Fatal("duplicate MarkSeen before expiry should reject")
	}
	if !seen.IsSeen("tok-x") {
		t.Fatal("marked token should be seen")
	}
	// After expiry, not seen.
	now = now.Add(3 * time.Minute)
	if seen.IsSeen("tok-x") {
		t.Fatal("expired token should not be seen")
	}
}

// --- ReplayGuardVerifier (Issue B: post-verify record pattern) ---

func TestReplayGuardVerifier_BlocksReplayAfterSuccess(t *testing.T) {
	t.Parallel()
	var siteverifyCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		siteverifyCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(ts.Close)

	inner := TurnstileVerifier{Secret: testSecretVal, VerifyURL: ts.URL, Client: ts.Client()}
	guard := &ReplayGuardVerifier{
		Inner: inner,
		Seen:  NewSeenTokens(time.Minute, nil),
	}

	// First call succeeds and reaches Siteverify.
	if err := guard.Verify(context.Background(), "replay-tok", testRemoteIP); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if siteverifyCalls.Load() != 1 {
		t.Fatalf("siteverify calls = %d, want 1", siteverifyCalls.Load())
	}
	// Second call with same token is rejected WITHOUT a Siteverify call.
	if err := guard.Verify(context.Background(), "replay-tok", testRemoteIP); err == nil {
		t.Fatal("replayed token should be rejected")
	}
	if siteverifyCalls.Load() != 1 {
		t.Fatalf("siteverify calls after replay = %d, want still 1 (no network call)", siteverifyCalls.Load())
	}
}

type sequenceVerifier struct {
	calls atomic.Int32
	first chan struct{}
	allow chan struct{}
}

func (v *sequenceVerifier) Verify(ctx context.Context, _, _ string) error {
	n := v.calls.Add(1)
	if n == 1 {
		close(v.first)
		select {
		case <-v.allow:
		case <-ctx.Done():
			return ctx.Err()
		}
		return errTurnstileRejected
	}
	return nil
}

func TestReplayGuardVerifier_WaitersRecheckFailedLeader(t *testing.T) {
	t.Parallel()
	inner := &sequenceVerifier{first: make(chan struct{}), allow: make(chan struct{})}
	guard := &ReplayGuardVerifier{
		Inner:  inner,
		Seen:   NewSeenTokens(time.Minute, nil),
		Failed: NewSeenTokens(time.Minute, nil),
	}
	waitersReady := make(chan struct{})
	var waiters atomic.Int32
	guard.waitHook = func() {
		if waiters.Add(1) == 2 {
			close(waitersReady)
		}
	}

	errs := make(chan error, 3)
	go func() {
		errs <- guard.Verify(context.Background(), "same-token", testRemoteIP)
	}()
	<-inner.first
	for range 2 {
		go func() {
			errs <- guard.Verify(context.Background(), "same-token", testRemoteIP)
		}()
	}
	<-waitersReady
	close(inner.allow)

	for range 3 {
		if err := <-errs; err == nil {
			t.Fatal("Verify succeeded, want failed leader and waiters to fail closed")
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("inner verifier calls = %d, want 1; waiters must recheck failed-token cache", got)
	}
}

func TestReplayGuardVerifier_FailedTokenDoesNotPoisonCache(t *testing.T) {
	t.Parallel()
	// Issue B: an attacker spraying invalid tokens must not fill the cache.
	// A failed Siteverify must NOT record the token, so the same token value
	// can succeed on a subsequent attempt.
	var callCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			// First call: upstream rejects.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":     false,
				"error-codes": []string{"timeout-or-duplicate"},
			})
			return
		}
		// Second call: upstream accepts.
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(ts.Close)

	seen := NewSeenTokens(time.Minute, nil)
	inner := TurnstileVerifier{Secret: testSecretVal, VerifyURL: ts.URL, Client: ts.Client()}
	guard := &ReplayGuardVerifier{
		Inner: inner,
		Seen:  seen,
	}

	// First attempt: upstream rejects.
	if err := guard.Verify(context.Background(), "the-token", testRemoteIP); err == nil {
		t.Fatal("first Verify should have failed")
	}

	// Token must NOT be in the seen cache.
	if seen.IsSeen("the-token") {
		t.Fatal("failed verification should not poison seen cache")
	}

	// Second attempt with same token: upstream accepts this time.
	if err := guard.Verify(context.Background(), "the-token", testRemoteIP); err != nil {
		t.Fatalf("second Verify should succeed: %v", err)
	}

	// NOW the token should be in the seen cache.
	if !seen.IsSeen("the-token") {
		t.Fatal("token should be recorded as seen after successful verification")
	}

	// Third attempt: replay rejected.
	if err := guard.Verify(context.Background(), "the-token", testRemoteIP); err == nil {
		t.Fatal("third Verify should reject replay")
	}
}

func TestReplayGuardVerifier_NegativeCacheDampsRetry(t *testing.T) {
	t.Parallel()
	// With a negative cache, a token that just failed upstream is fast-rejected
	// on immediate retry WITHOUT a second Siteverify call, damping the retry
	// amplification an attacker (or a provider outage) could otherwise cause.
	var callCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":     false,
			"error-codes": []string{"invalid-input-response"},
		})
	}))
	t.Cleanup(ts.Close)

	inner := TurnstileVerifier{Secret: testSecretVal, VerifyURL: ts.URL, Client: ts.Client()}
	guard := &ReplayGuardVerifier{
		Inner:  inner,
		Seen:   NewSeenTokens(time.Minute, nil),
		Failed: NewSeenTokens(time.Minute, nil),
	}

	// First attempt reaches upstream and fails.
	if err := guard.Verify(context.Background(), "bad-token", testRemoteIP); err == nil {
		t.Fatal("first Verify should fail")
	}
	if got := callCount.Load(); got != 1 {
		t.Fatalf("Siteverify calls after first attempt = %d, want 1", got)
	}

	// Immediate retry of the same bad token is short-circuited by the negative
	// cache: no additional Siteverify call.
	if err := guard.Verify(context.Background(), "bad-token", testRemoteIP); err == nil {
		t.Fatal("retry of a just-failed token should be rejected")
	}
	if got := callCount.Load(); got != 1 {
		t.Fatalf("Siteverify calls after retry = %d, want 1 (negative cache must short-circuit)", got)
	}
}

func TestReplayGuardVerifier_InvalidTokenDoesNotPopulateSeenCache(t *testing.T) {
	t.Parallel()
	var siteverifyCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		siteverifyCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(ts.Close)

	seen := NewSeenTokens(time.Minute, nil)
	inner := TurnstileVerifier{Secret: testSecretVal, VerifyURL: ts.URL, Client: ts.Client()}
	guard := &ReplayGuardVerifier{
		Inner: inner,
		Seen:  seen,
	}

	for _, tok := range []string{"", strings.Repeat("x", maxTurnstileTokenBytes+1)} {
		if err := guard.Verify(context.Background(), tok, testRemoteIP); err == nil {
			t.Fatal("invalid token Verify succeeded, want fail closed")
		}
	}
	if siteverifyCalls.Load() != 0 {
		t.Fatalf("siteverify calls = %d, want 0 for invalid tokens", siteverifyCalls.Load())
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	if len(seen.m) != 0 {
		t.Fatalf("seen-token cache len = %d, want 0 after invalid tokens", len(seen.m))
	}
}
