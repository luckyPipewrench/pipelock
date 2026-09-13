// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/authlimit"
)

func sessionListRequest(t *testing.T, remoteAddr, authorization string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/sessions", nil)
	req.RemoteAddr = remoteAddr
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return req
}

// TestSessionAPI_FailedAuthAttemptsAreRateLimited pins the admin API's
// online-guessing bound: wrong tokens from one address are refused before the
// compare once the budget is spent, the correct token from that address is
// refused too while blocked, and another address is unaffected.
func TestSessionAPI_FailedAuthAttemptsAreRateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)
	const attacker = "203.0.113.5:42000"
	const operator = "198.51.100.9:42000"

	// Each guess arrives from a different ephemeral port on the same host:
	// the budget keys on the address, so port rotation buys nothing.
	for i := range authlimit.DefaultMaxFailures {
		w := httptest.NewRecorder()
		addr := fmt.Sprintf("203.0.113.5:%d", 42000+i)
		handler.HandleList(w, sessionListRequest(t, addr, "Bearer guess"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status = %d, want 401", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, attacker, "Bearer guess"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget guess: status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}

	w = httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, attacker, "Bearer "+testSessionAPIToken))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("correct token from blocked address: status = %d, want 429", w.Code)
	}

	w = httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, operator, "Bearer "+testSessionAPIToken))
	if w.Code != http.StatusOK {
		t.Fatalf("operator: status = %d, want 200", w.Code)
	}
}

func TestSessionAPI_CredentiallessRequestsAreNotCountedAsGuesses(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)
	const addr = "203.0.113.6:42000"

	for i := range authlimit.DefaultMaxFailures + 5 {
		w := httptest.NewRecorder()
		handler.HandleList(w, sessionListRequest(t, addr, ""))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("no-token request %d: status = %d, want 401 (never 429)", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, addr, "Bearer "+testSessionAPIToken))
	if w.Code != http.StatusOK {
		t.Fatalf("correct token after credential-less requests: status = %d, want 200", w.Code)
	}
}

func TestSessionAPI_ValidTokenClearsEarlierFailures(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)
	const addr = "203.0.113.7:42000"

	for range authlimit.DefaultMaxFailures - 1 {
		w := httptest.NewRecorder()
		handler.HandleList(w, sessionListRequest(t, addr, "Bearer typo"))
	}
	w := httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, addr, "Bearer "+testSessionAPIToken))
	if w.Code != http.StatusOK {
		t.Fatalf("correct token under budget: status = %d, want 200", w.Code)
	}
	w = httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, addr, "Bearer typo"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mistake after success: status = %d, want 401", w.Code)
	}
}

// TestSessionAPI_FailedAuthBudgetRecoversAfterWindow pins the documented
// recovery: once the 60-second window passes, the address is evaluated again.
func TestSessionAPI_FailedAuthBudgetRecoversAfterWindow(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handler.authFailures.SetClock(func() time.Time { return now })
	const addr = "203.0.113.8:42000"

	for range authlimit.DefaultMaxFailures {
		w := httptest.NewRecorder()
		handler.HandleList(w, sessionListRequest(t, addr, "Bearer guess"))
	}
	w := httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, addr, "Bearer "+testSessionAPIToken))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked address: status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After = %q, want 60 at the start of the window", got)
	}
	now = now.Add(authlimit.DefaultWindow + time.Second)
	w = httptest.NewRecorder()
	handler.HandleList(w, sessionListRequest(t, addr, "Bearer "+testSessionAPIToken))
	if w.Code != http.StatusOK {
		t.Fatalf("after the window: status = %d, want 200", w.Code)
	}
}
