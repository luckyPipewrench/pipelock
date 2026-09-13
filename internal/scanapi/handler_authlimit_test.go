// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/authlimit"
)

func scanRequest(t *testing.T, remoteAddr, authorization string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(testDLPSafe))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return req
}

// TestHandler_FailedAuthAttemptsAreRateLimited pins that wrong bearer tokens
// from one address are refused before the compare once the budget is spent,
// that the correct token from that address is refused too while blocked, and
// that another address is unaffected.
func TestHandler_FailedAuthAttemptsAreRateLimited(t *testing.T) {
	h := newTestHandler(t)
	const attacker = "203.0.113.5:41000"
	const operator = "198.51.100.9:41000"

	// Each guess arrives from a different ephemeral port on the same host:
	// the budget keys on the address, so port rotation buys nothing.
	for i := range authlimit.DefaultMaxFailures {
		w := httptest.NewRecorder()
		addr := fmt.Sprintf("203.0.113.5:%d", 41000+i)
		h.ServeHTTP(w, scanRequest(t, addr, "Bearer guess"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status = %d, want 401", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, attacker, "Bearer guess"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget guess: status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	if !strings.Contains(w.Body.String(), "rate_limited") {
		t.Fatalf("body = %s, want rate_limited error code", w.Body.String())
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, attacker, "Bearer "+testToken))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("correct token from blocked address: status = %d, want 429", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, operator, "Bearer "+testToken))
	if w.Code != http.StatusOK {
		t.Fatalf("operator: status = %d, want 200: %s", w.Code, w.Body.String())
	}
}

func TestHandler_CredentiallessRequestsAreNotCountedAsGuesses(t *testing.T) {
	h := newTestHandler(t)
	const addr = "203.0.113.6:41000"
	for i := range authlimit.DefaultMaxFailures + 5 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, scanRequest(t, addr, ""))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("no-token request %d: status = %d, want 401 (never 429)", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, addr, "Bearer "+testToken))
	if w.Code != http.StatusOK {
		t.Fatalf("correct token after credential-less requests: status = %d, want 200", w.Code)
	}
}

func TestHandler_ValidTokenClearsEarlierFailures(t *testing.T) {
	h := newTestHandler(t)
	const addr = "203.0.113.7:41000"
	for range authlimit.DefaultMaxFailures - 1 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, scanRequest(t, addr, "Bearer typo"))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, addr, "Bearer "+testToken))
	if w.Code != http.StatusOK {
		t.Fatalf("correct token under budget: status = %d, want 200", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, addr, "Bearer typo"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mistake after success: status = %d, want 401", w.Code)
	}
}

// TestHandler_FailedAuthBudgetRecoversAfterWindow pins the documented
// recovery: once the 60-second window passes, the address is evaluated again.
func TestHandler_FailedAuthBudgetRecoversAfterWindow(t *testing.T) {
	h := newTestHandler(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h.authFailures.SetClock(func() time.Time { return now })
	const addr = "203.0.113.8:41000"

	for range authlimit.DefaultMaxFailures {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, scanRequest(t, addr, "Bearer guess"))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, addr, "Bearer "+testToken))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked address: status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After = %q, want 60 at the start of the window", got)
	}
	now = now.Add(authlimit.DefaultWindow + time.Second)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, scanRequest(t, addr, "Bearer "+testToken))
	if w.Code != http.StatusOK {
		t.Fatalf("after the window: status = %d, want 200: %s", w.Code, w.Body.String())
	}
}
