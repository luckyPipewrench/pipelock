// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/authlimit"
)

func killswitchStatusRequest(t *testing.T, remoteAddr, authorization string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/killswitch/status", nil)
	r.RemoteAddr = remoteAddr
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

// TestAPIHandler_FailedAuthAttemptsAreRateLimited pins the online-guessing
// bound: presented-but-wrong tokens from one address are refused unevaluated
// once the budget is spent, so even the correct token from that address gets
// 429 while blocked, while another address and the credential-less challenge
// path are unaffected.
func TestAPIHandler_FailedAuthAttemptsAreRateLimited(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "correct-token"
	h := NewAPIHandler(New(cfg))

	const attacker = "203.0.113.5:40000"
	const operator = "198.51.100.9:40000"

	for i := range authlimit.DefaultMaxFailures {
		w := httptest.NewRecorder()
		h.HandleStatus(w, killswitchStatusRequest(t, attacker, "Bearer guess"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status = %d, want 401", i, w.Code)
		}
	}

	w := httptest.NewRecorder()
	h.HandleStatus(w, killswitchStatusRequest(t, attacker, "Bearer guess"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget guess: status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}

	// The refusal happens before the compare: the right token from the
	// blocked address is refused too, so the guesser gets no oracle.
	w = httptest.NewRecorder()
	h.HandleStatus(w, killswitchStatusRequest(t, attacker, "Bearer correct-token"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("correct token from blocked address: status = %d, want 429", w.Code)
	}

	// Another address is unaffected, for both endpoints.
	w = httptest.NewRecorder()
	h.HandleStatus(w, killswitchStatusRequest(t, operator, "Bearer correct-token"))
	if w.Code != http.StatusOK {
		t.Fatalf("operator status: status = %d, want 200", w.Code)
	}
	w = httptest.NewRecorder()
	toggle := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/killswitch", bytes.NewBufferString(`{"active": false}`))
	toggle.RemoteAddr = operator
	toggle.Header.Set("Authorization", "Bearer correct-token")
	h.HandleToggle(w, toggle)
	if w.Code != http.StatusOK {
		t.Fatalf("operator toggle: status = %d, want 200", w.Code)
	}
}

func TestAPIHandler_CredentiallessRequestsAreNotCountedAsGuesses(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "correct-token"
	h := NewAPIHandler(New(cfg))
	const addr = "203.0.113.6:40000"

	for i := range authlimit.DefaultMaxFailures + 5 {
		w := httptest.NewRecorder()
		h.HandleStatus(w, killswitchStatusRequest(t, addr, ""))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("no-token request %d: status = %d, want 401 (never 429)", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.HandleStatus(w, killswitchStatusRequest(t, addr, "Bearer correct-token"))
	if w.Code != http.StatusOK {
		t.Fatalf("correct token after credential-less challenges: status = %d, want 200", w.Code)
	}
}

func TestAPIHandler_ValidTokenClearsEarlierFailures(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "correct-token"
	h := NewAPIHandler(New(cfg))
	const addr = "203.0.113.7:40000"

	for range authlimit.DefaultMaxFailures - 1 {
		w := httptest.NewRecorder()
		h.HandleStatus(w, killswitchStatusRequest(t, addr, "Bearer typo"))
	}
	w := httptest.NewRecorder()
	h.HandleStatus(w, killswitchStatusRequest(t, addr, "Bearer correct-token"))
	if w.Code != http.StatusOK {
		t.Fatalf("correct token under budget: status = %d, want 200", w.Code)
	}
	// Budget is fresh again: one more mistake does not block.
	w = httptest.NewRecorder()
	h.HandleStatus(w, killswitchStatusRequest(t, addr, "Bearer typo"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mistake after success: status = %d, want 401", w.Code)
	}
	w = httptest.NewRecorder()
	h.HandleStatus(w, killswitchStatusRequest(t, addr, "Bearer correct-token"))
	if w.Code != http.StatusOK {
		t.Fatalf("correct token after reset: status = %d, want 200", w.Code)
	}
}
