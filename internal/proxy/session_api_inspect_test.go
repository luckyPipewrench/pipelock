// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	inspectIdentityKey = "agent-x|10.0.0.5"
	inspectAuthHeader  = "Bearer " + testSessionAPIToken
	inspectEvidence    = "dlp blocked outbound AWS credentials"
)

// inspectURLFor builds /api/v1/sessions/{escaped-key} for tests.
func inspectURLFor(key string) string {
	return "/api/v1/sessions/" + url.PathEscape(key)
}

func TestSessionAPI_HandleInspect_HappyPath(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate(inspectIdentityKey)
	sess.RecordEvent(SessionEvent{Kind: "block", Target: "api.example.com", Detail: inspectEvidence, Severity: "critical", Score: 0.9})
	_, _, _ = sess.Airlock().SetTier(config.AirlockTierHard)

	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, inspectURLFor(inspectIdentityKey), nil)
	req.Header.Set("Authorization", inspectAuthHeader)
	w := httptest.NewRecorder()

	handler.HandleInspect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var detail SessionDetail
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, w.Body.String())
	}
	if detail.Key != inspectIdentityKey {
		t.Errorf("Key: got %q, want %q", detail.Key, inspectIdentityKey)
	}
	if detail.AirlockTier != config.AirlockTierHard {
		t.Errorf("AirlockTier: got %q, want %q", detail.AirlockTier, config.AirlockTierHard)
	}
	if detail.AirlockEnteredAt.IsZero() {
		t.Error("AirlockEnteredAt should be non-zero after transition")
	}
	if got := len(detail.RecentEvents); got != 1 {
		t.Fatalf("RecentEvents: got %d, want 1", got)
	}
	if detail.RecentEvents[0].Detail != inspectEvidence {
		t.Errorf("RecentEvents[0].Detail: got %q, want %q", detail.RecentEvents[0].Detail, inspectEvidence)
	}
}

func TestSessionAPI_HandleInspect_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, inspectURLFor("ghost|1.2.3.4"), nil)
	req.Header.Set("Authorization", inspectAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleInspect(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleInspect_MethodNotAllowed(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, inspectURLFor(inspectIdentityKey), nil)
	req.Header.Set("Authorization", inspectAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleInspect(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow: got %q, want %q", allow, http.MethodGet)
	}
}

func TestSessionAPI_HandleInspect_Unauthorized(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, inspectURLFor(inspectIdentityKey), nil)
	// No auth header.
	w := httptest.NewRecorder()
	handler.HandleInspect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestSessionAPI_HandleInspect_BadPath(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	tests := []struct {
		name string
		path string
	}{
		{"wrong api prefix", "/wrong/v1/sessions/key"},
		{"wrong version", "/api/v2/sessions/key"},
		{"five segments (action route)", "/api/v1/sessions/key/reset"},
		{"three segments (list route)", "/api/v1/sessions"},
		{"empty key", "/api/v1/sessions/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("Authorization", inspectAuthHeader)
			w := httptest.NewRecorder()
			handler.HandleInspect(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("expected non-200 for %s, got 200", tt.path)
			}
		})
	}
}

func TestSessionAPI_HandleInspect_RateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(inspectIdentityKey)
	handler := newTestSessionAPIHandler(t, sm)

	for i := 0; i < sessionAPIRateLimitMax; i++ {
		req := httptest.NewRequest(http.MethodGet, inspectURLFor(inspectIdentityKey), nil)
		req.Header.Set("Authorization", inspectAuthHeader)
		w := httptest.NewRecorder()
		handler.HandleInspect(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 within limit, got %d", i, w.Code)
		}
	}

	// The next request should be rate-limited.
	req := httptest.NewRequest(http.MethodGet, inspectURLFor(inspectIdentityKey), nil)
	req.Header.Set("Authorization", inspectAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleInspect(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status: got %d, want 429", w.Code)
	}
	if retryAfter := w.Header().Get("Retry-After"); retryAfter != "60" {
		t.Errorf("Retry-After: got %q, want 60", retryAfter)
	}
}

func TestSessionAPI_HandleInspect_ManagerDisabled(t *testing.T) {
	var smPtr atomic.Pointer[SessionManager]
	// Never Store() anything — Load() returns nil.
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	handler := NewSessionAPIHandler(SessionAPIOptions{
		SessionMgrPtr: &smPtr,
		EntropyPtr:    &etPtr,
		FragmentPtr:   &fbPtr,
		Logger:        audit.NewNop(),
		APIToken:      testSessionAPIToken,
	})

	req := httptest.NewRequest(http.MethodGet, inspectURLFor(inspectIdentityKey), nil)
	req.Header.Set("Authorization", inspectAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleInspect(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", w.Code)
	}
}

func TestSessionAPI_HandleInspect_RecentEventsEmpty(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(inspectIdentityKey)
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, inspectURLFor(inspectIdentityKey), nil)
	req.Header.Set("Authorization", inspectAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleInspect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var detail SessionDetail
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.RecentEvents == nil {
		t.Error("RecentEvents should be non-nil empty slice, not null")
	}
	if len(detail.RecentEvents) != 0 {
		t.Errorf("RecentEvents length: got %d, want 0", len(detail.RecentEvents))
	}
}
