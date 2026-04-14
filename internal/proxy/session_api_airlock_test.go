// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testAirlockEndpoint = "/api/v1/sessions/agent-a%7C10.0.0.1/airlock"
)

func TestSessionAPI_HandleAirlock_SoftTier(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("agent-a|10.0.0.1")

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`{"tier":"soft"}`)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp airlockResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.NewTier != "soft" {
		t.Errorf("expected new_tier=soft, got %s", resp.NewTier)
	}
	if !resp.Changed {
		t.Error("expected changed=true for none->soft transition")
	}
}

func TestSessionAPI_HandleAirlock_NormalRelease(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate("agent-a|10.0.0.1")
	sess.Airlock().ForceSetTier("soft")

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`{"tier":"normal"}`)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp airlockResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.NewTier != "none" {
		t.Errorf("expected new_tier=none (from 'normal' alias), got %s", resp.NewTier)
	}
	if resp.PreviousTier != "soft" {
		t.Errorf("expected previous_tier=soft, got %s", resp.PreviousTier)
	}
	if !resp.Changed {
		t.Error("expected changed=true for soft->none transition")
	}
}

func TestSessionAPI_HandleAirlock_InvalidTier(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("agent-a|10.0.0.1")

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`{"tier":"extreme"}`)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleAirlock_MissingBody(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("agent-a|10.0.0.1")

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleAirlock_InvalidJSON(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("agent-a|10.0.0.1")

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleAirlock_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodGet, testAirlockEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("expected Allow: POST, got %s", allow)
	}
}

func TestSessionAPI_HandleAirlock_NotFound(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`{"tier":"soft"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/nonexistent%7C10.0.0.1/airlock", body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleAirlock_Unauthorized(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`{"tier":"soft"}`)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
	// No Authorization header.
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleAirlock_BadKey(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`{"tier":"soft"}`)
	// Path with wrong number of segments.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/airlock", body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad key path, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleAirlock_SameTierNoop(t *testing.T) {
	t.Parallel()
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate("agent-a|10.0.0.1")
	sess.Airlock().ForceSetTier("hard")

	handler := newTestSessionAPIHandler(t, sm)
	body := strings.NewReader(`{"tier":"hard"}`)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleAirlock(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp airlockResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Changed {
		t.Error("expected changed=false for same-tier transition")
	}
}

// TestSessionAPI_HandleAirlock_RateLimited asserts that /airlock is
// gated by the same sliding-window limiter as /reset /task /trust. A
// flood of tier-transition calls must not be able to starve other admin
// endpoints nor mask a stuck session behind an infinite retry loop.
func TestSessionAPI_HandleAirlock_RateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("agent-a|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	// Exhaust the airlock limiter at the documented 10/min ceiling.
	for range sessionAPIRateLimitMax {
		body := strings.NewReader(`{"tier":"soft"}`)
		req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()
		handler.HandleAirlock(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request inside limit failed: code=%d body=%s", w.Code, w.Body.String())
		}
	}

	// One more request should 429 with a Retry-After header.
	body := strings.NewReader(`{"tier":"soft"}`)
	req := httptest.NewRequest(http.MethodPost, testAirlockEndpoint, body)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()
	handler.HandleAirlock(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after limit exhausted, got %d: %s", w.Code, w.Body.String())
	}
	if retry := w.Header().Get("Retry-After"); retry != "60" {
		t.Errorf("expected Retry-After: 60, got %q", retry)
	}
}

// TestSessionAPI_SetAPIToken_HotReload asserts that SetAPIToken rotates
// the bearer credential without a restart. Before the rotation, the old
// token authenticates; after, the old token is rejected and the new
// token is accepted. This proves the atomic.Pointer swap is live on the
// authenticate path and that operators can rotate kill_switch.api_token
// via SIGHUP without bouncing the proxy.
func TestSessionAPI_SetAPIToken_HotReload(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent-a|10.0.0.1")

	handler := newTestSessionAPIHandler(t, sm)

	// Old token accepted pre-rotation.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()
		handler.HandleList(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("pre-rotation: expected 200 with old token, got %d", w.Code)
		}
	}

	// Rotate to a new token.
	const newToken = "rotated-token-abc123"
	handler.SetAPIToken(newToken)

	// Old token must now be rejected.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()
		handler.HandleList(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("post-rotation: expected 401 with old token, got %d", w.Code)
		}
	}

	// New token must now be accepted.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+newToken)
		w := httptest.NewRecorder()
		handler.HandleList(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("post-rotation: expected 200 with new token, got %d", w.Code)
		}
	}

	// Rotating to empty string must disable the endpoint entirely —
	// operators use this to revoke access without tearing down the
	// listener. authenticate returns 503 (not configured), matching
	// the bootstrap path when no api_token is in the YAML.
	handler.SetAPIToken("")
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+newToken)
		w := httptest.NewRecorder()
		handler.HandleList(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("post-revoke: expected 503, got %d", w.Code)
		}
	}
}

func TestExtractSessionKeyWithAction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   string
		action string
		want   string
		wantOK bool
	}{
		{"valid airlock", "/api/v1/sessions/agent-a%7C10.0.0.1/airlock", "airlock", "agent-a|10.0.0.1", true},
		{"valid reset", "/api/v1/sessions/agent-b%7C10.0.0.2/reset", "reset", "agent-b|10.0.0.2", true},
		{"wrong action", "/api/v1/sessions/agent-a%7C10.0.0.1/reset", "airlock", "", false},
		{"too few segments", "/api/v1/sessions/airlock", "airlock", "", false},
		{"too many segments", "/api/v1/sessions/key/airlock/extra", "airlock", "", false},
		{"empty key", "/api/v1/sessions//airlock", "airlock", "", false},
		{"null byte in key", "/api/v1/sessions/agent%00a/airlock", "airlock", "", false},
		{"slash in key", "/api/v1/sessions/agent%2Fa/airlock", "airlock", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			got, ok := extractSessionKeyWithAction(req, tt.action)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("key = %q, want %q", got, tt.want)
			}
		})
	}
}
