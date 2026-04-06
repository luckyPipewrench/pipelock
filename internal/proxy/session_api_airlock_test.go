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
