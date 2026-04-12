// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const testSessionAPIToken = "test-session-api-token"

func setupSessionAPITestManager(t *testing.T) (*SessionManager, func()) {
	t.Helper()
	cfg := &config.SessionProfiling{
		MaxSessions:            100,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 300,
		DomainBurst:            10,
		WindowMinutes:          5,
	}
	sm := NewSessionManager(cfg, nil, metrics.New())
	return sm, func() { sm.Close() }
}

func newTestSessionAPIHandler(t *testing.T, sm *SessionManager) *SessionAPIHandler {
	t.Helper()
	var smPtr atomic.Pointer[SessionManager]
	if sm != nil {
		smPtr.Store(sm)
	}
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	return NewSessionAPIHandler(&smPtr, &etPtr, &fbPtr, nil, audit.NewNop(), testSessionAPIToken)
}

func TestSessionAPI_HandleList(t *testing.T) {
	t.Run("returns sessions sorted", func(t *testing.T) {
		sm, cleanup := setupSessionAPITestManager(t)
		defer cleanup()

		sm.GetOrCreate("zebra|10.0.0.1")
		sm.GetOrCreate("alpha|10.0.0.2")
		sm.GetOrCreate("mcp-stdio-1")

		handler := newTestSessionAPIHandler(t, sm)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()

		handler.HandleList(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp struct {
			Sessions []SessionSnapshot `json:"sessions"`
			Count    int               `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Count != 3 {
			t.Fatalf("expected 3 sessions, got %d", resp.Count)
		}
		if resp.Sessions[0].Key != "alpha|10.0.0.2" {
			t.Errorf("first: got %q, want alpha|10.0.0.2", resp.Sessions[0].Key)
		}
		if resp.Sessions[2].Kind != sessionKindInvocation {
			t.Errorf("last should be invocation, got %q", resp.Sessions[2].Kind)
		}
	})

	t.Run("unauthorized without token", func(t *testing.T) {
		sm, cleanup := setupSessionAPITestManager(t)
		defer cleanup()

		handler := newTestSessionAPIHandler(t, sm)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		w := httptest.NewRecorder()

		handler.HandleList(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("unauthorized with wrong token", func(t *testing.T) {
		sm, cleanup := setupSessionAPITestManager(t)
		defer cleanup()

		handler := newTestSessionAPIHandler(t, sm)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()

		handler.HandleList(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("profiling disabled", func(t *testing.T) {
		handler := newTestSessionAPIHandler(t, nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()

		handler.HandleList(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", w.Code)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		sm, cleanup := setupSessionAPITestManager(t)
		defer cleanup()

		handler := newTestSessionAPIHandler(t, sm)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()

		handler.HandleList(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})

	t.Run("empty sessions", func(t *testing.T) {
		sm, cleanup := setupSessionAPITestManager(t)
		defer cleanup()

		handler := newTestSessionAPIHandler(t, sm)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()

		handler.HandleList(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Count != 0 {
			t.Errorf("expected 0 sessions, got %d", resp.Count)
		}
	})

	t.Run("no token configured", func(t *testing.T) {
		sm, cleanup := setupSessionAPITestManager(t)
		defer cleanup()

		var smPtr atomic.Pointer[SessionManager]
		smPtr.Store(sm)
		var etPtr atomic.Pointer[scanner.EntropyTracker]
		var fbPtr atomic.Pointer[scanner.FragmentBuffer]
		handler := NewSessionAPIHandler(&smPtr, &etPtr, &fbPtr, nil, audit.NewNop(), "") // empty token

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		w := httptest.NewRecorder()

		handler.HandleList(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 when no token configured, got %d", w.Code)
		}
	})
}

func TestSessionAPI_HandleReset_Success(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate("agent-a|10.0.0.1")
	sess.RecordSignal(session.SignalBlock, 1.0)
	sess.RecordSignal(session.SignalBlock, 1.0)
	sess.SetBlockAll(true)

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent-a%7C10.0.0.1/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleReset(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Key           string  `json:"key"`
		Reset         bool    `json:"reset"`
		PreviousLevel string  `json:"previous_level"`
		PreviousScore float64 `json:"previous_score"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Reset {
		t.Error("expected reset=true")
	}
	if resp.PreviousScore == 0 {
		t.Error("expected non-zero previous score")
	}
	if sess.ThreatScore() != 0 {
		t.Error("session should be reset to zero score")
	}
	if sess.BlockAll() {
		t.Error("blockAll should be cleared")
	}
}

func TestSessionAPI_HandleTask_Success(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate("agent-a|10.0.0.1")
	sess.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})
	before := sess.TaskSnapshot()

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent-a%7C10.0.0.1/task", strings.NewReader(`{"label":"new task","reason":"user started a new task"}`))
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleTask(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		PreviousTaskID          string `json:"previous_task_id"`
		CurrentTaskID           string `json:"current_task_id"`
		RuntimeOverridesCleared int    `json:"runtime_overrides_cleared"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.PreviousTaskID != before.CurrentTaskID {
		t.Fatalf("previous_task_id = %q, want %q", resp.PreviousTaskID, before.CurrentTaskID)
	}
	if resp.CurrentTaskID == "" || resp.CurrentTaskID == resp.PreviousTaskID {
		t.Fatalf("expected rotated task id, got %q", resp.CurrentTaskID)
	}
	if sess.RiskSnapshot().Contaminated {
		t.Fatal("task boundary should clear taint contamination")
	}
}

func TestSessionAPI_HandleTrust_Success(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate("agent-a|10.0.0.1")
	task := sess.TaskSnapshot()

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent-a%7C10.0.0.1/trust", strings.NewReader(fmt.Sprintf(`{"scope":"task","action_match":"publish:post:https://api.example.com/auth/update","expires_at":"%s","granted_by":"operator","reason":"same-task follow-up"}`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))))
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleTrust(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		TaskID      string `json:"task_id"`
		ActionMatch string `json:"action_match"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TaskID != task.CurrentTaskID {
		t.Fatalf("task_id = %q, want %q", resp.TaskID, task.CurrentTaskID)
	}
	overrides := sess.RuntimeTrustOverrides()
	if len(overrides) != 1 {
		t.Fatalf("runtime overrides = %d, want 1", len(overrides))
	}
	if overrides[0].TaskID != task.CurrentTaskID {
		t.Fatalf("override task_id = %q, want %q", overrides[0].TaskID, task.CurrentTaskID)
	}
	if overrides[0].ActionMatch != resp.ActionMatch {
		t.Fatalf("override action_match = %q, want %q", overrides[0].ActionMatch, resp.ActionMatch)
	}
}

func TestSessionAPI_HandleReset_InvocationKeyRejected(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("mcp-stdio-42")

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/mcp-stdio-42/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleReset(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleReset_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/nonexistent%7C10.0.0.1/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleReset(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleReset_RateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("agent|10.0.0.1")

	handler := newTestSessionAPIHandler(t, sm)

	// Exhaust the rate limit (10 requests per window).
	for range sessionAPIRateLimitMax {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent%7C10.0.0.1/reset", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()
		handler.HandleReset(w, req)
	}

	// 11th request should be rate-limited.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent%7C10.0.0.1/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()
	handler.HandleReset(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if retry := w.Header().Get("Retry-After"); retry != "60" {
		t.Errorf("expected Retry-After: 60, got %q", retry)
	}
}

func TestSessionAPI_HandleList_NotRateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	handler := newTestSessionAPIHandler(t, sm)

	// Send more requests than the reset rate limit to prove list is unaffected.
	for range sessionAPIRateLimitMax + 5 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()
		handler.HandleList(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatal("GET /sessions should not be rate limited")
		}
	}
}

// TestSessionAPI_RateLimiters_Independent asserts that flooding one
// admin endpoint does not starve another. Each mutating endpoint
// has its own sliding-window limiter so an attacker (or a runaway
// script) exhausting /task cannot prevent a legitimate operator
// from hitting /reset during incident response.
func TestSessionAPI_RateLimiters_Independent(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	// Exhaust the /task limiter.
	for range sessionAPIRateLimitMax {
		req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", "")
		w := httptest.NewRecorder()
		handler.HandleTask(w, req)
	}
	// One more /task request should 429 — the limiter is exhausted.
	{
		req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", "")
		w := httptest.NewRecorder()
		handler.HandleTask(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("exhausted /task should 429, got %d", w.Code)
		}
	}
	// /reset on the same handler must still succeed — its limiter
	// has not been touched.
	{
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent%7C10.0.0.1/reset", nil)
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		w := httptest.NewRecorder()
		handler.HandleReset(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatal("/task flood should not starve /reset; got 429")
		}
		if w.Code != http.StatusOK {
			t.Fatalf("/reset expected 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	// /trust also has its own limiter and should still be fresh.
	{
		req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
			`{"scope":"task","action_match":"x","expires_at":"`+futureTimestamp()+`"}`)
		w := httptest.NewRecorder()
		handler.HandleTrust(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatal("/task flood should not starve /trust; got 429")
		}
	}
}

// TestSessionAPI_CheckRateLimit_UnknownActionDenies covers the
// defensive fail-closed path when a bug asks the limiter about an
// action that was never registered. The code must NOT silently
// bypass limiting — it must deny.
func TestSessionAPI_CheckRateLimit_UnknownActionDenies(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	if handler.checkRateLimit("nonexistent-action") {
		t.Fatal("unknown action should fail-closed, got allowed")
	}
}

func TestSessionAPI_HandleReset_MethodNotAllowed(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/agent%7C10.0.0.1/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleReset(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("expected Allow: POST, got %q", allow)
	}
}

func TestSessionAPI_HandleReset_DecrementEscalatedMetrics(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate("agent-b|10.0.0.2")
	// Push session to "elevated" by accumulating signals.
	for range 4 {
		sess.RecordSignal(session.SignalBlock, 1.0)
	}

	m := metrics.New()
	var smPtr atomic.Pointer[SessionManager]
	smPtr.Store(sm)
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	handler := NewSessionAPIHandler(&smPtr, &etPtr, &fbPtr, m, audit.NewNop(), testSessionAPIToken)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent-b%7C10.0.0.2/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleReset(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		PreviousLevel string `json:"previous_level"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The session should have been escalated above "normal" before reset.
	if resp.PreviousLevel == "normal" {
		t.Error("expected escalated level before reset, got normal")
	}
}

func TestExtractSessionKey(t *testing.T) {
	// extractSessionKey uses EscapedPath + segment parsing.
	// URL-encoded keys (e.g. %7C for |) are unescaped by the function.
	tests := []struct {
		url  string
		want string
		ok   bool
	}{
		{"/api/v1/sessions/agent%7C10.0.0.1/reset", "agent|10.0.0.1", true},
		{"/api/v1/sessions/10.0.0.1/reset", "10.0.0.1", true},
		{"/api/v1/sessions/mcp-stdio-42/reset", "mcp-stdio-42", true},
		{"/api/v1/sessions//reset", "", false},            // empty key segment
		{"/api/v1/sessions", "", false},                   // wrong segment count
		{"/other/path", "", false},                        // wrong prefix
		{"/api/v1/sessions/key%00evil/reset", "", false},  // null byte rejected
		{"/api/v1/sessions/key%2Fslash/reset", "", false}, // embedded slash rejected
		{"/api/v1/sessions/a/b/extra/reset", "", false},   // extra segments
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tt.url, nil)
			got, ok := extractSessionKey(r)
			if ok != tt.ok {
				t.Errorf("extractSessionKey(%q) ok = %v, want %v", tt.url, ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("extractSessionKey(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestSessionState_IsResettable(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	identity := sm.GetOrCreate("agent|10.0.0.1")
	if !identity.IsResettable() {
		t.Error("identity session should be resettable")
	}

	invocation := sm.GetOrCreate("mcp-stdio-42")
	if invocation.IsResettable() {
		t.Error("invocation session should not be resettable")
	}

	invocationHTTP := sm.GetOrCreate("mcp-http-99")
	if invocationHTTP.IsResettable() {
		t.Error("mcp-http invocation session should not be resettable")
	}

	invocationWS := sm.GetOrCreate("mcp-ws-77")
	if invocationWS.IsResettable() {
		t.Error("mcp-ws invocation session should not be resettable")
	}

	// IP-only key (no agent header) should be identity.
	ipOnly := sm.GetOrCreate("10.0.0.5")
	if !ipOnly.IsResettable() {
		t.Error("IP-only session should be resettable (identity kind)")
	}
}

func TestSessionAPI_IntegrationViaProxy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 100
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 300
	cfg.SessionProfiling.DomainBurst = 10
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 1.0
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.1
	cfg.KillSwitch.APIToken = testSessionAPIToken

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("expected session manager with profiling enabled")
	}
	sess := sm.GetOrCreate("test-agent|10.0.0.1")
	sess.RecordSignal(session.SignalBlock, 1.0)

	handler := p.buildHandler(p.buildMux())

	// List sessions via the proxy handler.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	listReq.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", listW.Code, listW.Body.String())
	}

	// Reset session via the proxy handler.
	resetReq := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/test-agent%7C10.0.0.1/reset", nil)
	resetReq.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	resetW := httptest.NewRecorder()
	handler.ServeHTTP(resetW, resetReq)

	if resetW.Code != http.StatusOK {
		t.Fatalf("reset: expected 200, got %d: %s", resetW.Code, resetW.Body.String())
	}

	if sess.ThreatScore() != 0 {
		t.Error("session should be reset after API call")
	}
}

func TestSessionAPI_HandleReset_ClearsCEEState(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	et := scanner.NewEntropyTracker(100, 60)
	defer et.Close()
	fb := scanner.NewFragmentBuffer(4096, 100, 60)
	defer fb.Close()

	sm.GetOrCreate("agent|10.0.0.1")

	// Build up CEE state.
	key := CeeSessionKey("agent", "10.0.0.1")
	et.Record(key, []byte("high-entropy-payload-for-testing"))
	fb.Append(key, []byte("fragment-data"))
	fb.Append(key+"|keys", []byte("keys-data"))

	if et.CurrentUsage(key) == 0 {
		t.Fatal("expected non-zero entropy before reset")
	}

	// Create handler with real CEE pointers.
	var smPtr atomic.Pointer[SessionManager]
	smPtr.Store(sm)
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	etPtr.Store(et)
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	fbPtr.Store(fb)
	handler := NewSessionAPIHandler(&smPtr, &etPtr, &fbPtr, nil, audit.NewNop(), testSessionAPIToken)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent%7C10.0.0.1/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()

	handler.HandleReset(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Entropy should be cleared.
	if et.CurrentUsage(key) != 0 {
		t.Error("entropy should be cleared after reset")
	}

	var resp struct {
		CEEStateCleared bool `json:"cee_state_cleared"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.CEEStateCleared {
		t.Error("expected cee_state_cleared=true")
	}
}

func TestSessionAPI_ResetUnderConcurrentTraffic(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 100
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 300
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 100
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.01
	cfg.KillSwitch.APIToken = testSessionAPIToken

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	sm.GetOrCreate("agent|10.0.0.1")

	handler := p.buildHandler(p.buildMux())

	// Deadline watchdog: deadlock = timeout failure.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)

		var wg sync.WaitGroup

		// Hot-path traffic goroutines.
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, "ok")
		}))
		defer backend.Close()

		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 50 {
					_ = i
					select {
					case <-ctx.Done():
						return
					default:
					}
					req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/", nil)
					req.RemoteAddr = testRemoteAddr3
					req.Header.Set("X-Pipelock-Agent", "agent")
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, req)
				}
			}()
		}

		// Interleave reset calls.
		for range 20 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent%7C10.0.0.1/reset", nil)
			req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}

		wg.Wait()
	}()

	select {
	case <-done:
		// Success — completed without deadlock.
	case <-ctx.Done():
		t.Fatal("deadlock detected: test did not complete within timeout")
	}
}

// --- HandleTask coverage: error and guard paths ---

// futureTimestamp builds a valid expires_at string one hour in the future
// for trust-override request bodies. Extracted to avoid reading time.RFC3339
// in every test literal.
func futureTimestamp() string {
	return time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
}

// newTaskRequest constructs a POST /task request with the given body reader
// and standard auth header. Returns the request ready for ServeHTTP.
func newTaskRequest(method, key, body string) *http.Request {
	path := "/api/v1/sessions/" + url.PathEscape(key) + "/task"
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	return req
}

// newTrustRequest constructs a POST /trust request with the given body and
// auth header.
func newTrustRequest(method, key, body string) *http.Request {
	path := "/api/v1/sessions/" + url.PathEscape(key) + "/trust"
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	return req
}

func TestSessionAPI_HandleTask_MethodNotAllowed(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := newTaskRequest(http.MethodGet, "agent|10.0.0.1", "")
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("expected Allow: POST, got %q", allow)
	}
}

func TestSessionAPI_HandleTask_Unauthorized(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent%7C10.0.0.1/task", nil)
	// No Authorization header.
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTask_RateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	// Task and reset share the same limiter — exhaust it via /task.
	for range sessionAPIRateLimitMax {
		req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", "")
		w := httptest.NewRecorder()
		handler.HandleTask(w, req)
	}
	req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", "")
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if retry := w.Header().Get("Retry-After"); retry != "60" {
		t.Errorf("expected Retry-After: 60, got %q", retry)
	}
}

func TestSessionAPI_HandleTask_ProfilingDisabled(t *testing.T) {
	handler := newTestSessionAPIHandler(t, nil) // nil SessionManager
	req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", "")
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTask_BadKey(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	// Path missing the session key entirely.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions//task", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTask_BadBody(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", `{"label":`) // truncated JSON
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleTask_UnknownField(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", `{"label":"x","unknown_field":true}`)
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleTask_TrailingData(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	// Two JSON objects back-to-back should be rejected.
	req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", `{"label":"a"}{"label":"b"}`)
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing data, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleTask_EmptyBodyOK(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	// Empty body is allowed for HandleTask — rotates the task with no
	// label/reason. This was the chunked-body case CodeRabbit flagged.
	req := newTaskRequest(http.MethodPost, "agent|10.0.0.1", "")
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty body, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleTask_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := newTaskRequest(http.MethodPost, "ghost|10.0.0.1", `{}`)
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestSessionAPI_HandleTask_InvocationKeyRejected is the GPT-flagged
// privilege-boundary bypass regression. Invocation sessions (ephemeral
// per-request MCP keys) must not be mutable via /task, mirroring the
// HandleReset guardrail.
func TestSessionAPI_HandleTask_InvocationKeyRejected(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("mcp-stdio-42") // classifies as invocation (no pipe)
	handler := newTestSessionAPIHandler(t, sm)

	req := newTaskRequest(http.MethodPost, "mcp-stdio-42", `{"label":"attempt"}`)
	w := httptest.NewRecorder()
	handler.HandleTask(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invocation key, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invocation session") {
		t.Errorf("expected invocation-session error, got %q", w.Body.String())
	}
}

// --- HandleTrust coverage: error and guard paths ---

func TestSessionAPI_HandleTrust_MethodNotAllowed(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodGet, "agent|10.0.0.1", "")
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_Unauthorized(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/agent%7C10.0.0.1/trust", nil)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_RateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	for range sessionAPIRateLimitMax {
		req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
			`{"scope":"task","action_match":"x","expires_at":"`+futureTimestamp()+`"}`)
		w := httptest.NewRecorder()
		handler.HandleTrust(w, req)
	}
	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
		`{"scope":"task","action_match":"x","expires_at":"`+futureTimestamp()+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_ProfilingDisabled(t *testing.T) {
	handler := newTestSessionAPIHandler(t, nil)
	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
		`{"scope":"task","action_match":"x","expires_at":"`+futureTimestamp()+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_BadKey(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions//trust", nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_BadBody(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1", `{not-json`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_UnknownField(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
		`{"scope":"task","action_match":"x","expires_at":"`+futureTimestamp()+`","wildcard":true}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_BadScope(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
		`{"scope":"source","source_match":"https://x","expires_at":"`+futureTimestamp()+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-task scope, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_NoMatchPattern(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
		`{"scope":"task","expires_at":"`+futureTimestamp()+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing match, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_ExpiredOrMissing(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	// Past expiry.
	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
		`{"scope":"task","action_match":"x","expires_at":"`+time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for past expiry, got %d", w.Code)
	}
}

func TestSessionAPI_HandleTrust_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodPost, "ghost|10.0.0.1",
		`{"scope":"task","action_match":"x","expires_at":"`+futureTimestamp()+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestSessionAPI_HandleTrust_InvocationKeyRejected is the GPT-flagged
// privilege-boundary bypass regression for HandleTrust.
func TestSessionAPI_HandleTrust_InvocationKeyRejected(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("mcp-stdio-7")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodPost, "mcp-stdio-7",
		`{"scope":"task","action_match":"publish:*","expires_at":"`+futureTimestamp()+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invocation key, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invocation session") {
		t.Errorf("expected invocation-session error, got %q", w.Body.String())
	}
}

func TestSessionAPI_HandleTrust_SourceMatchOnly(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate("agent|10.0.0.1")
	handler := newTestSessionAPIHandler(t, sm)

	req := newTrustRequest(http.MethodPost, "agent|10.0.0.1",
		`{"scope":"task","source_match":"https://docs.example","expires_at":"`+futureTimestamp()+`"}`)
	w := httptest.NewRecorder()
	handler.HandleTrust(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- decodeJSONBody unit coverage ---

func TestDecodeJSONBody(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	cases := []struct {
		name    string
		body    string
		wantErr bool
		wantVal string
	}{
		{name: "valid", body: `{"name":"alice"}`, wantErr: false, wantVal: "alice"},
		{name: "empty_body", body: "", wantErr: false, wantVal: ""},
		{name: "unknown_field", body: `{"name":"x","extra":1}`, wantErr: true},
		{name: "trailing_data", body: `{"name":"a"}garbage`, wantErr: true},
		{name: "malformed", body: `{bad`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r io.Reader
			if tc.body != "" {
				r = strings.NewReader(tc.body)
			}
			req := httptest.NewRequest(http.MethodPost, "/x", r)
			var v payload
			err := decodeJSONBody(req, &v)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr && v.Name != tc.wantVal {
				t.Fatalf("Name = %q, want %q", v.Name, tc.wantVal)
			}
		})
	}
}

// TestDecodeJSONBody_NilBody confirms the nil-body early return path.
func TestDecodeJSONBody_NilBody(t *testing.T) {
	var v struct {
		Name string `json:"name"`
	}
	r := &http.Request{Body: nil}
	if err := decodeJSONBody(r, &v); err != nil {
		t.Fatalf("nil body should return nil error, got %v", err)
	}
}

// TestDecodeJSONBody_SizeLimit confirms the size limit truncates input and
// causes a decode error for oversized payloads.
func TestDecodeJSONBody_SizeLimit(t *testing.T) {
	// Build a body larger than sessionAPIMaxBodyBytes with a valid opening.
	big := `{"name":"` + strings.Repeat("a", sessionAPIMaxBodyBytes+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(big))
	var v struct {
		Name string `json:"name"`
	}
	err := decodeJSONBody(req, &v)
	if err == nil {
		t.Fatal("expected decode error on oversized body, got nil")
	}
}

// --- SessionManager guard coverage ---

// TestSessionManager_BeginNewTask_InvocationRejected asserts the guard at
// the SessionManager layer rejects invocation sessions directly (not just
// via the HTTP handler).
func TestSessionManager_BeginNewTask_InvocationRejected(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("mcp-stdio-99")
	_, _, _, found, err := sm.BeginNewTask("mcp-stdio-99", "label")
	if !found {
		t.Fatal("expected found=true for existing invocation session")
	}
	if !errors.Is(err, ErrInvocationReset) {
		t.Fatalf("err = %v, want ErrInvocationReset", err)
	}
}

// TestSessionManager_AddRuntimeTrustOverride_InvocationRejected asserts
// the guard at the SessionManager layer for AddRuntimeTrustOverride.
func TestSessionManager_AddRuntimeTrustOverride_InvocationRejected(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("mcp-stdio-101")
	override := session.TrustOverride{
		Scope:       "task",
		ActionMatch: "x",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	_, found, err := sm.AddRuntimeTrustOverride("mcp-stdio-101", override)
	if !found {
		t.Fatal("expected found=true for existing invocation session")
	}
	if !errors.Is(err, ErrInvocationReset) {
		t.Fatalf("err = %v, want ErrInvocationReset", err)
	}
}

// TestSessionManager_BeginNewTask_NotFound covers the no-session path.
func TestSessionManager_BeginNewTask_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	_, _, _, found, err := sm.BeginNewTask("no-such-session", "")
	if found {
		t.Fatal("expected found=false for nonexistent session")
	}
	if err != nil {
		t.Fatalf("expected nil err for not-found, got %v", err)
	}
}

// TestSessionManager_AddRuntimeTrustOverride_NotFound covers the
// no-session path for the trust override API.
func TestSessionManager_AddRuntimeTrustOverride_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	override := session.TrustOverride{
		Scope:       "task",
		ActionMatch: "x",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	_, found, err := sm.AddRuntimeTrustOverride("no-such-session", override)
	if found {
		t.Fatal("expected found=false for nonexistent session")
	}
	if err != nil {
		t.Fatalf("expected nil err for not-found, got %v", err)
	}
}

// TestSessionManager_AddRuntimeTrustOverride_WrongScope covers the
// ErrTaskScopeOnly branch.
func TestSessionManager_AddRuntimeTrustOverride_WrongScope(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sm.GetOrCreate("agent|10.0.0.1")
	override := session.TrustOverride{
		Scope:       "source",
		SourceMatch: "https://docs.example",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
	_, found, err := sm.AddRuntimeTrustOverride("agent|10.0.0.1", override)
	if found {
		t.Errorf("expected found=false when scope is wrong, got true")
	}
	if !errors.Is(err, ErrTaskScopeOnly) {
		t.Fatalf("err = %v, want ErrTaskScopeOnly", err)
	}
}

// TestSessionManager_WithMutableIdentitySession_BlocksConcurrentWriteLock
// proves the helper keeps sm.mu.RLock held for the full callback duration.
// A concurrent writer must stay blocked until the mutation callback returns.
func TestSessionManager_WithMutableIdentitySession_BlocksConcurrentWriteLock(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	const targetKey = "agent|10.0.0.1"
	sm.GetOrCreate(targetKey)

	entered := make(chan struct{})
	releaseMutation := make(chan struct{})
	resultCh := make(chan struct {
		found bool
		err   error
	}, 1)

	go func() {
		found, err := sm.withMutableIdentitySession(targetKey, func(_ *SessionState) {
			close(entered)
			<-releaseMutation
		})
		resultCh <- struct {
			found bool
			err   error
		}{found: found, err: err}
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("mutation callback did not start")
	}

	writerStarted := make(chan struct{})
	writerAcquired := make(chan struct{})
	writerRelease := make(chan struct{})
	go func() {
		close(writerStarted)
		sm.mu.Lock()
		close(writerAcquired)
		<-writerRelease
		sm.mu.Unlock()
	}()

	// Wait for the writer goroutine to be scheduled before checking it
	// stays blocked. Without this handshake, a slow scheduler could make
	// the 50ms window pass before the goroutine even reaches sm.mu.Lock().
	select {
	case <-writerStarted:
	case <-time.After(time.Second):
		t.Fatal("writer goroutine did not start")
	}

	select {
	case <-writerAcquired:
		t.Fatal("concurrent writer acquired sm.mu while mutation callback was active")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseMutation)

	select {
	case res := <-resultCh:
		if !res.found {
			t.Fatal("expected found=true for existing identity session")
		}
		if res.err != nil {
			t.Fatalf("unexpected mutation err: %v", res.err)
		}
	case <-time.After(time.Second):
		t.Fatal("mutation did not complete after release")
	}

	select {
	case <-writerAcquired:
	case <-time.After(time.Second):
		t.Fatal("concurrent writer did not acquire sm.mu after mutation completed")
	}
	close(writerRelease)
}

// TestSessionManager_WithMutableIdentitySession_BlocksEvictionDuringMutation
// proves that eviction-triggering writes stay blocked until the mutation
// callback returns. This is the stale-pointer race that BeginNewTask and
// AddRuntimeTrustOverride rely on withMutableIdentitySession to prevent.
func TestSessionManager_WithMutableIdentitySession_BlocksEvictionDuringMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SessionState) string
	}{
		{
			name: "begin new task",
			mutate: func(sess *SessionState) string {
				_, current, _ := sess.BeginNewTask("coordinated-task")
				return current.CurrentTaskID
			},
		},
		{
			name: "runtime trust override",
			mutate: func(sess *SessionState) string {
				applied := sess.AddRuntimeTrustOverride(session.TrustOverride{
					Scope:       "task",
					ActionMatch: "publish:*",
					ExpiresAt:   time.Now().UTC().Add(time.Hour),
					Reason:      "lock-span regression",
				})
				return applied.TaskID
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewSessionManager(&config.SessionProfiling{
				MaxSessions:            1,
				SessionTTLMinutes:      30,
				CleanupIntervalSeconds: 300,
				DomainBurst:            10,
				WindowMinutes:          5,
			}, nil, nil)
			defer sm.Close()

			const targetKey = "agent|10.0.0.1"
			sm.GetOrCreate(targetKey)

			entered := make(chan struct{})
			releaseMutation := make(chan struct{})
			resultCh := make(chan struct {
				found     bool
				err       error
				mutatedID string
			}, 1)

			go func() {
				var mutatedID string
				found, err := sm.withMutableIdentitySession(targetKey, func(sess *SessionState) {
					close(entered)
					<-releaseMutation
					mutatedID = tt.mutate(sess)
				})
				resultCh <- struct {
					found     bool
					err       error
					mutatedID string
				}{found: found, err: err, mutatedID: mutatedID}
			}()

			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("mutation callback did not start")
			}

			evictStarted := make(chan struct{})
			evictDone := make(chan struct{})
			go func() {
				close(evictStarted)
				sm.GetOrCreate("evictor|10.0.0.2")
				close(evictDone)
			}()

			select {
			case <-evictStarted:
			case <-time.After(time.Second):
				t.Fatal("evictor goroutine did not start")
			}

			select {
			case <-evictDone:
				t.Fatal("GetOrCreate completed before mutation released sm.mu.RLock")
			case <-time.After(50 * time.Millisecond):
			}

			close(releaseMutation)

			var mutatedID string
			select {
			case res := <-resultCh:
				if !res.found {
					t.Fatal("expected found=true for existing identity session")
				}
				if res.err != nil {
					t.Fatalf("unexpected mutation err: %v", res.err)
				}
				if res.mutatedID == "" {
					t.Fatal("mutation did not produce a task ID")
				}
				mutatedID = res.mutatedID
			case <-time.After(time.Second):
				t.Fatal("mutation did not complete after release")
			}

			select {
			case <-evictDone:
			case <-time.After(time.Second):
				t.Fatal("eviction-triggering GetOrCreate did not resume after mutation completed")
			}

			if got := sm.GetOrCreate(targetKey).TaskSnapshot().CurrentTaskID; got == mutatedID {
				t.Fatalf("expected target session to be replaced after eviction, but live task ID %s still matches the pre-eviction mutation", got)
			}
		})
	}
}
