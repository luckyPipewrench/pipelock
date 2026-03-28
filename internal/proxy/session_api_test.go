// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
