// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Rate limiting constants for the session reset endpoint.
const (
	sessionAPIRateLimitWindow = time.Minute
	sessionAPIRateLimitMax    = 10
)

// SessionAPIHandler handles the admin session management API.
type SessionAPIHandler struct {
	smPtr    *atomic.Pointer[SessionManager]
	etPtr    *atomic.Pointer[scanner.EntropyTracker]
	fbPtr    *atomic.Pointer[scanner.FragmentBuffer]
	metrics  *metrics.Metrics
	apiToken string

	mu          sync.Mutex
	reqCount    int
	windowStart time.Time
}

// NewSessionAPIHandler creates a session API handler.
func NewSessionAPIHandler(
	smPtr *atomic.Pointer[SessionManager],
	etPtr *atomic.Pointer[scanner.EntropyTracker],
	fbPtr *atomic.Pointer[scanner.FragmentBuffer],
	m *metrics.Metrics,
	apiToken string,
) *SessionAPIHandler {
	return &SessionAPIHandler{
		smPtr:       smPtr,
		etPtr:       etPtr,
		fbPtr:       fbPtr,
		metrics:     m,
		apiToken:    apiToken,
		windowStart: time.Now(),
	}
}

func (h *SessionAPIHandler) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if h.apiToken == "" {
		http.Error(w, "session API not configured (no api_token)", http.StatusServiceUnavailable)
		return false
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	var token string
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		token = auth[len(prefix):]
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(h.apiToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pipelock"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (h *SessionAPIHandler) loadManager(w http.ResponseWriter) *SessionManager {
	sm := h.smPtr.Load()
	if sm == nil {
		http.Error(w, "session profiling disabled", http.StatusServiceUnavailable)
		return nil
	}
	return sm
}

// HandleList handles GET /api/v1/sessions.
func (h *SessionAPIHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}
	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	snaps := sm.Snapshot()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Sessions []SessionSnapshot `json:"sessions"`
		Count    int               `json:"count"`
	}{
		Sessions: snaps,
		Count:    len(snaps),
	})
}

// checkResetRateLimit enforces a sliding-window rate limit on reset requests.
// Returns true if the request is within the limit.
func (h *SessionAPIHandler) checkResetRateLimit() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	if now.Sub(h.windowStart) > sessionAPIRateLimitWindow {
		h.reqCount = 0
		h.windowStart = now
	}
	h.reqCount++
	return h.reqCount <= sessionAPIRateLimitMax
}

// extractSessionKey extracts the URL-decoded session key from /api/v1/sessions/{key}/reset.
func extractSessionKey(path string) string {
	const prefix = "/api/v1/sessions/"
	const suffix = "/reset"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	encoded := path[len(prefix) : len(path)-len(suffix)]
	if encoded == "" {
		return ""
	}
	decoded, err := url.PathUnescape(encoded)
	if err != nil {
		return ""
	}
	return decoded
}

// HandleReset handles POST /api/v1/sessions/{key}/reset.
func (h *SessionAPIHandler) HandleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}
	if !h.checkResetRateLimit() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key := extractSessionKey(r.URL.Path)
	if key == "" {
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	// Reject invocation keys (MCP transport sessions are not resettable).
	kind, agent, ip := classifySessionKey(key)
	if kind == sessionKindInvocation {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: "cannot reset invocation session; only identity sessions are resettable"})
		return
	}

	// Lock order: CEE first, then SessionManager, then SessionState.
	ceeCleared := false
	if h.etPtr != nil && h.fbPtr != nil {
		et := h.etPtr.Load()
		fb := h.fbPtr.Load()
		if et != nil || fb != nil {
			ResetCEEState(agent, ip, et, fb)
			ceeCleared = true
		}
	}

	prev, found := sm.ResetSession(key)
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Update metrics gauge if session was escalated.
	if prev.EscalationLevel != "normal" && h.metrics != nil {
		h.metrics.SetAdaptiveSessionLevel(prev.EscalationLevel, -1)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Key             string  `json:"key"`
		Reset           bool    `json:"reset"`
		PreviousLevel   string  `json:"previous_level"`
		PreviousScore   float64 `json:"previous_score"`
		IPStateCleared  bool    `json:"ip_state_cleared"`
		CEEStateCleared bool    `json:"cee_state_cleared"`
	}{
		Key:             key,
		Reset:           true,
		PreviousLevel:   prev.EscalationLevel,
		PreviousScore:   prev.ThreatScore,
		IPStateCleared:  ip != "",
		CEEStateCleared: ceeCleared,
	})
}
