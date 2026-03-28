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

	"github.com/luckyPipewrench/pipelock/internal/audit"
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
	logger   *audit.Logger
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
	logger *audit.Logger,
	apiToken string,
) *SessionAPIHandler {
	return &SessionAPIHandler{
		smPtr:       smPtr,
		etPtr:       etPtr,
		fbPtr:       fbPtr,
		metrics:     m,
		logger:      logger,
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
		clientIP, _ := requestMeta(r)
		h.logSessionAdmin("auth_failure", clientIP, "", "", http.StatusUnauthorized)
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

	clientIP, _ := requestMeta(r)
	h.logSessionAdmin("list", clientIP, "", "ok", http.StatusOK)

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

// extractSessionKey extracts the session key from /api/v1/sessions/{key}/reset.
// Uses EscapedPath + segment parsing to prevent path-traversal tricks
// (e.g. double-encoded slashes) that prefix/suffix slicing would miss.
func extractSessionKey(r *http.Request) (string, bool) {
	segs := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	// Expect exactly: api/v1/sessions/{encoded-key}/reset
	if len(segs) != 5 || segs[0] != "api" || segs[1] != "v1" || segs[2] != "sessions" || segs[4] != "reset" {
		return "", false
	}
	key, err := url.PathUnescape(segs[3])
	if err != nil || key == "" || strings.ContainsAny(key, "/\x00") {
		return "", false
	}
	return key, true
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

	clientIP, _ := requestMeta(r)

	if !h.checkResetRateLimit() {
		h.logSessionAdmin("reset_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key, ok := extractSessionKey(r)
	if !ok {
		h.logSessionAdmin("reset_bad_key", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	// Atomic lookup + kind check + reset under a single lock.
	// Eliminates the TOCTOU race where a session could be evicted or
	// replaced between a separate lookupSession and ResetSession call.
	prev, found, resetErr := sm.ResetSessionIfResettable(key)
	if !found {
		h.logSessionAdmin("reset_not_found", clientIP, key, "session not found", http.StatusNotFound)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if resetErr != nil {
		h.logSessionAdmin("reset_rejected", clientIP, key, "invocation key", http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: "cannot reset invocation session; only identity sessions are resettable"})
		return
	}

	_, agent, ip := classifySessionKey(key)

	// Clear CEE state AFTER the reset succeeds. This prevents clearing
	// CEE state as a side effect when the session is not found or not
	// resettable.
	ceeCleared := false
	if h.etPtr != nil && h.fbPtr != nil {
		et := h.etPtr.Load()
		fb := h.fbPtr.Load()
		if et != nil || fb != nil {
			ResetCEEState(agent, ip, et, fb)
			ceeCleared = true
		}
	}

	h.logSessionAdmin("reset_ok", clientIP, key, prev.EscalationLevel, http.StatusOK)

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

// logSessionAdmin logs a session admin API operation if a logger is available.
func (h *SessionAPIHandler) logSessionAdmin(action, clientIP, sessionKey, result string, statusCode int) {
	if h.logger != nil {
		h.logger.LogSessionAdmin(action, clientIP, sessionKey, result, statusCode)
	}
}
