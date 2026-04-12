// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// Rate limiting constants for the session reset endpoint.
const (
	sessionAPIRateLimitWindow = time.Minute
	sessionAPIRateLimitMax    = 10
)

// sessionAPIMaxBodyBytes caps the size of admin API request bodies. These
// endpoints accept small JSON (tier, label, trust override) and have no
// reason to read more. The limit defends against slow-body DoS and
// accidental large uploads.
const sessionAPIMaxBodyBytes = 64 * 1024 // 64 KiB

// decodeJSONBody is the shared strict decoder for admin API endpoints.
// It enforces:
//   - a hard size limit via io.LimitReader (defends against large bodies)
//   - DisallowUnknownFields (rejects typos and field injection attempts)
//   - exactly-one-JSON-value (rejects trailing garbage after the object)
//
// An empty body is treated as "no fields" (v is left at its zero value and
// nil is returned). Callers that require a body must validate fields after
// decoding.
func decodeJSONBody(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, sessionAPIMaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			// Empty body — acceptable for optional-body endpoints.
			return nil
		}
		return fmt.Errorf("decode body: %w", err)
	}
	// Reject bodies with trailing data after the first JSON value. This
	// catches multi-object smuggling and trailing garbage.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("decode body: unexpected trailing data")
	}
	return nil
}

// API path segment constants used in URL validation.
const (
	apiPathSegment     = "api"
	apiVersionSegment  = "v1"
	apiSessionsSegment = "sessions"
)

// Admin API action names used as rate-limiter keys. Extracted so
// there is exactly one source of truth per endpoint label.
const (
	sessionAPIActionReset = "reset"
	sessionAPIActionTask  = "task"
	sessionAPIActionTrust = "trust"
)

// rateLimiterState tracks a sliding-window request count for a
// single admin action. One instance per action so high-volume abuse
// of one endpoint cannot starve legitimate traffic on another during
// incident response.
type rateLimiterState struct {
	reqCount    int
	windowStart time.Time
}

// SessionAPIHandler handles the admin session management API.
type SessionAPIHandler struct {
	smPtr    *atomic.Pointer[SessionManager]
	etPtr    *atomic.Pointer[scanner.EntropyTracker]
	fbPtr    *atomic.Pointer[scanner.FragmentBuffer]
	metrics  *metrics.Metrics
	logger   *audit.Logger
	apiToken string

	// limitMu guards all rate-limiter state. One limiter per admin
	// action (reset/task/trust) so /task abuse cannot suppress
	// /reset during incident response, and vice versa.
	limitMu  sync.Mutex
	limiters map[string]*rateLimiterState
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
		smPtr:    smPtr,
		etPtr:    etPtr,
		fbPtr:    fbPtr,
		metrics:  m,
		logger:   logger,
		apiToken: apiToken,
		limiters: map[string]*rateLimiterState{
			sessionAPIActionReset: {windowStart: time.Now()},
			sessionAPIActionTask:  {windowStart: time.Now()},
			sessionAPIActionTrust: {windowStart: time.Now()},
		},
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

// checkRateLimit enforces a sliding-window rate limit on a single
// admin action (reset/task/trust). Returns true if the request is
// within the limit. Each action has its own counter so a flood on one
// endpoint cannot starve another during incident response — the
// operator can hit /reset even while /task or /trust is being abused.
func (h *SessionAPIHandler) checkRateLimit(action string) bool {
	h.limitMu.Lock()
	defer h.limitMu.Unlock()

	st, ok := h.limiters[action]
	if !ok {
		// Defensive: if a new admin action is added without
		// registering a limiter, fail-closed (deny) rather than
		// silently bypass rate limiting.
		return false
	}
	now := time.Now()
	if now.Sub(st.windowStart) > sessionAPIRateLimitWindow {
		st.reqCount = 0
		st.windowStart = now
	}
	st.reqCount++
	return st.reqCount <= sessionAPIRateLimitMax
}

// extractSessionKey extracts the session key from /api/v1/sessions/{key}/reset.
// Uses EscapedPath + segment parsing to prevent path-traversal tricks
// (e.g. double-encoded slashes) that prefix/suffix slicing would miss.
func extractSessionKey(r *http.Request) (string, bool) {
	segs := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	// Expect exactly: api/v1/sessions/{encoded-key}/reset
	if len(segs) != 5 || segs[0] != apiPathSegment || segs[1] != apiVersionSegment || segs[2] != apiSessionsSegment || segs[4] != "reset" {
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

	if !h.checkRateLimit(sessionAPIActionReset) {
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

// extractSessionKeyWithAction extracts the session key and trailing action from
// /api/v1/sessions/{key}/{action}. Reusable for both /reset and /airlock paths.
func extractSessionKeyWithAction(r *http.Request, action string) (string, bool) {
	segs := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	// Expect exactly: api/v1/sessions/{encoded-key}/{action}
	if len(segs) != 5 || segs[0] != apiPathSegment || segs[1] != apiVersionSegment || segs[2] != apiSessionsSegment || segs[4] != action {
		return "", false
	}
	key, err := url.PathUnescape(segs[3])
	if err != nil || key == "" || strings.ContainsAny(key, "/\x00") {
		return "", false
	}
	return key, true
}

// airlockRequest is the JSON body for POST /api/v1/sessions/{key}/airlock.
type airlockRequest struct {
	Tier string `json:"tier"`
}

// airlockResponse is the JSON response for the airlock endpoint.
type airlockResponse struct {
	Key          string `json:"key"`
	PreviousTier string `json:"previous_tier"`
	NewTier      string `json:"new_tier"`
	Changed      bool   `json:"changed"`
}

type taskRequest struct {
	Label  string `json:"label"`
	Reason string `json:"reason"`
}

type trustOverrideRequest struct {
	Scope       string    `json:"scope"`
	SourceMatch string    `json:"source_match"`
	ActionMatch string    `json:"action_match"`
	ExpiresAt   time.Time `json:"expires_at"`
	GrantedBy   string    `json:"granted_by"`
	Reason      string    `json:"reason"`
}

// HandleAirlock handles POST /api/v1/sessions/{key}/airlock.
// Accepts {"tier": "soft|hard|drain|normal"} and transitions the session's
// airlock state. "normal" is an alias for "none" (human-friendly).
func (h *SessionAPIHandler) HandleAirlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}

	clientIP, _ := requestMeta(r)

	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key, ok := extractSessionKeyWithAction(r, "airlock")
	if !ok {
		h.logSessionAdmin("airlock_bad_key", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	var req airlockRequest
	if err := decodeJSONBody(r, &req); err != nil {
		h.logSessionAdmin("airlock_bad_body", clientIP, key, err.Error(), http.StatusBadRequest)
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Accept "normal" as a human-friendly alias for "none".
	tier := req.Tier
	if tier == "normal" {
		tier = "none"
	}

	// Validate tier value.
	validTiers := map[string]bool{
		"none": true, "soft": true, "hard": true, "drain": true,
	}
	if !validTiers[tier] {
		h.logSessionAdmin("airlock_bad_tier", clientIP, key, "invalid tier: "+tier, http.StatusBadRequest)
		http.Error(w, "invalid tier: must be none|soft|hard|drain|normal", http.StatusBadRequest)
		return
	}

	// Use ForceSetAirlockTier for atomic lookup+mutation under one lock,
	// eliminating the TOCTOU race where a session could be evicted between
	// lookup and ForceSetTier.
	found, changed, from, to := sm.ForceSetAirlockTier(key, tier)
	if !found {
		h.logSessionAdmin("airlock_not_found", clientIP, key, "session not found", http.StatusNotFound)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	h.logSessionAdmin("airlock_ok", clientIP, key, from+"->"+to, http.StatusOK)

	if changed && h.metrics != nil {
		h.metrics.RecordAirlockTransition(from, to, "api")
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(airlockResponse{
		Key:          key,
		PreviousTier: from,
		NewTier:      to,
		Changed:      changed,
	})
}

// HandleTask starts a new task boundary for an active session.
func (h *SessionAPIHandler) HandleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}

	clientIP, _ := requestMeta(r)
	if !h.checkRateLimit(sessionAPIActionTask) {
		h.logSessionAdmin("task_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key, ok := extractSessionKeyWithAction(r, "task")
	if !ok {
		h.logSessionAdmin("task_bad_key", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	// Body is optional for HandleTask — callers may POST with no body to
	// rotate the task without a label/reason. decodeJSONBody treats an
	// empty body as "no fields" and leaves req at its zero value, so a
	// missing Content-Length or chunked transfer encoding is handled
	// correctly without skipping the decode.
	var req taskRequest
	if err := decodeJSONBody(r, &req); err != nil {
		h.logSessionAdmin("task_bad_body", clientIP, key, err.Error(), http.StatusBadRequest)
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	prev, current, cleared, found, taskErr := sm.BeginNewTask(key, req.Label)
	if !found {
		h.logSessionAdmin("task_not_found", clientIP, key, "session not found", http.StatusNotFound)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if taskErr != nil {
		// Invocation sessions are ephemeral per-request contexts and
		// cannot be mutated via the admin API. Mirrors the guardrail on
		// HandleReset.
		h.logSessionAdmin("task_rejected", clientIP, key, "invocation key", http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: "cannot begin new task on invocation session; only identity sessions are mutable"})
		return
	}

	h.logSessionAdmin("task_ok", clientIP, key, req.Reason, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Key                     string `json:"key"`
		PreviousTaskID          string `json:"previous_task_id"`
		CurrentTaskID           string `json:"current_task_id"`
		CurrentTaskLabel        string `json:"current_task_label,omitempty"`
		TaintCleared            bool   `json:"taint_cleared"`
		RuntimeOverridesCleared int    `json:"runtime_overrides_cleared"`
	}{
		Key:                     key,
		PreviousTaskID:          prev.CurrentTaskID,
		CurrentTaskID:           current.CurrentTaskID,
		CurrentTaskLabel:        current.CurrentTaskLabel,
		TaintCleared:            true,
		RuntimeOverridesCleared: cleared,
	})
}

// HandleTrust grants a runtime trust override bound to the current task.
func (h *SessionAPIHandler) HandleTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}

	clientIP, _ := requestMeta(r)
	if !h.checkRateLimit(sessionAPIActionTrust) {
		h.logSessionAdmin("trust_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key, ok := extractSessionKeyWithAction(r, "trust")
	if !ok {
		h.logSessionAdmin("trust_bad_key", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	var req trustOverrideRequest
	if err := decodeJSONBody(r, &req); err != nil {
		h.logSessionAdmin("trust_bad_body", clientIP, key, err.Error(), http.StatusBadRequest)
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Scope != taintScopeTask {
		h.logSessionAdmin("trust_bad_scope", clientIP, key, "invalid scope", http.StatusBadRequest)
		http.Error(w, "invalid scope: must be task", http.StatusBadRequest)
		return
	}
	if req.SourceMatch == "" && req.ActionMatch == "" {
		h.logSessionAdmin("trust_bad_match", clientIP, key, "missing match pattern", http.StatusBadRequest)
		http.Error(w, "source_match or action_match is required", http.StatusBadRequest)
		return
	}
	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(time.Now().UTC()) {
		h.logSessionAdmin("trust_bad_expiry", clientIP, key, "invalid expiry", http.StatusBadRequest)
		http.Error(w, "expires_at must be in the future", http.StatusBadRequest)
		return
	}

	override := session.TrustOverride{
		Scope:       taintScopeTask,
		SourceMatch: req.SourceMatch,
		ActionMatch: req.ActionMatch,
		ExpiresAt:   req.ExpiresAt.UTC(),
		GrantedBy:   req.GrantedBy,
		Reason:      req.Reason,
	}
	applied, found, err := sm.AddRuntimeTrustOverride(key, override)
	if !found && err == nil {
		h.logSessionAdmin("trust_not_found", clientIP, key, "session not found", http.StatusNotFound)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if err != nil {
		// Distinguish invocation-session rejection from other errors so
		// the audit trail mirrors HandleReset. Both return 400; only the
		// error string + log tag differ.
		if errors.Is(err, ErrInvocationReset) {
			h.logSessionAdmin("trust_rejected", clientIP, key, "invocation key", http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(struct {
				Error string `json:"error"`
			}{Error: "cannot grant runtime trust override on invocation session; only identity sessions are mutable"})
			return
		}
		h.logSessionAdmin("trust_rejected", clientIP, key, err.Error(), http.StatusBadRequest)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logSessionAdmin("trust_ok", clientIP, key, applied.Reason, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Key         string    `json:"key"`
		Scope       string    `json:"scope"`
		TaskID      string    `json:"task_id"`
		SourceMatch string    `json:"source_match,omitempty"`
		ActionMatch string    `json:"action_match,omitempty"`
		ExpiresAt   time.Time `json:"expires_at"`
		GrantedBy   string    `json:"granted_by,omitempty"`
		Reason      string    `json:"reason,omitempty"`
	}{
		Key:   key,
		Scope: applied.Scope,
		// applied.TaskID was bound under the session mutex by
		// SessionState.AddRuntimeTrustOverride — use it directly instead
		// of taking a second TaskSnapshot that could race a concurrent
		// BeginNewTask rotation.
		TaskID:      applied.TaskID,
		SourceMatch: applied.SourceMatch,
		ActionMatch: applied.ActionMatch,
		ExpiresAt:   applied.ExpiresAt,
		GrantedBy:   applied.GrantedBy,
		Reason:      applied.Reason,
	})
}

// logSessionAdmin logs a session admin API operation if a logger is available.
func (h *SessionAPIHandler) logSessionAdmin(action, clientIP, sessionKey, result string, statusCode int) {
	if h.logger != nil {
		h.logger.LogSessionAdmin(action, clientIP, sessionKey, result, statusCode)
	}
}
