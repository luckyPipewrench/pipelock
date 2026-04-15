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
	"github.com/luckyPipewrench/pipelock/internal/config"
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
	sessionAPIActionReset     = "reset"
	sessionAPIActionTask      = "task"
	sessionAPIActionTrust     = "trust"
	sessionAPIActionAirlock   = "airlock"
	sessionAPIActionInspect   = "inspect"
	sessionAPIActionExplain   = "explain"
	sessionAPIActionTerminate = "terminate"
)

// tierNotQuarantinedReason is the explanation returned for sessions that
// are not currently in any airlock tier. Operators may call explain on a
// normal session too; returning 200 with this reason avoids confusing 404.
const tierNotQuarantinedReason = "session not quarantined"

// airlockTierAliasNormal is the human-friendly alias accepted alongside
// "none" on admin API inputs. Kept here so every endpoint validates tiers
// with the same vocabulary as HandleAirlock.
const airlockTierAliasNormal = "normal"

// rateLimiterState tracks a sliding-window request count for a
// single admin action. One instance per action so high-volume abuse
// of one endpoint cannot starve legitimate traffic on another during
// incident response.
type rateLimiterState struct {
	reqCount    int
	windowStart time.Time
}

// SessionAPIHandler handles the admin session management API.
//
// apiTokenPtr is an atomic.Pointer[string] so SetAPIToken can rotate the
// admin bearer credential on config reload without racing the
// authenticate() fast path. Storing the token inline would force a
// mutex around every request or leave stale credentials live after a
// SIGHUP. A nil or empty-string payload disables the endpoint entirely
// (authenticate returns 503), matching the "service not configured"
// bootstrap path.
type SessionAPIHandler struct {
	smPtr       *atomic.Pointer[SessionManager]
	etPtr       *atomic.Pointer[scanner.EntropyTracker]
	fbPtr       *atomic.Pointer[scanner.FragmentBuffer]
	metrics     *metrics.Metrics
	logger      *audit.Logger
	apiTokenPtr atomic.Pointer[string]

	// limitMu guards all rate-limiter state. One limiter per admin
	// action (reset/task/trust/airlock/inspect/explain/terminate) so
	// /task abuse cannot suppress /reset during incident response, and
	// vice versa.
	limitMu  sync.Mutex
	limiters map[string]*rateLimiterState
}

// SessionAPIOptions configures a SessionAPIHandler. Using an options struct
// keeps the constructor signature stable as new endpoints land and new
// collaborators wire in — CLAUDE.md caps positional parameters at six.
// The APIToken field holds the bearer token used to authenticate admin
// API requests; it is never serialized because this struct is never
// marshaled — it exists only to carry constructor inputs.
type SessionAPIOptions struct {
	SessionMgrPtr *atomic.Pointer[SessionManager]
	EntropyPtr    *atomic.Pointer[scanner.EntropyTracker]
	FragmentPtr   *atomic.Pointer[scanner.FragmentBuffer]
	Metrics       *metrics.Metrics
	Logger        *audit.Logger
	APIToken      string `json:"-"` //nolint:gosec // options input, never serialized
}

// NewSessionAPIHandler creates a session API handler from the given options.
func NewSessionAPIHandler(opts SessionAPIOptions) *SessionAPIHandler {
	h := &SessionAPIHandler{
		smPtr:   opts.SessionMgrPtr,
		etPtr:   opts.EntropyPtr,
		fbPtr:   opts.FragmentPtr,
		metrics: opts.Metrics,
		logger:  opts.Logger,
		limiters: map[string]*rateLimiterState{
			sessionAPIActionReset:     {windowStart: time.Now()},
			sessionAPIActionTask:      {windowStart: time.Now()},
			sessionAPIActionTrust:     {windowStart: time.Now()},
			sessionAPIActionAirlock:   {windowStart: time.Now()},
			sessionAPIActionInspect:   {windowStart: time.Now()},
			sessionAPIActionExplain:   {windowStart: time.Now()},
			sessionAPIActionTerminate: {windowStart: time.Now()},
		},
	}
	// Seed the atomic token pointer from the constructor input. Stored via
	// SetAPIToken so the nil-vs-empty logic stays in one place.
	h.SetAPIToken(opts.APIToken)
	return h
}

// SetAPIToken rotates the admin bearer credential used by authenticate.
// Called from proxy.Reload so operators can rotate kill_switch.api_token
// (or the PIPELOCK_KILLSWITCH_API_TOKEN env var) without restarting the
// proxy. An empty string disables the endpoint (authenticate returns
// 503), matching the "service not configured" bootstrap path.
func (h *SessionAPIHandler) SetAPIToken(token string) {
	if token == "" {
		h.apiTokenPtr.Store(nil)
		return
	}
	t := token
	h.apiTokenPtr.Store(&t)
}

// currentAPIToken returns the active admin API bearer token, or empty
// string when the endpoint is not configured.
func (h *SessionAPIHandler) currentAPIToken() string {
	if p := h.apiTokenPtr.Load(); p != nil {
		return *p
	}
	return ""
}

func (h *SessionAPIHandler) authenticate(w http.ResponseWriter, r *http.Request) bool {
	// Load the active token once per request. The atomic snapshot keeps
	// the comparison safe against a concurrent SetAPIToken rotation and
	// also pins the value across the constant-time compare below so a
	// mid-call swap cannot flip us into a stale-credential accept.
	activeToken := h.currentAPIToken()
	if activeToken == "" {
		http.Error(w, "session API not configured (no api_token)", http.StatusServiceUnavailable)
		return false
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	var token string
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		token = auth[len(prefix):]
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(activeToken)) != 1 {
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
//
// Supports an optional ?tier=none|soft|hard|drain|normal query parameter to
// filter returned sessions by airlock tier. "normal" is accepted as an
// alias for "none" (mirrors HandleAirlock) so operators and scripts share
// the same tier vocabulary end to end.
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

	clientIP, _ := requestMeta(r)

	filter, filterErr := parseTierFilter(r.URL.Query().Get("tier"))
	if filterErr != nil {
		h.logSessionAdmin("list_bad_tier", clientIP, "", filterErr.Error(), http.StatusBadRequest)
		http.Error(w, filterErr.Error(), http.StatusBadRequest)
		return
	}

	snaps := sm.Snapshot()
	if filter != "" {
		kept := make([]SessionSnapshot, 0, len(snaps))
		for _, s := range snaps {
			if tierMatches(s.AirlockTier, filter) {
				kept = append(kept, s)
			}
		}
		snaps = kept
	}

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

// parseTierFilter validates the optional ?tier= query parameter and
// normalizes it to a canonical tier string. Empty input means no filter.
// "normal" is accepted as an alias for "none" so admin API consumers can
// use the same human-friendly vocabulary as HandleAirlock.
func parseTierFilter(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	tier := raw
	if tier == airlockTierAliasNormal {
		tier = config.AirlockTierNone
	}
	switch tier {
	case config.AirlockTierNone,
		config.AirlockTierSoft,
		config.AirlockTierHard,
		config.AirlockTierDrain:
		return tier, nil
	}
	return "", errors.New("invalid tier filter: must be none|soft|hard|drain|normal")
}

// tierMatches compares a session's current airlock tier against a filter
// tier, treating the empty snapshot tier as equivalent to "none" (the zero
// value left by sessions that never escalated).
func tierMatches(snapshotTier, filter string) bool {
	if snapshotTier == "" {
		snapshotTier = config.AirlockTierNone
	}
	return snapshotTier == filter
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

// extractSessionKeyOnly extracts the session key from /api/v1/sessions/{key}
// with no trailing action segment. Used by HandleInspect, which exposes the
// full detail snapshot under the base session path. Mirrors the segment
// validation pattern in extractSessionKey and extractSessionKeyWithAction.
func extractSessionKeyOnly(r *http.Request) (string, bool) {
	segs := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	// Expect exactly: api/v1/sessions/{encoded-key}
	if len(segs) != 4 || segs[0] != apiPathSegment || segs[1] != apiVersionSegment || segs[2] != apiSessionsSegment {
		return "", false
	}
	key, err := url.PathUnescape(segs[3])
	if err != nil || key == "" || strings.ContainsAny(key, "/\x00") {
		return "", false
	}
	return key, true
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

// SessionDetail is the response shape for GET /api/v1/sessions/{key}.
// Embeds SessionSnapshot (flattened in JSON output) and adds the extra
// fields operators need for airlock recovery: tier timing, request
// in-flight gauge, numeric escalation level, and the recent event buffer.
type SessionDetail struct {
	SessionSnapshot
	AirlockEnteredAt   time.Time      `json:"airlock_entered_at"`
	InFlight           int64          `json:"in_flight"`
	EscalationLevelInt int            `json:"escalation_level_int"`
	RecentEvents       []SessionEvent `json:"recent_events"`
}

// SessionExplanation is the response shape for GET
// /api/v1/sessions/{key}/explain. The answer to "why is this session in
// the state it is in" — which trigger fired, what the score was, what
// evidence (event excerpt) crossed the threshold, and when the next
// automatic de-escalation will fire.
type SessionExplanation struct {
	Key                  string        `json:"key"`
	Tier                 string        `json:"tier"`
	Reason               string        `json:"reason"`
	Trigger              string        `json:"trigger,omitempty"`
	TriggerSource        string        `json:"trigger_source,omitempty"`
	EnteredAt            time.Time     `json:"entered_at,omitempty"`
	ElapsedInTier        time.Duration `json:"elapsed_in_tier_ns,omitempty"`
	EscalationLevel      string        `json:"escalation_level"`
	EscalationLevelInt   int           `json:"escalation_level_int"`
	ThreatScore          float64       `json:"threat_score"`
	EvidenceKind         string        `json:"evidence_kind,omitempty"`
	EvidenceTarget       string        `json:"evidence_target,omitempty"`
	EvidenceDetail       string        `json:"evidence_detail,omitempty"`
	EvidenceAt           time.Time     `json:"evidence_at,omitempty"`
	NextDeescalationTier string        `json:"next_deescalation_tier,omitempty"`
	NextDeescalationAt   time.Time     `json:"next_deescalation_at,omitempty"`
}

// SessionTerminateResult is the response shape for POST
// /api/v1/sessions/{key}/terminate. Captures the "before" snapshot so the
// operator can audit what was in flight at the moment of termination.
type SessionTerminateResult struct {
	Key             string  `json:"key"`
	Terminated      bool    `json:"terminated"`
	PreviousTier    string  `json:"previous_tier"`
	PreviousLevel   string  `json:"previous_level"`
	PreviousScore   float64 `json:"previous_score"`
	IPStateCleared  bool    `json:"ip_state_cleared"`
	CEEStateCleared bool    `json:"cee_state_cleared"`
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

	if !h.checkRateLimit(sessionAPIActionAirlock) {
		h.logSessionAdmin("airlock_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

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

// HandleInspect handles GET /api/v1/sessions/{key}. Returns a SessionDetail
// with the session snapshot, airlock timing, in-flight count, and recent-
// event ring buffer so operators can reason about quarantined sessions
// without exec-ing into the pipelock container.
func (h *SessionAPIHandler) HandleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}

	clientIP, _ := requestMeta(r)

	if !h.checkRateLimit(sessionAPIActionInspect) {
		h.logSessionAdmin("inspect_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key, ok := extractSessionKeyOnly(r)
	if !ok {
		h.logSessionAdmin("inspect_bad_key", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	adminSnap, found := sm.AdminSnapshotByKey(key)
	if !found {
		h.logSessionAdmin("inspect_not_found", clientIP, key, "session not found", http.StatusNotFound)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	detail := SessionDetail{
		SessionSnapshot:    adminSnap.SessionSnapshot,
		AirlockEnteredAt:   adminSnap.AirlockEnteredAt,
		InFlight:           adminSnap.InFlight,
		EscalationLevelInt: adminSnap.EscalationLevelInt,
		RecentEvents:       adminSnap.RecentEvents,
	}
	if detail.RecentEvents == nil {
		detail.RecentEvents = []SessionEvent{}
	}

	h.logSessionAdmin("inspect_ok", clientIP, key, adminSnap.AirlockTier, http.StatusOK)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detail)
}

// HandleExplain handles GET /api/v1/sessions/{key}/explain. Answers the
// operator question "why is this session in its current state" with the
// trigger that fired, the evidence that crossed the threshold, and an
// estimate of when the next automatic de-escalation will drop the tier.
//
// Sessions at the none tier are NOT 404 — explain returns 200 with a
// "session not quarantined" reason so operators can sanity-check normal
// sessions without special-casing the happy path in their tooling.
func (h *SessionAPIHandler) HandleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}

	clientIP, _ := requestMeta(r)

	if !h.checkRateLimit(sessionAPIActionExplain) {
		h.logSessionAdmin("explain_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key, ok := extractSessionKeyWithAction(r, "explain")
	if !ok {
		h.logSessionAdmin("explain_bad_key", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	adminSnap, found := sm.AdminSnapshotByKey(key)
	if !found {
		h.logSessionAdmin("explain_not_found", clientIP, key, "session not found", http.StatusNotFound)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	exp := buildExplanation(adminSnap, h.airlockCfgFromManager(sm))

	h.logSessionAdmin("explain_ok", clientIP, key, exp.Tier, http.StatusOK)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exp)
}

// HandleTerminate handles POST /api/v1/sessions/{key}/terminate. Performs
// a superset of reset: clears in-flight cancel functions, zeros all
// enforcement state via ResetSessionIfResettable, and clears CEE entropy
// and fragment-buffer state. Returns the previous tier/level/score so the
// operator trail captures what was torn down.
//
// Invocation sessions (ephemeral MCP transport contexts) are rejected
// with the same 400 error shape as HandleReset — terminate is a
// destructive admin action scoped to identity sessions only.
func (h *SessionAPIHandler) HandleTerminate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}

	clientIP, _ := requestMeta(r)

	if !h.checkRateLimit(sessionAPIActionTerminate) {
		h.logSessionAdmin("terminate_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	sm := h.loadManager(w)
	if sm == nil {
		return
	}

	key, ok := extractSessionKeyWithAction(r, "terminate")
	if !ok {
		h.logSessionAdmin("terminate_bad_key", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid session key in URL path", http.StatusBadRequest)
		return
	}

	// Decode empty body. decodeJSONBody tolerates missing/empty bodies and
	// enforces the shared size limit and DisallowUnknownFields contract,
	// so callers sending stray fields get a 400 here instead of a silent
	// accept that leaks the extra data into logs.
	var empty struct{}
	if err := decodeJSONBody(r, &empty); err != nil {
		h.logSessionAdmin("terminate_bad_body", clientIP, key, err.Error(), http.StatusBadRequest)
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Capture pre-terminate state and reset atomically under a single
	// sm.mu.Lock so the response's previous_tier/previous_level/
	// previous_score describe one consistent moment in time. Splitting
	// the snapshot and the reset across two critical sections let a
	// concurrent tier change slip an inconsistent row into the audit
	// trail; SnapshotAndResetIfResettable closes that gap.
	preSnap, found, resetErr := sm.SnapshotAndResetIfResettable(key)
	if !found {
		h.logSessionAdmin("terminate_not_found", clientIP, key, "session not found", http.StatusNotFound)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if resetErr != nil {
		h.logSessionAdmin("terminate_rejected", clientIP, key, "invocation key", http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: "cannot terminate invocation session; only identity sessions are resettable"})
		return
	}

	_, agent, ip := classifySessionKey(key)

	ceeCleared := false
	if h.etPtr != nil && h.fbPtr != nil {
		et := h.etPtr.Load()
		fb := h.fbPtr.Load()
		if et != nil || fb != nil {
			ResetCEEState(agent, ip, et, fb)
			ceeCleared = true
		}
	}

	h.logSessionAdmin("terminate_ok", clientIP, key, preSnap.AirlockTier, http.StatusOK)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SessionTerminateResult{
		Key:             key,
		Terminated:      true,
		PreviousTier:    preSnap.AirlockTier,
		PreviousLevel:   preSnap.EscalationLevel,
		PreviousScore:   preSnap.ThreatScore,
		IPStateCleared:  ip != "",
		CEEStateCleared: ceeCleared,
	})
}

// airlockCfgFromManager fetches the active airlock config from the manager
// if one is configured, returning a pointer safe for read-only use.
// Returns nil when airlock is not configured — the explain builder handles
// that case by omitting the next-deescalation estimate.
func (h *SessionAPIHandler) airlockCfgFromManager(sm *SessionManager) *config.Airlock {
	if sm == nil {
		return nil
	}
	return sm.AirlockConfig()
}

// buildExplanation constructs a SessionExplanation from a snapshot, recent
// events, and live session state. Trigger/source come from the airlock
// entry metadata; the next-deescalation estimate is derived from the
// airlock timer config when available.
func buildExplanation(snap sessionAdminSnapshot, airlockCfg *config.Airlock) SessionExplanation {
	tier := snap.AirlockTier
	if tier == "" {
		tier = config.AirlockTierNone
	}

	exp := SessionExplanation{
		Key:                snap.Key,
		Tier:               tier,
		EscalationLevel:    snap.EscalationLevel,
		EscalationLevelInt: snap.EscalationLevelInt,
		ThreatScore:        snap.ThreatScore,
	}

	if tier == config.AirlockTierNone {
		exp.Reason = tierNotQuarantinedReason
		// Still attach the most recent notable event as evidence so the
		// operator can see what the session has been doing even when the
		// tier is normal. Keeps explain useful outside of incident mode.
		// Trigger/TriggerSource are left empty: a normal-tier session has
		// no active quarantine cause, and reporting stale trigger metadata
		// would contradict the "not quarantined" reason string.
		attachMostRecentEvidence(&exp, snap.RecentEvents)
		return exp
	}

	exp.Trigger = snap.AirlockTrigger
	exp.TriggerSource = snap.AirlockTriggerSource
	exp.Reason = "session quarantined at airlock tier " + tier
	if exp.Trigger == "" {
		exp.Trigger = airlockTriggerManual
	}
	if exp.TriggerSource == "" {
		exp.TriggerSource = airlockSourceAdminAPI
	}

	exp.EnteredAt = snap.AirlockEnteredAt
	if !exp.EnteredAt.IsZero() {
		exp.ElapsedInTier = time.Since(exp.EnteredAt)
	}

	// Prefer evidence recorded at or before the tier-entry moment so a
	// noisy quarantined session that keeps generating post-entry blocks
	// doesn't overwrite the event that actually drove the escalation.
	// Falls back to the newest event in the buffer if the original
	// trigger has rotated out.
	attachTierEntryEvidence(&exp, snap.RecentEvents, snap.AirlockEnteredAt)

	// Only advertise auto-deescalation when the timer for the current
	// tier is actually positive. A disabled timer (0) means manual
	// recovery only — surfacing a next_deescalation_tier without an
	// at= would tell operators a timer exists when it doesn't.
	if airlockCfg != nil {
		if dur := deescalationDuration(tier, &airlockCfg.Timers); dur > 0 {
			exp.NextDeescalationTier = nextDeescalationTier(tier)
			if !exp.EnteredAt.IsZero() && exp.NextDeescalationTier != "" {
				exp.NextDeescalationAt = exp.EnteredAt.Add(dur)
			}
		}
	}

	return exp
}

// attachMostRecentEvidence copies the most recent non-transition event
// into the explanation as evidence. Falls back to transition events only
// when there is nothing more specific in the ring buffer. Used by the
// none-tier explain path where there is no tier-entry timestamp to
// prefer events against.
func attachMostRecentEvidence(exp *SessionExplanation, events []SessionEvent) {
	if attachEvidence(exp, events, time.Time{}, false) {
		return
	}
	_ = attachEvidence(exp, events, time.Time{}, true)
}

// attachTierEntryEvidence prefers the newest event recorded at or
// before the tier-entry timestamp so quarantined sessions report the
// evidence that actually drove the escalation, not whatever noise has
// accumulated since. Falls back to (a) post-entry non-transition
// events, then (b) any non-empty event, if the original tier-entry
// evidence has already rotated out of the 20-slot ring buffer.
func attachTierEntryEvidence(exp *SessionExplanation, events []SessionEvent, enteredAt time.Time) {
	if !enteredAt.IsZero() {
		if attachEvidence(exp, events, enteredAt, false) {
			return
		}
	}
	if attachEvidence(exp, events, time.Time{}, false) {
		return
	}
	_ = attachEvidence(exp, events, time.Time{}, true)
}

// attachEvidence walks the event ring buffer newest-to-oldest and
// stores the first matching event on exp. When cutoff is non-zero the
// selector skips events strictly after the cutoff so the tier-entry
// window can be preferred. When includeTransitions is false, airlock_*
// transition events are skipped as well.
func attachEvidence(exp *SessionExplanation, events []SessionEvent, cutoff time.Time, includeTransitions bool) bool {
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Kind == "" && e.Detail == "" {
			continue
		}
		if !includeTransitions && strings.HasPrefix(e.Kind, "airlock_") {
			continue
		}
		if !cutoff.IsZero() && e.At.After(cutoff) {
			continue
		}
		exp.EvidenceKind = e.Kind
		exp.EvidenceTarget = e.Target
		exp.EvidenceDetail = e.Detail
		exp.EvidenceAt = e.At
		return true
	}
	return false
}

// nextDeescalationTier returns the tier that an automatic de-escalation
// would transition into from the given current tier. Mirrors the state
// machine in AirlockState.TryDeescalate.
func nextDeescalationTier(current string) string {
	switch current {
	case config.AirlockTierSoft:
		return config.AirlockTierNone
	case config.AirlockTierHard:
		return config.AirlockTierSoft
	case config.AirlockTierDrain:
		return config.AirlockTierHard
	}
	return ""
}

// deescalationDuration returns the configured timer duration for the
// given tier, or zero when the timer is disabled (0 = manual recovery).
// Drain honors the shorter of DrainMinutes and DrainTimeoutSeconds as a
// hard ceiling for in-flight completion.
func deescalationDuration(tier string, timers *config.AirlockTimers) time.Duration {
	if timers == nil {
		return 0
	}
	switch tier {
	case config.AirlockTierSoft:
		if timers.SoftMinutes <= 0 {
			return 0
		}
		return time.Duration(timers.SoftMinutes) * time.Minute
	case config.AirlockTierHard:
		if timers.HardMinutes <= 0 {
			return 0
		}
		return time.Duration(timers.HardMinutes) * time.Minute
	case config.AirlockTierDrain:
		if timers.DrainMinutes <= 0 && timers.DrainTimeoutSeconds <= 0 {
			return 0
		}
		d := time.Duration(timers.DrainMinutes) * time.Minute
		if timers.DrainTimeoutSeconds > 0 {
			drainTimeout := time.Duration(timers.DrainTimeoutSeconds) * time.Second
			if d <= 0 || drainTimeout < d {
				d = drainTimeout
			}
		}
		return d
	}
	return 0
}

// logSessionAdmin logs a session admin API operation if a logger is available.
func (h *SessionAPIHandler) logSessionAdmin(action, clientIP, sessionKey, result string, statusCode int) {
	if h.logger != nil {
		h.logger.LogSessionAdmin(action, clientIP, sessionKey, result, statusCode)
	}
}
