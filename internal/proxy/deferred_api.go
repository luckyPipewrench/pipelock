// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
)

// DeferredHeldView is the operator-safe projection of a held (deferred) action.
// It deliberately omits the raw held Payload and ArgDigest: an operator needs to
// see WHAT is held (target/method/reason/identity), not the raw request bytes,
// which are a data-exfiltration surface.
type DeferredHeldView struct {
	DeferID       string `json:"defer_id"`
	ActionID      string `json:"action_id"`
	Surface       string `json:"surface"`
	Method        string `json:"method"`
	Target        string `json:"target"`
	Reason        string `json:"reason"`
	SizeBytes     int    `json:"size_bytes"`
	SessionID     string `json:"session_id"`
	Principal     string `json:"principal,omitempty"`
	Actor         string `json:"actor,omitempty"`
	ParentDeferID string `json:"parent_defer_id,omitempty"`
	CascadeDepth  int    `json:"cascade_depth"`
	Linkage       string `json:"linkage,omitempty"`
	Deadline      string `json:"deadline,omitempty"`
}

// DeferredListResponse is returned by GET /api/v1/deferred.
type DeferredListResponse struct {
	Held  []DeferredHeldView `json:"held"`
	Count int                `json:"count"`
}

// loadDeferredManager returns the live deferred manager, or writes a 503 and
// returns ok=false when the deferred operator surface is not configured for
// this process (no deferrable MCP transport is running).
func (h *SessionAPIHandler) loadDeferredManager(w http.ResponseWriter) (*deferred.Manager, bool) {
	if h.deferred == nil {
		http.Error(w, "deferred surface not configured", http.StatusServiceUnavailable)
		return nil, false
	}
	return h.deferred, true
}

// deferredHeldView projects a held action onto its operator-safe view, dropping
// the raw payload and arg digest.
func deferredHeldView(a deferred.HeldAction) DeferredHeldView {
	v := DeferredHeldView{
		DeferID:       a.DeferID,
		ActionID:      a.ActionID,
		Surface:       a.Surface,
		Method:        a.Method,
		Target:        a.Target,
		Reason:        a.Reason,
		SizeBytes:     a.SizeBytes,
		SessionID:     a.Authority.SessionID,
		Principal:     a.Authority.Principal,
		Actor:         a.Authority.Actor,
		ParentDeferID: a.ParentDeferID,
		CascadeDepth:  a.CascadeDepth,
		Linkage:       a.Linkage,
	}
	if !a.Deadline.IsZero() {
		v.Deadline = a.Deadline.UTC().Format(time.RFC3339)
	}
	return v
}

// HandleDeferredList handles GET /api/v1/deferred on the operator-only admin
// surface. It returns the pending held actions. Read-only.
func (h *SessionAPIHandler) HandleDeferredList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}
	clientIP, _ := requestMeta(r)
	mgr, ok := h.loadDeferredManager(w)
	if !ok {
		h.logSessionAdmin("deferred_list_unavailable", clientIP, "", "deferred disabled", http.StatusServiceUnavailable)
		return
	}
	held := mgr.Snapshot()
	resp := DeferredListResponse{
		Held:  make([]DeferredHeldView, 0, len(held)),
		Count: len(held),
	}
	for _, a := range held {
		resp.Held = append(resp.Held, deferredHeldView(a))
	}
	h.logSessionAdmin("deferred_list", clientIP, "", "ok", http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Deferred action path segments.
const (
	deferredActionApprove = "approve"
	deferredActionDeny    = "deny"
)

// DeferredResolveResult is returned by POST /api/v1/deferred/{id}/{approve,deny}.
// FinalDecision is the decision that was ACTUALLY applied: an "approve" on a
// hold whose rule forbids approval resolves closed, so FinalDecision is "block"
// even though Action is "approve". The operator never sees a misleading success.
type DeferredResolveResult struct {
	DeferID       string `json:"defer_id"`
	Action        string `json:"action"`
	FinalDecision string `json:"final_decision"`
	Resolved      bool   `json:"resolved"`
}

// extractDeferIDWithAction extracts the defer ID from
// /api/v1/deferred/{id}/{action}. Mirrors extractBaselineAgentWithAction:
// EscapedPath + segment parsing rejects path-traversal tricks (double-encoded
// slashes) that prefix/suffix slicing would miss.
func extractDeferIDWithAction(r *http.Request, action string) (string, bool) {
	segs := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	if len(segs) != 5 || segs[0] != apiPathSegment || segs[1] != apiVersionSegment ||
		segs[2] != apiDeferredSegment || segs[4] != action {
		return "", false
	}
	id, err := url.PathUnescape(segs[3])
	if err != nil || id == "" || strings.ContainsAny(id, "/\x00") {
		return "", false
	}
	if decodedAgain, err := url.PathUnescape(id); err == nil && strings.ContainsAny(decodedAgain, "/\x00") {
		return "", false
	}
	return id, true
}

// HandleDeferredAction routes POST /api/v1/deferred/{id}/approve and
// /api/v1/deferred/{id}/deny on the operator-only admin surface. GET/other
// verbs are rejected before any routing so a probe cannot enumerate holds here.
func (h *SessionAPIHandler) HandleDeferredAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.EscapedPath()
	switch {
	case strings.HasSuffix(path, "/"+deferredActionApprove):
		h.handleDeferredResolve(w, r, deferredActionApprove)
	case strings.HasSuffix(path, "/"+deferredActionDeny):
		h.handleDeferredResolve(w, r, deferredActionDeny)
	default:
		http.NotFound(w, r)
	}
}

// handleDeferredResolve is the shared approve/deny handler. approve sends an
// affirmative ActionAllow input (gated by the held rule's approval policy - a
// hold the rule does not permit to open still resolves closed); deny sends
// ActionBlock. The resolution is stamped SourceOperator so the receipt and
// journal record that a human operator, not the interactive HITL path, drove
// it.
//
// Fail-closed status codes:
//   - unknown ID (never held)              -> 404 (no resolver is called)
//   - known at preflight, lost to a race   -> 409 (timeout/cascade/other operator)
//   - defer surface not configured         -> 503
//
// The response reports the ACTUAL terminal decision, so an approve on a hold
// whose rule forbids approval returns final_decision:"block", never a
// misleading success.
func (h *SessionAPIHandler) handleDeferredResolve(w http.ResponseWriter, r *http.Request, action string) {
	if !h.authenticate(w, r) {
		return
	}
	clientIP, _ := requestMeta(r)
	logAction := "deferred_" + action
	if !h.checkRateLimit(sessionAPIActionDeferred) {
		h.logSessionAdmin(logAction+"_rate_limited", clientIP, "", "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	// approve/deny take no parameters; reject any body with an unexpected
	// field (client bug or smuggling). Empty/missing bodies are tolerated.
	if err := decodeJSONBody(r, &struct{}{}); err != nil {
		h.logSessionAdmin(logAction+"_bad_body", clientIP, "", err.Error(), http.StatusBadRequest)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mgr, ok := h.loadDeferredManager(w)
	if !ok {
		h.logSessionAdmin(logAction+"_unavailable", clientIP, "", "deferred disabled", http.StatusServiceUnavailable)
		return
	}
	deferID, ok := extractDeferIDWithAction(r, action)
	if !ok {
		h.logSessionAdmin(logAction+"_bad_id", clientIP, "", "invalid path", http.StatusBadRequest)
		http.Error(w, "missing or invalid defer id in URL path", http.StatusBadRequest)
		return
	}

	// Preflight: an ID that was never held is a hard 404 and reaches no
	// resolver. A hold present now but resolved by a racing
	// timeout/cascade/other-operator before we mutate is a 409, told apart
	// by the ErrNotFound the resolve returns after preflight succeeded.
	if _, held := mgr.Held(deferID); !held {
		h.logSessionAdmin(logAction+"_not_found", clientIP, deferID, "hold not found", http.StatusNotFound)
		http.Error(w, "deferred hold not found", http.StatusNotFound)
		return
	}

	input := config.ActionAllow
	if action == deferredActionDeny {
		input = config.ActionBlock
	}
	decision, err := mgr.ResolveApprovalResult(deferID, input, deferred.SourceOperator)
	if err != nil {
		if errors.Is(err, deferred.ErrNotFound) {
			h.logSessionAdmin(logAction+"_conflict", clientIP, deferID, "already resolved", http.StatusConflict)
			http.Error(w, "deferred hold already resolved", http.StatusConflict)
			return
		}
		h.logSessionAdmin(logAction+"_failed", clientIP, deferID, err.Error(), http.StatusServiceUnavailable)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	resp := DeferredResolveResult{
		DeferID:       deferID,
		Action:        action,
		FinalDecision: decision,
		Resolved:      true,
	}
	h.logSessionAdmin(logAction, clientIP, deferID, "final="+decision, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
