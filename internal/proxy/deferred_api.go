// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"time"

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
