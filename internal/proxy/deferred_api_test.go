// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/deferred"
)

const deferredTestToken = "deferred-admin-token"

// seededDeferManager returns an enabled manager holding one MCP-stdio action.
func seededDeferManager(t *testing.T) *deferred.Manager {
	t.Helper()
	m := deferred.NewManager(deferred.Config{
		Enabled:              true,
		Timeout:              time.Hour,
		MaxPending:           8,
		MaxPendingPerSession: 8,
		MaxPendingBytes:      1 << 20,
		MaxCascadeDepth:      4,
	})
	if err := m.Hold(deferred.HeldAction{
		DeferID:   "0193defer00000000000000000001",
		ActionID:  "0193defer00000000000000000001",
		Surface:   deferred.SurfaceMCPStdio,
		Method:    "tools/call",
		Target:    "shell.exec",
		Reason:    "tool policy: defer",
		Payload:   []byte("SECRET-EXFIL-PAYLOAD"),
		Authority: deferred.AuthoritySnapshot{SessionID: "sess-1", Principal: "agent-a"},
		Resolve:   func(deferred.Resolution) {},
	}); err != nil {
		t.Fatalf("seed hold: %v", err)
	}
	return m
}

func deferredTestHandler(mgr *deferred.Manager) *SessionAPIHandler {
	return NewSessionAPIHandler(SessionAPIOptions{
		APIToken: deferredTestToken,
		Deferred: mgr,
	})
}

func TestHandleDeferredList_ReturnsHeldActions(t *testing.T) {
	h := deferredTestHandler(seededDeferManager(t))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/deferred", nil)
	req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	rr := httptest.NewRecorder()

	h.HandleDeferredList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DeferredListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || len(resp.Held) != 1 {
		t.Fatalf("count=%d held=%d, want 1/1", resp.Count, len(resp.Held))
	}
	got := resp.Held[0]
	if got.DeferID != "0193defer00000000000000000001" {
		t.Errorf("defer_id = %q", got.DeferID)
	}
	if got.Target != "shell.exec" || got.Method != "tools/call" || got.Surface != deferred.SurfaceMCPStdio {
		t.Errorf("unexpected view: %+v", got)
	}
	if got.SessionID != "sess-1" || got.Principal != "agent-a" {
		t.Errorf("identity not surfaced: %+v", got)
	}

	// The raw held payload must never appear on the operator surface.
	if bytes.Contains(rr.Body.Bytes(), []byte("SECRET-EXFIL-PAYLOAD")) {
		t.Errorf("response leaked the raw held payload: %s", rr.Body.String())
	}
}

func TestHandleDeferredList_RequiresAuth(t *testing.T) {
	h := deferredTestHandler(seededDeferManager(t))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/deferred", nil) // no Authorization
	rr := httptest.NewRecorder()

	h.HandleDeferredList(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestHandleDeferredList_NotConfiguredWhenManagerNil(t *testing.T) {
	h := NewSessionAPIHandler(SessionAPIOptions{APIToken: deferredTestToken}) // nil deferred manager
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/deferred", nil)
	req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	rr := httptest.NewRecorder()

	h.HandleDeferredList(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestHandleDeferredList_RejectsNonGET(t *testing.T) {
	h := deferredTestHandler(seededDeferManager(t))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/deferred", nil)
	req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	rr := httptest.NewRecorder()

	h.HandleDeferredList(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}
