// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
)

const deferredTestToken = "deferred-admin-token"

// resolveCapture records how a held action's resolution callback fired, so a
// test can assert the operator API resumed the waiting client with the correct
// terminal decision (and did so exactly once).
type resolveCapture struct {
	mu    sync.Mutex
	count int
	last  deferred.Resolution
}

func (c *resolveCapture) cb(res deferred.Resolution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	c.last = res
}

func (c *resolveCapture) snapshot() (int, deferred.Resolution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count, c.last
}

// newDeferManager returns an enabled, journal-less manager.
func newDeferManager() *deferred.Manager {
	return deferred.NewManager(deferred.Config{
		Enabled:              true,
		Timeout:              time.Hour,
		MaxPending:           64,
		MaxPendingPerSession: 64,
		MaxPendingBytes:      1 << 20,
		MaxCascadeDepth:      4,
	})
}

// seedHold stores one MCP-stdio hold. When approvable, its rule permits an
// affirmative approval to open it; otherwise a positive approve must still
// resolve closed.
func seedHold(t *testing.T, m *deferred.Manager, id string, approvable bool, cb func(deferred.Resolution)) {
	t.Helper()
	var rp config.DeferResolutionPolicy
	if approvable {
		rp.AllowOn.Approval = true
	}
	if err := m.Hold(deferred.HeldAction{
		DeferID:    id,
		ActionID:   id,
		Surface:    deferred.SurfaceMCPStdio,
		Method:     "tools/call",
		Target:     "shell.exec",
		Reason:     "tool policy: defer",
		RulePolicy: rp,
		Payload:    []byte("SECRET-EXFIL-PAYLOAD"),
		Authority:  deferred.AuthoritySnapshot{SessionID: "sess-1", Principal: "agent-a"},
		Resolve:    cb,
	}); err != nil {
		t.Fatalf("seed hold %s: %v", id, err)
	}
}

// deferredActionReq drives POST /api/v1/deferred/{id}/{action} through the
// handler with the admin token, returning the recorder.
func deferredActionReq(t *testing.T, h *SessionAPIHandler, id, action string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/deferred/"+id+"/"+action, nil)
	if auth {
		req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	}
	rr := httptest.NewRecorder()
	h.HandleDeferredAction(rr, req)
	return rr
}

func TestHandleDeferredAction_ApproveApprovableResolvesAllow(t *testing.T) {
	mgr := newDeferManager()
	rec := &resolveCapture{}
	seedHold(t, mgr, "0193defer00000000000000000010", true, rec.cb)
	h := deferredTestHandler(mgr)

	// Not yet resumed.
	if n, _ := rec.snapshot(); n != 0 {
		t.Fatalf("callback fired before approval: %d", n)
	}

	rr := deferredActionReq(t, h, "0193defer00000000000000000010", deferredActionApprove, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DeferredResolveResult
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.FinalDecision != config.ActionAllow || !resp.Resolved || resp.Action != deferredActionApprove {
		t.Fatalf("unexpected result: %+v", resp)
	}
	// The waiting client is resumed exactly once, with allow, stamped operator.
	n, res := rec.snapshot()
	if n != 1 {
		t.Fatalf("callback fired %d times, want 1", n)
	}
	if res.FinalDecision != config.ActionAllow || res.ResolutionSource != deferred.SourceOperator {
		t.Fatalf("resume decision=%q source=%q, want allow/operator", res.FinalDecision, res.ResolutionSource)
	}
	// The hold is gone from the list after resolution.
	if got := mgr.Snapshot(); len(got) != 0 {
		t.Fatalf("hold still listed after approve: %d", len(got))
	}
}

// TestHandleDeferredAction_ApproveNonApprovableResolvesBlock is the core
// security property: an "approve" on a hold whose rule does NOT permit approval
// must resolve CLOSED (block) and report final_decision:"block", never a
// misleading success. A trivial fix must not be a trivial bypass.
func TestHandleDeferredAction_ApproveNonApprovableResolvesBlock(t *testing.T) {
	mgr := newDeferManager()
	rec := &resolveCapture{}
	seedHold(t, mgr, "0193defer00000000000000000011", false, rec.cb) // rule forbids approval
	h := deferredTestHandler(mgr)

	rr := deferredActionReq(t, h, "0193defer00000000000000000011", deferredActionApprove, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DeferredResolveResult
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.FinalDecision != config.ActionBlock {
		t.Fatalf("non-approvable approve final_decision=%q, want block", resp.FinalDecision)
	}
	n, res := rec.snapshot()
	if n != 1 || res.FinalDecision != config.ActionBlock {
		t.Fatalf("callback n=%d decision=%q, want 1/block", n, res.FinalDecision)
	}
}

func TestHandleDeferredAction_DenyResolvesBlock(t *testing.T) {
	mgr := newDeferManager()
	rec := &resolveCapture{}
	seedHold(t, mgr, "0193defer00000000000000000012", true, rec.cb) // even an approvable hold is blocked by deny
	h := deferredTestHandler(mgr)

	rr := deferredActionReq(t, h, "0193defer00000000000000000012", deferredActionDeny, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DeferredResolveResult
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.FinalDecision != config.ActionBlock || resp.Action != deferredActionDeny {
		t.Fatalf("unexpected result: %+v", resp)
	}
	n, res := rec.snapshot()
	if n != 1 || res.FinalDecision != config.ActionBlock || res.ResolutionSource != deferred.SourceOperator {
		t.Fatalf("callback n=%d decision=%q source=%q", n, res.FinalDecision, res.ResolutionSource)
	}
}

func TestHandleDeferredAction_UnknownIDReturns404(t *testing.T) {
	mgr := newDeferManager()
	rec := &resolveCapture{}
	seedHold(t, mgr, "0193defer00000000000000000013", true, rec.cb)
	h := deferredTestHandler(mgr)

	rr := deferredActionReq(t, h, "0193defer0000000000000000ffff", deferredActionApprove, true)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404; body=%s", rr.Code, rr.Body.String())
	}
	// No resolver was called: the seeded hold is untouched.
	if n, _ := rec.snapshot(); n != 0 {
		t.Fatalf("resolver called on unknown id: %d", n)
	}
	if got := mgr.Snapshot(); len(got) != 1 {
		t.Fatalf("seeded hold disturbed: %d", len(got))
	}
}

func TestHandleDeferredAction_RequiresAuth(t *testing.T) {
	mgr := newDeferManager()
	rec := &resolveCapture{}
	seedHold(t, mgr, "0193defer00000000000000000014", true, rec.cb)
	h := deferredTestHandler(mgr)

	rr := deferredActionReq(t, h, "0193defer00000000000000000014", deferredActionApprove, false) // no auth
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rr.Code)
	}
	if n, _ := rec.snapshot(); n != 0 {
		t.Fatalf("unauth request resolved a hold: %d", n)
	}
}

func TestHandleDeferredAction_RejectsNonPOST(t *testing.T) {
	h := deferredTestHandler(seededDeferManager(t))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/deferred/0193defer00000000000000000001/approve", nil)
	req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	rr := httptest.NewRecorder()
	h.HandleDeferredAction(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rr.Code)
	}
}

func TestHandleDeferredAction_NotConfiguredWhenManagerNil(t *testing.T) {
	h := NewSessionAPIHandler(SessionAPIOptions{APIToken: deferredTestToken}) // nil manager
	rr := deferredActionReq(t, h, "0193defer00000000000000000001", deferredActionApprove, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
}

func TestHandleDeferredAction_RejectsUnknownBodyField(t *testing.T) {
	mgr := newDeferManager()
	rec := &resolveCapture{}
	seedHold(t, mgr, "0193defer00000000000000000015", true, rec.cb)
	h := deferredTestHandler(mgr)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/deferred/0193defer00000000000000000015/approve",
		strings.NewReader(`{"force":true}`))
	req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	rr := httptest.NewRecorder()
	h.HandleDeferredAction(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if n, _ := rec.snapshot(); n != 0 {
		t.Fatalf("malformed body still resolved a hold: %d", n)
	}
}

func TestHandleDeferredAction_UnknownSuffixNotFound(t *testing.T) {
	h := deferredTestHandler(seededDeferManager(t))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/deferred/0193defer00000000000000000001/bogus", nil)
	req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	rr := httptest.NewRecorder()
	h.HandleDeferredAction(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rr.Code)
	}
}

func TestHandleDeferredAction_EmptyIDBadRequest(t *testing.T) {
	h := deferredTestHandler(seededDeferManager(t))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/deferred//approve", nil)
	req.Header.Set("Authorization", "Bearer "+deferredTestToken)
	rr := httptest.NewRecorder()
	h.HandleDeferredAction(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeferredAction_MalformedPathsFailClosed(t *testing.T) {
	mgr := newDeferManager()
	rec := &resolveCapture{}
	seedHold(t, mgr, "0193defer00000000000000000016", true, rec.cb)
	h := deferredTestHandler(mgr)

	cases := []struct {
		name string
		path string
		want int
	}{
		{
			name: "double encoded slash",
			path: "/api/v1/deferred/%252f/approve",
			want: http.StatusBadRequest,
		},
		{
			name: "encoded nul",
			path: "/api/v1/deferred/%00/approve",
			want: http.StatusBadRequest,
		},
		{
			name: "encoded dot dot remains unknown id",
			path: "/api/v1/deferred/%2e%2e/approve",
			want: http.StatusNotFound,
		},
		{
			name: "trailing slash",
			path: "/api/v1/deferred/0193defer00000000000000000016/approve/",
			want: http.StatusNotFound,
		},
		{
			name: "unknown suffix",
			path: "/api/v1/deferred/0193defer00000000000000000016/approve/extra",
			want: http.StatusNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+deferredTestToken)
			rr := httptest.NewRecorder()
			h.HandleDeferredAction(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status=%d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if n, _ := rec.snapshot(); n != 0 {
				t.Fatalf("malformed path resolved a hold: %d", n)
			}
		})
	}
}

// TestHandleDeferredAction_RateLimited proves the deferred mutate bucket caps
// request volume: after the limit is reached the next request is rejected 429
// before it can touch the manager. checkRateLimit runs before preflight, so a
// resolved-away hold still counts toward the bucket.
func TestHandleDeferredAction_RateLimited(t *testing.T) {
	mgr := newDeferManager()
	seedHold(t, mgr, "0193defer00000000000000000030", true, func(deferred.Resolution) {})
	h := deferredTestHandler(mgr)

	saw429 := false
	for i := 0; i < sessionAPIRateLimitMax+1; i++ {
		rr := deferredActionReq(t, h, "0193defer00000000000000000030", deferredActionApprove, true)
		if rr.Code == http.StatusTooManyRequests {
			saw429 = true
		}
	}
	if !saw429 {
		t.Fatalf("expected a 429 after %d requests in one window", sessionAPIRateLimitMax+1)
	}
}

// TestHandleDeferredAction_ConcurrentResolveSingleWinner proves the fail-closed
// TOCTOU guarantee: many operators racing to resolve the same hold produce
// EXACTLY ONE success and EXACTLY ONE resume of the waiting client; every loser
// gets a fail-closed status (404 unknown or 409 lost-race), never a second
// success. This exercises the preflight-then-resolve race window.
func TestHandleDeferredAction_ConcurrentResolveSingleWinner(t *testing.T) {
	mgr := newDeferManager()
	var callbacks atomic.Int64
	seedHold(t, mgr, "0193defer00000000000000000020", true, func(deferred.Resolution) {
		callbacks.Add(1)
	})
	h := deferredTestHandler(mgr)

	const n = 32
	var wg sync.WaitGroup
	codes := make([]int, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rr := deferredActionReq(t, h, "0193defer00000000000000000020", deferredActionApprove, true)
			codes[i] = rr.Code
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
		case http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests:
			// fail-closed losers are acceptable
		default:
			t.Fatalf("unexpected status in race: %d", c)
		}
	}
	if wins != 1 {
		t.Fatalf("winners=%d, want exactly 1 (no double-resolve)", wins)
	}
	if got := callbacks.Load(); got != 1 {
		t.Fatalf("callback fired %d times, want exactly 1", got)
	}
}

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
