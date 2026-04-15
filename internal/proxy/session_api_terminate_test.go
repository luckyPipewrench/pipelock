// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	terminateIdentityKey   = "terminate-agent|10.0.0.9"
	terminateInvocationKey = "mcp-stdio-99"
	terminateAuthHeader    = "Bearer " + testSessionAPIToken
)

func terminateURLFor(key string) string {
	return "/api/v1/sessions/" + url.PathEscape(key) + "/terminate"
}

func TestSessionAPI_HandleTerminate_HappyPath(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate(terminateIdentityKey)
	_, _, _ = sess.Airlock().SetTier(config.AirlockTierHard)

	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var res SessionTerminateResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Terminated {
		t.Error("Terminated: got false, want true")
	}
	if res.PreviousTier != config.AirlockTierHard {
		t.Errorf("PreviousTier: got %q, want %q", res.PreviousTier, config.AirlockTierHard)
	}

	// Post-condition: session still exists, tier is now none.
	postSnap, _, found := sm.SnapshotByKey(terminateIdentityKey)
	if !found {
		t.Error("session should still exist in manager after terminate")
	}
	if postSnap.AirlockTier != config.AirlockTierNone {
		t.Errorf("post tier: got %q, want none", postSnap.AirlockTier)
	}
}

func TestSessionAPI_HandleTerminate_CEEStateCleared(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(terminateIdentityKey)

	var smPtr atomic.Pointer[SessionManager]
	smPtr.Store(sm)

	// Provide non-nil CEE state pointers so the handler clears them.
	et := scanner.NewEntropyTracker(1000, 300)
	fb := scanner.NewFragmentBuffer(1000, 2, 300)
	t.Cleanup(func() {
		et.Close()
		fb.Close()
	})
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	etPtr.Store(et)
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	fbPtr.Store(fb)

	handler := NewSessionAPIHandler(SessionAPIOptions{
		SessionMgrPtr: &smPtr,
		EntropyPtr:    &etPtr,
		FragmentPtr:   &fbPtr,
		Logger:        audit.NewNop(),
		APIToken:      testSessionAPIToken,
	})

	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}

	var res SessionTerminateResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.CEEStateCleared {
		t.Error("CEEStateCleared: got false, want true")
	}
}

func TestSessionAPI_HandleTerminate_InvocationKeyRejected(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(terminateInvocationKey)

	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateInvocationKey), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error == "" {
		t.Error("error body should describe the rejection")
	}
}

func TestSessionAPI_HandleTerminate_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, terminateURLFor("ghost|1.2.3.4"), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

func TestSessionAPI_HandleTerminate_MethodNotAllowed(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, terminateURLFor(terminateIdentityKey), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow: got %q, want %q", allow, http.MethodPost)
	}
}

func TestSessionAPI_HandleTerminate_Unauthorized(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), nil)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
}

func TestSessionAPI_HandleTerminate_BadPath(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions//terminate", nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}

func TestSessionAPI_HandleTerminate_RejectsUnknownFields(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(terminateIdentityKey)
	handler := newTestSessionAPIHandler(t, sm)

	body := bytes.NewBufferString(`{"unexpected_field": "value"}`)
	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), body)
	req.Header.Set("Authorization", terminateAuthHeader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}

func TestSessionAPI_HandleTerminate_EmptyBodyOK(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(terminateIdentityKey)
	handler := newTestSessionAPIHandler(t, sm)

	// Zero-length body is allowed — decodeJSONBody treats empty as "no
	// fields" and leaves the target struct at its zero value.
	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), bytes.NewBuffer(nil))
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestSessionAPI_HandleTerminate_NoCEEPointers(t *testing.T) {
	// No CEE pointers wired in — handler should still terminate cleanly.
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(terminateIdentityKey)

	var smPtr atomic.Pointer[SessionManager]
	smPtr.Store(sm)
	handler := NewSessionAPIHandler(SessionAPIOptions{
		SessionMgrPtr: &smPtr,
		// EntropyPtr and FragmentPtr intentionally nil.
		Logger:   audit.NewNop(),
		APIToken: testSessionAPIToken,
	})

	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var res SessionTerminateResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.CEEStateCleared {
		t.Error("CEEStateCleared should be false with nil CEE pointers")
	}
}

func TestSessionAPI_HandleTerminate_NoCEEStateLoaded(t *testing.T) {
	// CEE pointers provided but nothing Stored — Load returns nil.
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(terminateIdentityKey)

	var smPtr atomic.Pointer[SessionManager]
	smPtr.Store(sm)
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	handler := NewSessionAPIHandler(SessionAPIOptions{
		SessionMgrPtr: &smPtr,
		EntropyPtr:    &etPtr,
		FragmentPtr:   &fbPtr,
		Logger:        audit.NewNop(),
		APIToken:      testSessionAPIToken,
	})

	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var res SessionTerminateResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.CEEStateCleared {
		t.Error("CEEStateCleared should be false when both Load() return nil")
	}
}

func TestExtractSessionKeyOnly_BadPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"wrong api", "/wrong/v1/sessions/k", false},
		{"wrong version", "/api/v2/sessions/k", false},
		{"wrong segment", "/api/v1/sess/k", false},
		{"5 segments", "/api/v1/sessions/k/reset", false},
		{"3 segments", "/api/v1/sessions", false},
		{"empty key", "/api/v1/sessions/", false},
		{"null byte", "/api/v1/sessions/foo%00", false},
		{"valid", "/api/v1/sessions/agent%7C1.2.3.4", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			_, ok := extractSessionKeyOnly(req)
			if ok != tt.want {
				t.Errorf("got ok=%v, want %v for path %q", ok, tt.want, tt.path)
			}
		})
	}
}

func TestAttachMostRecentEvidence_AllEmptyEvents(t *testing.T) {
	// All events have empty Kind AND empty Detail — loop skips everything
	// without setting evidence fields.
	exp := &SessionExplanation{}
	events := []SessionEvent{{Kind: "", Detail: ""}, {Kind: "", Detail: ""}}
	attachMostRecentEvidence(exp, events)
	if exp.EvidenceKind != "" || exp.EvidenceDetail != "" {
		t.Errorf("expected no evidence attached, got kind=%q detail=%q", exp.EvidenceKind, exp.EvidenceDetail)
	}
}

func TestSessionAPI_HandleTerminate_RateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(terminateIdentityKey)
	handler := newTestSessionAPIHandler(t, sm)

	for i := 0; i < sessionAPIRateLimitMax; i++ {
		req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), nil)
		req.Header.Set("Authorization", terminateAuthHeader)
		w := httptest.NewRecorder()
		handler.HandleTerminate(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d", i, w.Code)
		}
		// Re-create the session since terminate evicts it back to normal;
		// Snapshot is still valid but this keeps the loop idempotent.
		sm.GetOrCreate(terminateIdentityKey)
	}

	req := httptest.NewRequest(http.MethodPost, terminateURLFor(terminateIdentityKey), nil)
	req.Header.Set("Authorization", terminateAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleTerminate(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status: got %d, want 429", w.Code)
	}
}
