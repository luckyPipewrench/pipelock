//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// erroringClearer implements EmergencyStore (via the embedded
// failingEmergencyStore) plus the optional rollbackClearer interface, returning
// an error from the clear so the handler's writeStoreError branch is exercised.
type erroringClearer struct {
	failingEmergencyStore
}

func (erroringClearer) ClearRollbackAuthorization(context.Context, string) (bool, error) {
	return false, errors.New("clear failed")
}

func clearRollbackRequest(body string, admin bool) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, RollbackAuthorizationsPath, strings.NewReader(body))
	if admin {
		req.Header.Set("X-Pipelock-Admin", "ok")
	}
	return req
}

// TestHandlerClearRollbackAuthorization drives the DELETE
// /api/v1/conductor/rollback-authorizations handler through every branch: the
// nil-store and non-clearer 501s, the admin-forbidden 403, malformed/oversized
// body, empty authorization_id, store error, not-found, and the success path.
func TestHandlerClearRollbackAuthorization(t *testing.T) {
	t.Run("success clears existing authorization then 404 on retry", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		signer := newTestSigner(t)
		wildcard := conductor.Audience{InstanceIDs: []string{"*"}}
		v1 := signedControlBundle(t, signer, bundleSpec{id: "bundle-clear-v1", version: 1, audience: wildcard})
		v2 := signedControlBundle(t, signer, bundleSpec{id: "bundle-clear-v2", version: 2, audience: wildcard})
		auth := signedRollbackAuthorizationForBundles(t, "rollback-clear-ok", v2, v1, testNow)
		if _, created, err := handler.emergencyControls.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
			t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"rollback-clear-ok"}`, true))
		if w.Code != http.StatusOK {
			t.Fatalf("clear status=%d body=%s, want 200", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"cleared":true`) {
			t.Fatalf("clear body=%s, want cleared:true", w.Body.String())
		}

		// The authorization is gone, so a second clear is a 404.
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"rollback-clear-ok"}`, true))
		if w.Code != http.StatusNotFound {
			t.Fatalf("second clear status=%d body=%s, want 404", w.Code, w.Body.String())
		}
	})

	t.Run("unknown authorization_id returns 404", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"does-not-exist"}`, true))
		if w.Code != http.StatusNotFound {
			t.Fatalf("status=%d body=%s, want 404", w.Code, w.Body.String())
		}
	})

	t.Run("empty authorization_id returns 400", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"   "}`, true))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body.String())
		}
	})

	t.Run("malformed json returns 400", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{not valid json`, true))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body.String())
		}
	})

	t.Run("oversized body returns 413", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		handler.maxRequestBody = 8
		big := `{"authorization_id":"` + strings.Repeat("a", 256) + `"}`
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(big, true))
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d body=%s, want 413", w.Code, w.Body.String())
		}
	})

	t.Run("missing admin auth returns 403", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"x"}`, false))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body.String())
		}
	})

	t.Run("nil emergency controls returns 501", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		handler.emergencyControls = nil
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"x"}`, true))
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("status=%d body=%s, want 501", w.Code, w.Body.String())
		}
	})

	t.Run("store without clearer returns 501", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		handler.emergencyControls = failingEmergencyStore{}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"x"}`, true))
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("status=%d body=%s, want 501", w.Code, w.Body.String())
		}
	})

	t.Run("clear error maps to 500", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		handler.emergencyControls = erroringClearer{}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"x"}`, true))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500", w.Code, w.Body.String())
		}
	})
}
