//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// A realistic store supports the bound clear. The handler refuses rather than
// clearing unconditionally when it cannot bind the delete to the record the
// scope check approved, so a double lacking this would exercise the refusal
// path instead of the store-error path this case is written for.
func (erroringClearer) ClearRollbackAuthorizationMatching(context.Context, string, string) (bool, error) {
	return false, errors.New("clear failed")
}

func (erroringClearer) RollbackAuthorizationByID(context.Context, string) (StoredRollbackAuthorization, bool, error) {
	return StoredRollbackAuthorization{Authorization: conductor.RollbackAuthorization{
		OrgID: "org-main", FleetID: "prod",
	}}, true, nil
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

	t.Run("cross-org authorization is hidden and not cleared", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		auth := signedTestRollback(t, "rollback-other-org", testNow, 100)
		if _, created, err := handler.emergencyControls.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
			t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"rollback-other-org"}`, true))
		if w.Code != http.StatusNotFound {
			t.Fatalf("cross-org clear status=%d body=%s, want 404", w.Code, w.Body.String())
		}
		reader := handler.emergencyControls.(rollbackAuthorizationByIDReader)
		if _, found, err := reader.RollbackAuthorizationByID(t.Context(), "rollback-other-org"); err != nil || !found {
			t.Fatalf("cross-org rollback missing after denied clear: found=%v err=%v", found, err)
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

	t.Run("wrapped store without clearer returns 501", func(t *testing.T) {
		handler, err := NewHandler(HandlerOptions{
			Store:              mustStore(t),
			Capabilities:       DefaultCapabilities("conductor-test"),
			Now:                func() time.Time { return testNow },
			FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
			AuthorizePublisher: func(*http.Request) error { return nil },
			AuthenticateAdmin:  allowTestAdmin,
			AuditSink:          discardAuditSink{},
			AuditKeys:          rejectingAuditKeyResolver,
			EmergencyControls:  failingEmergencyStore{},
		})
		if err != nil {
			t.Fatalf("NewHandler() error = %v", err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"x"}`, true))
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("status=%d body=%s, want 501", w.Code, w.Body.String())
		}
	})

	// The scope check reads a record, and the delete happens in a separate
	// store call. If the id is remapped in between, an unconditional delete
	// removes the REPLACEMENT, which is a cross-tenant deletion the scope check
	// appeared to have prevented. The store binds the delete to the record hash
	// the caller authorised, so a swapped record is left alone.
	t.Run("a record replaced between the scope check and the delete is not cleared", func(t *testing.T) {
		handler := newTestHandler(t, mustStore(t), nil)
		swapping := &swapOnReadStore{}
		handler.emergencyControls = swapping

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, clearRollbackRequest(`{"authorization_id":"auth-victim"}`, true))

		if swapping.clearedHash != "" && swapping.clearedHash != swapping.readHash {
			t.Fatalf("cleared hash %q differs from the authorised hash %q, so a replacement record was deleted",
				swapping.clearedHash, swapping.readHash)
		}
		if swapping.replacementRemoved {
			t.Fatal("the replacement record was removed; the delete was not bound to the authorised record")
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

// swapOnReadStore simulates the record being replaced between the handler's
// scope-check read and its delete. It records the hash the handler authorised
// and the hash it then asked to clear, so the test can assert the two agree
// rather than asserting on a message.
type swapOnReadStore struct {
	failingEmergencyStore
	readHash           string
	clearedHash        string
	replacementRemoved bool
}

func (s *swapOnReadStore) RollbackAuthorizationByID(context.Context, string) (StoredRollbackAuthorization, bool, error) {
	s.readHash = "hash-victim"
	return StoredRollbackAuthorization{
		Authorization:     conductor.RollbackAuthorization{OrgID: "org-main", FleetID: "prod"},
		AuthorizationHash: s.readHash,
	}, true, nil
}

// The handler resolves the base clearer first, so a double lacking this never
// reaches the bound path and every assertion about it passes vacuously. That
// happened on the first attempt at this test.
func (s *swapOnReadStore) ClearRollbackAuthorization(_ context.Context, _ string) (bool, error) {
	s.replacementRemoved = true
	return true, nil
}

func (s *swapOnReadStore) ClearRollbackAuthorizationMatching(_ context.Context, _ string, expectedHash string) (bool, error) {
	s.clearedHash = expectedHash
	// The id now resolves to a different organisation's record. A store that
	// honours the binding must refuse; one that ignores it removes this.
	const replacementHash = "hash-other-org"
	if expectedHash != "" && expectedHash != replacementHash {
		return false, nil
	}
	s.replacementRemoved = true
	return true, nil
}
