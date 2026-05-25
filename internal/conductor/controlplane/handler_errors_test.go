// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
)

func TestNewHandlerValidation(t *testing.T) {
	store := mustStore(t)
	identity := func(*http.Request) (FollowerIdentity, error) {
		return FollowerIdentity{OrgID: "org", FleetID: "fleet", InstanceID: "instance", Environment: "prod"}, nil
	}
	authorizer := func(*http.Request) error { return nil }

	if _, err := NewHandler(HandlerOptions{FollowerIdentity: identity, AuthorizePublisher: authorizer}); !errors.Is(err, ErrStoreRequired) {
		t.Fatalf("NewHandler(nil store) error = %v, want ErrStoreRequired", err)
	}
	if _, err := NewHandler(HandlerOptions{Store: store, AuthorizePublisher: authorizer}); !errors.Is(err, ErrFollowerRequired) {
		t.Fatalf("NewHandler(nil identity) error = %v, want ErrFollowerRequired", err)
	}
	if _, err := NewHandler(HandlerOptions{Store: store, FollowerIdentity: identity}); !errors.Is(err, ErrPublisherForbidden) {
		t.Fatalf("NewHandler(nil publisher) error = %v, want ErrPublisherForbidden", err)
	}
	if _, err := NewHandler(HandlerOptions{
		Store:              store,
		FollowerIdentity:   identity,
		AuthorizePublisher: authorizer,
		Capabilities:       conductor.CapabilitiesResponse{SchemaVersion: conductor.SchemaVersion},
	}); err == nil {
		t.Fatal("NewHandler(invalid capabilities) error = nil, want error")
	}
}

func TestHandlerMapsStoreErrors(t *testing.T) {
	internalErr := errors.New("database password leaked")
	for _, tc := range []struct {
		name string
		err  error
		code int
		body string
	}{
		{name: "conflict", err: ErrBundleConflict, code: http.StatusConflict},
		{name: "rollback", err: ErrUnsupportedRollback, code: http.StatusConflict},
		{name: "too-large", err: conductor.ErrPayloadTooLarge, code: http.StatusRequestEntityTooLarge},
		{name: "expired", err: conductor.ErrExpired, code: http.StatusUnprocessableEntity},
		{name: "internal", err: internalErr, code: http.StatusInternalServerError, body: "internal server error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := newTestHandler(t, fakeStore{publishErr: tc.err}, nil)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, PublishPolicyBundlePath, strings.NewReader(`{"bundle":{}}`))
			req.Header.Set("X-Pipelock-Publisher", "ok")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.code {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tc.code)
			}
			if tc.body != "" && !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("body = %s, want %q", w.Body.String(), tc.body)
			}
			if strings.Contains(w.Body.String(), internalErr.Error()) {
				t.Fatalf("body leaked internal error: %s", w.Body.String())
			}
		})
	}
}

func TestHandlerLatestNoBundleAndStoreError(t *testing.T) {
	handler := newTestHandler(t, fakeStore{latestErr: ErrBundleNotFound}, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("latest no bundle status = %d, want 204", w.Code)
	}

	handler = newTestHandler(t, fakeStore{latestErr: errors.New("store unavailable")}, nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("latest store error status = %d body=%s, want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal server error") || strings.Contains(w.Body.String(), "store unavailable") {
		t.Fatalf("latest store error body = %s, want generic internal error", w.Body.String())
	}
}

func TestFollowerIdentityValidate(t *testing.T) {
	valid := FollowerIdentity{OrgID: "org", FleetID: "fleet", InstanceID: "instance", Environment: "prod"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid) error = %v", err)
	}
	for _, identity := range []FollowerIdentity{
		{FleetID: "fleet", InstanceID: "instance", Environment: "prod"},
		{OrgID: "org", InstanceID: "instance", Environment: "prod"},
		{OrgID: "org", FleetID: "fleet", Environment: "prod"},
		{OrgID: "org", FleetID: "fleet", InstanceID: "instance"},
	} {
		if err := identity.Validate(); !errors.Is(err, ErrFollowerRequired) {
			t.Fatalf("Validate(%+v) error = %v, want ErrFollowerRequired", identity, err)
		}
	}
}

func TestStoreValidationEdges(t *testing.T) {
	if _, err := OpenFileBundleStore(""); err == nil {
		t.Fatal("OpenFileBundleStore(empty) error = nil, want error")
	}
	if _, err := OpenFileBundleStore("relative"); err == nil {
		t.Fatal("OpenFileBundleStore(relative) error = nil, want error")
	}
	if _, _, err := (*FileBundleStore)(nil).Publish(t.Context(), conductor.PolicyBundle{}, PublishOptions{}); !errors.Is(err, ErrStoreRequired) {
		t.Fatalf("nil Publish() error = %v, want ErrStoreRequired", err)
	}
	if _, err := (*FileBundleStore)(nil).Latest(t.Context(), FollowerIdentity{}, testNow); !errors.Is(err, ErrStoreRequired) {
		t.Fatalf("nil Latest() error = %v, want ErrStoreRequired", err)
	}

	store := mustStore(t)
	expired := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "expired-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), expired, PublishOptions{Now: testNow.Add(3 * time.Hour)}); !errors.Is(err, conductor.ErrExpired) {
		t.Fatalf("Publish(expired) error = %v, want ErrExpired", err)
	}
}

type fakeStore struct {
	publishErr error
	latestErr  error
	latest     PublishedBundle
}

func (f fakeStore) Publish(context.Context, conductor.PolicyBundle, PublishOptions) (PublishedBundle, bool, error) {
	return PublishedBundle{}, false, f.publishErr
}

func (f fakeStore) Latest(context.Context, FollowerIdentity, time.Time) (PublishedBundle, error) {
	if f.latestErr != nil {
		return PublishedBundle{}, f.latestErr
	}
	return f.latest, nil
}
