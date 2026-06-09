//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
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
	if _, err := NewHandler(HandlerOptions{Store: store, FollowerIdentity: identity, AuthorizePublisher: authorizer, AuditKeys: rejectingAuditKeyResolver}); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("NewHandler(nil audit sink) error = %v, want ErrAuditSinkRequired", err)
	}
	if _, err := NewHandler(HandlerOptions{Store: store, FollowerIdentity: identity, AuthorizePublisher: authorizer, AuditSink: discardAuditSink{}}); !errors.Is(err, ErrAuditKeyRequired) {
		t.Fatalf("NewHandler(nil audit keys) error = %v, want ErrAuditKeyRequired", err)
	}
	if _, err := NewHandler(HandlerOptions{
		Store:              store,
		FollowerIdentity:   identity,
		AuthorizePublisher: authorizer,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Capabilities:       conductor.CapabilitiesResponse{SchemaVersion: conductor.SchemaVersion},
	}); err == nil {
		t.Fatal("NewHandler(invalid capabilities) error = nil, want error")
	}
}

func TestHandlerDefaultAuthorizersDenyNewScopedOperations(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	auditStore := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = auditStore.Close() }()
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          auditStore,
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
	})
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
	if err != nil {
		t.Fatalf("Marshal(bundle) error = %v", err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("publish status = %d body=%s, want 403", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"?org_id=org-main", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("audit query status = %d body=%s, want 403", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, strings.NewReader(`{}`)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("enrollment token status = %d body=%s, want 403", w.Code, w.Body.String())
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
		// Client-input validation sentinels produced by PolicyBundle.Validate
		// must map to 4xx, never fall through to 500. Mirrors the audit-ingest
		// path's choices: malformed structure -> 400, hash mismatch -> 422.
		{name: "schema-version", err: conductor.ErrUnsupportedSchemaVersion, code: http.StatusBadRequest, body: conductor.ErrUnsupportedSchemaVersion.Error()},
		{name: "invalid-hash", err: conductor.ErrInvalidHash, code: http.StatusBadRequest, body: conductor.ErrInvalidHash.Error()},
		{name: "invalid-sequence-range", err: conductor.ErrInvalidSequenceRange, code: http.StatusBadRequest, body: conductor.ErrInvalidSequenceRange.Error()},
		{name: "invalid-dropped-accounting", err: conductor.ErrInvalidDroppedAccounting, code: http.StatusBadRequest, body: conductor.ErrInvalidDroppedAccounting.Error()},
		{name: "invalid-min-version", err: conductor.ErrInvalidMinVersion, code: http.StatusBadRequest, body: conductor.ErrInvalidMinVersion.Error()},
		{name: "hash-mismatch", err: conductor.ErrHashMismatch, code: http.StatusUnprocessableEntity, body: conductor.ErrHashMismatch.Error()},
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

func TestHandlerValidationSentinelsReachRealPublishHandlers(t *testing.T) {
	signer := newTestSigner(t)
	for _, tc := range []struct {
		name   string
		mutate func(*conductor.PolicyBundle)
		code   int
		body   string
	}{
		{
			name:   "unsupported_schema_version",
			mutate: func(b *conductor.PolicyBundle) { b.SchemaVersion = 99 },
			code:   http.StatusBadRequest,
			body:   conductor.ErrUnsupportedSchemaVersion.Error(),
		},
		{
			name:   "invalid_hash",
			mutate: func(b *conductor.PolicyBundle) { b.PayloadSHA256 = "not-hex" },
			code:   http.StatusBadRequest,
			body:   conductor.ErrInvalidHash.Error(),
		},
		{
			name:   "invalid_min_version",
			mutate: func(b *conductor.PolicyBundle) { b.MinPipelockVersion = "01.2.3" },
			code:   http.StatusBadRequest,
			body:   conductor.ErrInvalidMinVersion.Error(),
		},
		{
			name: "hash_mismatch",
			mutate: func(b *conductor.PolicyBundle) {
				b.Payload.ConfigYAML = "mode: balanced\napi_allowlist:\n  - api.example.com\n"
			},
			code: http.StatusUnprocessableEntity,
			body: conductor.ErrHashMismatch.Error(),
		},
	} {
		t.Run("policy_"+tc.name, func(t *testing.T) {
			bundle := signedControlBundle(t, signer, bundleSpec{
				id:       "bundle-" + strings.ReplaceAll(tc.name, "_", "-"),
				version:  1,
				audience: conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
			})
			tc.mutate(&bundle)
			data, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
			if err != nil {
				t.Fatalf("Marshal(bundle) error = %v", err)
			}
			handler := newTestHandler(t, mustStore(t), nil)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(data))
			req.Header.Set("X-Pipelock-Publisher", "ok")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.code {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tc.code)
			}
			if !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("body = %s, want %q", w.Body.String(), tc.body)
			}
		})
	}

	pub, priv := testAuditSigner(t)
	for _, tc := range []struct {
		name   string
		mutate func(*ingestAuditBatchRequest)
		body   string
	}{
		{
			name: "invalid_sequence_range",
			mutate: func(req *ingestAuditBatchRequest) {
				req.Envelope.SeqEnd = req.Envelope.SeqStart - 1
			},
			body: conductor.ErrInvalidSequenceRange.Error(),
		},
		{
			name: "invalid_dropped_accounting",
			mutate: func(req *ingestAuditBatchRequest) {
				req.Envelope.Dropped = conductor.DroppedAccounting{Count: 1}
			},
			body: conductor.ErrInvalidDroppedAccounting.Error(),
		},
	} {
		t.Run("audit_"+tc.name, func(t *testing.T) {
			req := signedAuditIngestRequest(t, defaultFollowerIdentity(), []byte(`{"entry":"ok"}`), priv, testNow)
			tc.mutate(&req)
			handler := newAuditIngestTestHandler(t, &captureAuditSink{}, auditKeyResolverFor(pub), 0)
			w := postAuditBatch(t, handler, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s, want 400", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("body = %s, want %q", w.Body.String(), tc.body)
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
