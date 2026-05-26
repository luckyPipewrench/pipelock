// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func TestHandlerPublishesAndServesLatestBundle(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	handler := newTestHandler(t, store, nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
	})
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Publisher", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("publish status = %d body=%s, want 201", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("latest status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	if w.Header().Get("ETag") == "" {
		t.Fatal("latest ETag empty")
	}
	var got conductor.PolicyBundle
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode latest: %v", err)
	}
	if got.BundleID != "bundle-1" {
		t.Fatalf("latest bundle_id = %q, want bundle-1", got.BundleID)
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil)
	req.Header.Set("If-None-Match", w.Header().Get("ETag"))
	w304 := httptest.NewRecorder()
	handler.ServeHTTP(w304, req)
	if w304.Code != http.StatusNotModified {
		t.Fatalf("latest If-None-Match status = %d, want 304", w304.Code)
	}
}

func TestIfNoneMatchMatches(t *testing.T) {
	etag := `"abc123"`
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "empty", raw: "", want: false},
		{name: "exact", raw: etag, want: true},
		{name: "wildcard", raw: "*", want: true},
		{name: "comma list", raw: `"other", "abc123"`, want: true},
		{name: "weak candidate", raw: `W/"abc123"`, want: true},
		{name: "miss", raw: `"other"`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ifNoneMatchMatches(tt.raw, etag); got != tt.want {
				t.Fatalf("ifNoneMatchMatches(%q, %q) = %v, want %v", tt.raw, etag, got, tt.want)
			}
		})
	}
}

func TestHandlerCapabilities(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, conductor.CapabilitiesPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var got conductor.CapabilitiesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("capabilities Validate() error = %v", err)
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, conductor.CapabilitiesPath, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("capabilities wrong method status = %d, want 405", w.Code)
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/missing", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing path status = %d, want 404", w.Code)
	}
}

func TestHandlerHealthAndReady(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	probes := handler.ProbeHandler()
	for _, path := range []string{HealthPath, HealthzPath} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("%s status = %d body=%s, want 200", path, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), `"status":"ok"`) {
				t.Fatalf("%s body = %s, want status ok", path, w.Body.String())
			}
		})
	}

	w := httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, ReadyzPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ready status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var got readyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode ready response: %v", err)
	}
	if got.Status != "ready" || !got.Subsystems.PolicyStore || !got.Subsystems.AuditSink || !got.Subsystems.AuditKeyResolver {
		t.Fatalf("ready response = %+v", got)
	}
	if got.Subsystems.AuditQuerySupported {
		t.Fatalf("ready audit_query_supported = true for discard sink, want false")
	}

	w = httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, ReadyzPath, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("ready wrong method status=%d allow=%q, want 405 GET", w.Code, w.Header().Get("Allow"))
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, HealthzPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("main healthz status = %d body=%s, want 404", w.Code, w.Body.String())
	}
}

func TestHandlerMetricsAndRequestLogging(t *testing.T) {
	var logs bytes.Buffer
	m := metrics.New()
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return FollowerIdentity{}, ErrFollowerRequired
		},
		AuthorizePublisher: func(*http.Request) error { return ErrPublisherForbidden },
		AuditSink:          failingAuditQuerySink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Metrics:            m,
		Logger:             slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	probes := handler.ProbeHandler()

	w := httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, HealthzPath+"?probe_id=opaque", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%s, want 200", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("audit ingest status = %d body=%s, want 401", w.Code, w.Body.String())
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"?org_id=org-main", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("audit query status = %d body=%s, want 403", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, MetricsPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`pipelock_conductor_server_requests_total{method="GET",route="/healthz",status="200"} 1`,
		`pipelock_conductor_server_audit_ingest_total{outcome="rejected",reason="unauthorized"} 1`,
		`pipelock_conductor_server_audit_queries_total{outcome="rejected",reason="forbidden"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q:\n%s", want, body)
		}
	}
	logBody := logs.String()
	if !strings.Contains(logBody, `"event":"conductor_request"`) || !strings.Contains(logBody, `"route":"/healthz"`) {
		t.Fatalf("logs = %s, want conductor request route", logBody)
	}
	if strings.Contains(logBody, "probe_id") || strings.Contains(logBody, "opaque") {
		t.Fatalf("logs leaked query value: %s", logBody)
	}

	pub, priv := testAuditSigner(t)
	successMetrics := metrics.New()
	successHandler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          &captureAuditSink{},
		AuditKeys:          auditKeyResolverFor(pub),
		Metrics:            successMetrics,
	})
	if err != nil {
		t.Fatalf("NewHandler(success) error = %v", err)
	}
	w = postAuditBatch(t, successHandler, signedAuditIngestRequest(t, defaultFollowerIdentity(), []byte(`{"entry":"ok"}`), priv, testNow))
	if w.Code != http.StatusAccepted {
		t.Fatalf("successful audit ingest status = %d body=%s, want 202", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	successHandler.ProbeHandler().ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, MetricsPath, nil))
	if !strings.Contains(w.Body.String(), `pipelock_conductor_server_audit_ingest_total{outcome="accepted",reason="ok"} 1`) {
		t.Fatalf("successful ingest metric missing:\n%s", w.Body.String())
	}
}

func TestHandlerRejectsUnauthenticatedPublisherAndStrictJSON(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, strings.NewReader(`{}`)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized publish status = %d, want 403", w.Code)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, strings.NewReader(`{"bundle":{},"extra":true}`))
	req.Header.Set("X-Pipelock-Publisher", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field publish status = %d body=%s, want 400", w.Code, w.Body.String())
	}

	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
	})
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, strings.NewReader(string(body)+"{}"))
	req.Header.Set("X-Pipelock-Publisher", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing document status = %d body=%s, want 400", w.Code, w.Body.String())
	}
}

func TestHandlerLatestRequiresFollowerIdentity(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), func(*http.Request) (FollowerIdentity, error) {
		return FollowerIdentity{}, ErrFollowerRequired
	})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing identity status = %d, want 401", w.Code)
	}
}

func TestHandlerMethodChecks(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, LatestPolicyBundlePath, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method status=%d allow=%q, want 405 GET", w.Code, w.Header().Get("Allow"))
	}
}

func newTestHandler(t *testing.T, store BundleStore, identity FollowerIdentityResolver) *Handler {
	t.Helper()
	if identity == nil {
		identity = func(*http.Request) (FollowerIdentity, error) {
			return FollowerIdentity{
				OrgID:       "org-main",
				FleetID:     "prod",
				InstanceID:  "pl-prod-1",
				Environment: "prod",
			}, nil
		}
	}
	publisher := func(r *http.Request) error {
		if r.Header.Get("X-Pipelock-Publisher") != "ok" {
			return ErrPublisherForbidden
		}
		return nil
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              store,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   identity,
		AuthorizePublisher: publisher,
		AuthorizeBundle: func(r *http.Request, _ conductor.PolicyBundle) error {
			return publisher(r)
		},
		AuditSink: discardAuditSink{},
		AuditKeys: rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func mustStore(t *testing.T) *FileBundleStore {
	t.Helper()
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	return store
}
