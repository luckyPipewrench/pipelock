//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
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

func TestHandlerPublishesAndServesEmergencyControls(t *testing.T) {
	msg, killResolver := signedRemoteKillMessageWithResolver(t, "kill-handler", 3, conductor.KillSwitchActive, testNow)
	auth, rollbackResolver := signedRollbackAuthorizationWithResolver(t, "rollback-handler", 4, testNow)
	handler := newTestHandlerWithEmergencyKeys(t, killResolver, rollbackResolver)
	body, err := json.Marshal(publishRemoteKillRequest{Message: msg})
	if err != nil {
		t.Fatalf("Marshal(remote kill): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("publish remote kill status=%d body=%s, want 201", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RemoteKillPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("duplicate remote kill status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, RemoteKillPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("latest remote kill status=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var gotKill conductor.RemoteKillMessage
	if err := json.Unmarshal(w.Body.Bytes(), &gotKill); err != nil {
		t.Fatalf("decode remote kill: %v", err)
	}
	if gotKill.MessageID != msg.MessageID {
		t.Fatalf("remote kill message_id=%q, want %q", gotKill.MessageID, msg.MessageID)
	}

	body, err = json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("publish rollback status=%d body=%s, want 201", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("duplicate rollback status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		RollbackAuthorizationsPath+"?current_bundle_id=bundle-current&current_version=42&target_bundle_id=bundle-target&target_version=41", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("latest rollback status=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var gotRollback conductor.RollbackAuthorization
	if err := json.Unmarshal(w.Body.Bytes(), &gotRollback); err != nil {
		t.Fatalf("decode rollback: %v", err)
	}
	if gotRollback.AuthorizationID != auth.AuthorizationID {
		t.Fatalf("rollback authorization_id=%q, want %q", gotRollback.AuthorizationID, auth.AuthorizationID)
	}
}

func TestHandlerRejectsOverlongEmergencyValidity(t *testing.T) {
	msg, killResolver := signedRemoteKillMessageWithTTL(t, "kill-long", 3, conductor.KillSwitchActive, testNow, DefaultRemoteKillMaxValidity+time.Minute)
	auth, rollbackResolver := signedRollbackAuthorizationWithTTL(t, "rollback-long", 4, testNow, DefaultRollbackMaxValidity+time.Minute)
	handler := newTestHandlerWithEmergencyKeys(t, killResolver, rollbackResolver)

	body, err := json.Marshal(publishRemoteKillRequest{Message: msg})
	if err != nil {
		t.Fatalf("Marshal(remote kill): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("publish overlong remote kill status=%d body=%s, want 422", w.Code, w.Body.String())
	}

	body, err = json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("publish overlong rollback status=%d body=%s, want 422", w.Code, w.Body.String())
	}
}

func TestHandlerEmergencyControlErrors(t *testing.T) {
	msg, killResolver := signedRemoteKillMessageWithResolver(t, "kill-errors", 3, conductor.KillSwitchActive, testNow)
	auth, rollbackResolver := signedRollbackAuthorizationWithResolver(t, "rollback-errors", 4, testNow)
	handler := newTestHandlerWithEmergencyKeys(t, killResolver, rollbackResolver)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPatch, RemoteKillPath, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") == "" {
		t.Fatalf("remote kill wrong method status=%d allow=%q, want 405 with Allow", w.Code, w.Header().Get("Allow"))
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPatch, RollbackAuthorizationsPath, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") == "" {
		t.Fatalf("rollback wrong method status=%d allow=%q, want 405 with Allow", w.Code, w.Header().Get("Allow"))
	}

	body, err := json.Marshal(publishRemoteKillRequest{Message: msg})
	if err != nil {
		t.Fatalf("Marshal(remote kill): %v", err)
	}
	remoteBody := string(body)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(remoteBody)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("remote kill unauthorized status=%d body=%s, want 403", w.Code, w.Body.String())
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(`{"message":{},"extra":true}`))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("remote kill strict JSON status=%d body=%s, want 400", w.Code, w.Body.String())
	}

	noKeys := newTestHandler(t, mustStore(t), nil)
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(remoteBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	noKeys.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("remote kill no keys status=%d body=%s, want 501", w.Code, w.Body.String())
	}

	missingStore, err := NewHandler(HandlerOptions{
		Store:              mustStore(t),
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler(missing store): %v", err)
	}
	w = httptest.NewRecorder()
	missingStore.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, RemoteKillPath, nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("remote kill missing store status=%d body=%s, want 501", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(remoteBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	missingStore.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("remote kill publish missing store status=%d body=%s, want 501", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	missingStore.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		RollbackAuthorizationsPath+"?current_bundle_id=bundle-current&current_version=42&target_bundle_id=bundle-target&target_version=41", nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("rollback missing store status=%d body=%s, want 501", w.Code, w.Body.String())
	}

	badSig := newTestHandlerWithEmergencyKeys(t, func(string) (conductor.SignatureKey, error) {
		return conductor.SignatureKey{}, conductor.ErrSignatureVerification
	})
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(remoteBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	badSig.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("remote kill bad signature status=%d body=%s, want 422", w.Code, w.Body.String())
	}

	noMatch := defaultFollowerIdentity()
	noMatch.InstanceID = "pl-prod-2"
	identityMiss := newTestHandlerWithOptions(t, mustStore(t), func(*http.Request) (FollowerIdentity, error) {
		return noMatch, nil
	}, killResolver)
	w = httptest.NewRecorder()
	identityMiss.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, RemoteKillPath, nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("remote kill miss status=%d body=%s, want 204", w.Code, w.Body.String())
	}

	identityErr := newTestHandlerWithOptions(t, mustStore(t), func(*http.Request) (FollowerIdentity, error) {
		return FollowerIdentity{}, ErrFollowerRequired
	}, killResolver)
	w = httptest.NewRecorder()
	identityErr.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, RemoteKillPath, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("remote kill identity error status=%d body=%s, want 401", w.Code, w.Body.String())
	}

	body, err = json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	rollbackBody := string(body)
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(rollbackBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("rollback unauthorized status=%d body=%s, want 403", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(rollbackBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	missingStore.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("rollback publish missing store status=%d body=%s, want 501", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(rollbackBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	noKeys.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("rollback no keys status=%d body=%s, want 501", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(rollbackBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	badSig.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("rollback bad signature status=%d body=%s, want 422", w.Code, w.Body.String())
	}

	smallBody := newTestHandlerWithEmergencyKeys(t, killResolver, rollbackResolver)
	smallBody.maxRequestBody = 1
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(`{"message":{}}`))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	smallBody.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("remote kill too large status=%d body=%s, want 413", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(`{"authorization":{}}`))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	smallBody.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("rollback too large status=%d body=%s, want 413", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, RollbackAuthorizationsPath+"?current_version=x", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("rollback bad query status=%d body=%s, want 400", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		RollbackAuthorizationsPath+"?current_bundle_id=bundle-current&current_version=42&target_bundle_id=bundle-target&target_version=41", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("rollback miss status=%d body=%s, want 204", w.Code, w.Body.String())
	}

	failing := newTestHandlerWithEmergencyKeys(t, killResolver, rollbackResolver)
	failing.emergencyControls = failingEmergencyStore{}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, strings.NewReader(remoteBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	failing.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("remote kill store error status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	failing.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, RemoteKillPath, nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("remote kill latest store error status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(rollbackBody))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w = httptest.NewRecorder()
	failing.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("rollback store error status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	failing.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		RollbackAuthorizationsPath+"?current_bundle_id=bundle-current&current_version=42&target_bundle_id=bundle-target&target_version=41", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("rollback latest store error status=%d body=%s, want 500", w.Code, w.Body.String())
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

func TestStatusHelpersCoverClasses(t *testing.T) {
	tests := map[int]string{
		101: "1xx",
		302: "3xx",
		700: "unknown",
	}
	for status, want := range tests {
		if got := statusClass(status); got != want {
			t.Fatalf("statusClass(%d) = %q, want %q", status, got, want)
		}
	}
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, err := rec.Write([]byte("ok")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if rec.status != http.StatusOK {
		t.Fatalf("recorder status = %d, want 200", rec.status)
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

	w = httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, HealthPath, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("health wrong method status=%d allow=%q, want 405 GET", w.Code, w.Header().Get("Allow"))
	}

	w = httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, MetricsPath, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("metrics wrong method status=%d allow=%q, want 405 GET", w.Code, w.Header().Get("Allow"))
	}

	w = httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, MetricsPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("metrics without registry status=%d body=%s, want 404", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	probes.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/missing", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("probe missing path status=%d body=%s, want 404", w.Code, w.Body.String())
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
	return newTestHandlerWithOptions(t, store, identity, nil)
}

func newTestHandlerWithEmergencyKeys(t *testing.T, resolvers ...conductor.SignatureKeyResolver) *Handler {
	t.Helper()
	resolver := func(keyID string) (conductor.SignatureKey, error) {
		for _, resolve := range resolvers {
			if resolve == nil {
				continue
			}
			key, err := resolve(keyID)
			if err == nil {
				return key, nil
			}
		}
		return conductor.SignatureKey{}, conductor.ErrSignatureVerification
	}
	return newTestHandlerWithOptions(t, mustStore(t), nil, resolver)
}

func newTestHandlerWithOptions(t *testing.T, store BundleStore, identity FollowerIdentityResolver, emergencyKeys conductor.SignatureKeyResolver) *Handler {
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
		AuthorizeAdmin: func(r *http.Request) error {
			if r.Header.Get("X-Pipelock-Admin") != "ok" {
				return ErrPublisherForbidden
			}
			return nil
		},
		EmergencyControls: mustEmergencyStore(t),
		EmergencyKeys:     emergencyKeys,
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

func mustEmergencyStore(t *testing.T) *FileEmergencyStore {
	t.Helper()
	store, err := OpenFileEmergencyStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore() error = %v", err)
	}
	return store
}

type failingEmergencyStore struct{}

func (failingEmergencyStore) PublishRemoteKill(context.Context, conductor.RemoteKillMessage, time.Time) (StoredRemoteKill, bool, error) {
	return StoredRemoteKill{}, false, errors.New("emergency store failed")
}

func (failingEmergencyStore) LatestRemoteKill(context.Context, FollowerIdentity, time.Time) (StoredRemoteKill, error) {
	return StoredRemoteKill{}, errors.New("emergency store failed")
}

func (failingEmergencyStore) PublishRollbackAuthorization(context.Context, conductor.RollbackAuthorization, time.Time) (StoredRollbackAuthorization, bool, error) {
	return StoredRollbackAuthorization{}, false, errors.New("emergency store failed")
}

func (failingEmergencyStore) LatestRollbackAuthorization(context.Context, FollowerIdentity, RollbackLookup, time.Time) (StoredRollbackAuthorization, error) {
	return StoredRollbackAuthorization{}, errors.New("emergency store failed")
}
