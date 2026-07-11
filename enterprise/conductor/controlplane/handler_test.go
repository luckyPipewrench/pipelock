//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	rollbackCeilingBundleV1      = "bundle-ceiling-v1"
	rollbackCeilingBundleV2      = "bundle-ceiling-v2"
	rollbackCeilingBundleV3      = "bundle-ceiling-v3"
	rollbackCeilingMissingTarget = "bundle-ceiling-missing-target"
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

func TestHandlerLatestPolicyBundleRequiresRollbackHead(t *testing.T) {
	store := mustStore(t)
	signer := newTestSigner(t)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       rollbackCeilingBundleV1,
		version:  1,
		audience: audience,
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           rollbackCeilingBundleV2,
		version:      2,
		previousHash: r1.BundleHash,
		audience:     audience,
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	// The rollback ceiling is served through the signature-verifying view, so
	// the handler must trust the keys that signed the authorization.
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-ceiling", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, store, nil, resolver)
	if _, created, err := handler.emergencyControls.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
	}

	w := latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, w, rollbackCeilingBundleV2)
	w = latestRollbackAuthorization(t, handler, auth)
	if w.Code != http.StatusNoContent {
		t.Fatalf("residual rollback auth status=%d body=%s, want 204 until bundle head is rolled back", w.Code, w.Body.String())
	}

	if err := store.ApplyRollbackHead(t.Context(), auth, testNow); err != nil {
		t.Fatalf("ApplyRollbackHead() error = %v", err)
	}
	w = latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, w, rollbackCeilingBundleV1)
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("rollback-ceiling latest ETag empty")
	}
	w = latestRollbackAuthorization(t, handler, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("active rollback auth status=%d body=%s, want 200 after bundle head is rolled back", w.Code, w.Body.String())
	}
	w304 := latestPolicyBundle(t, handler, map[string]string{"If-None-Match": etag})
	if w304.Code != http.StatusNotModified {
		t.Fatalf("rollback-ceiling If-None-Match status=%d body=%s, want 304", w304.Code, w304.Body.String())
	}

	canaryAudience := conductor.Audience{Labels: map[string]string{"ring": "canary"}}
	canaryV1 := signedControlBundle(t, signer, bundleSpec{
		id:         "bundle-ceiling-canary-v1",
		version:    1,
		audience:   canaryAudience,
		configYAML: "mode: strict\napi_allowlist:\n  - canary1.example.com\n",
	})
	canaryR1, _, err := store.Publish(t.Context(), canaryV1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(canary v1) error = %v", err)
	}
	canaryV2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-ceiling-canary-v2",
		version:      2,
		previousHash: canaryR1.BundleHash,
		audience:     canaryAudience,
		configYAML:   "mode: strict\napi_allowlist:\n  - canary2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), canaryV2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(canary v2) error = %v", err)
	}
	handler.followerIdentity = func(*http.Request) (FollowerIdentity, error) {
		return FollowerIdentity{
			OrgID:       "org-main",
			FleetID:     "prod",
			InstanceID:  "pl-prod-canary",
			Environment: "prod",
			Labels:      map[string]string{"ring": "canary"},
		}, nil
	}
	w = latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, w, "bundle-ceiling-canary-v2")

	missingStore := mustStore(t)
	missingCurrent := signedControlBundle(t, signer, bundleSpec{
		id:       rollbackCeilingBundleV2,
		version:  2,
		audience: audience,
	})
	if _, _, err := missingStore.Publish(t.Context(), missingCurrent, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(missing current) error = %v", err)
	}
	missingTarget := signedControlBundle(t, signer, bundleSpec{
		id:       rollbackCeilingMissingTarget,
		version:  1,
		audience: audience,
	})
	missingAuth, missingResolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-missing-target", missingCurrent, missingTarget, testNow)
	missingHandler := newTestHandlerWithOptions(t, missingStore, nil, missingResolver)
	if _, created, err := missingHandler.emergencyControls.PublishRollbackAuthorization(t.Context(), missingAuth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization(missing target) created=%v err=%v, want created", created, err)
	}
	w = latestPolicyBundle(t, missingHandler, nil)
	assertLatestBundleID(t, w, rollbackCeilingBundleV2)
	w = latestRollbackAuthorization(t, missingHandler, missingAuth)
	if w.Code != http.StatusNoContent {
		t.Fatalf("missing rollback target auth status=%d body=%s, want 204", w.Code, w.Body.String())
	}

	handler.followerIdentity = nil
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           rollbackCeilingBundleV3,
		version:      3,
		previousHash: r1.BundleHash,
		audience:     audience,
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v3, PublishOptions{Now: testNow.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("Publish(v3) error = %v", err)
	}
	handler.followerIdentity = func(*http.Request) (FollowerIdentity, error) {
		return defaultFollowerIdentity(), nil
	}
	w = latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, w, rollbackCeilingBundleV3)
}

func TestHandlerPublishRollbackAuthorizationResetsPolicyHead(t *testing.T) {
	store := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-reset-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-reset-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-reset", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, store, nil, resolver)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("rollback publish status=%d body=%s, want 201", w.Code, w.Body.String())
	}
	w = latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, w, "bundle-handler-reset-v1")

	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-reset-v3",
		version:      3,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	body, err = json.Marshal(publishPolicyBundleRequest{Bundle: v3})
	if err != nil {
		t.Fatalf("Marshal(v3): %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, PublishPolicyBundlePath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Publisher", "ok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("forward publish status=%d body=%s, want 201", w.Code, w.Body.String())
	}
	w = latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, w, "bundle-handler-reset-v3")
}

func TestHandlerPublishRollbackAuthorizationMissingTargetDoesNotRecord(t *testing.T) {
	store := mustStore(t)
	signer := newTestSigner(t)
	current := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-missing-current",
		version:  2,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), current, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(current) error = %v", err)
	}
	missingTarget := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-missing-target",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-missing-target-not-recorded", current, missingTarget, testNow)
	handler := newTestHandlerWithOptions(t, store, nil, resolver)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("rollback missing target status=%d body=%s, want 404", w.Code, w.Body.String())
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	if _, err := handler.emergencyControls.LatestRollbackAuthorization(t.Context(), defaultFollowerIdentity(), lookup, testNow); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(after missing target) err=%v, want ErrEmergencyNotFound", err)
	}
}

func TestHandlerPublishRollbackAuthorizationApplyFailureRecordIsNotServed(t *testing.T) {
	base := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-apply-fail-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := base.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-apply-fail-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := base.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-apply-fail", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, applyRollbackFailureStore{BundleStore: base, err: errHandlerApplyRollbackFailed}, nil, resolver)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("rollback apply-fail status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	latest := latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, latest, "bundle-handler-apply-fail-v2")
	servedAuth := latestRollbackAuthorization(t, handler, auth)
	if servedAuth.Code != http.StatusNoContent {
		t.Fatalf("rollback auth after apply failure status=%d body=%s, want 204", servedAuth.Code, servedAuth.Body.String())
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	// The apply failed, so the just-created authorization record is
	// compensating-cleared: replay and audit must never surface an
	// accepted-but-unapplied rollback (split-brain). The record must be gone,
	// not merely un-served.
	if _, err := handler.emergencyControls.LatestRollbackAuthorization(t.Context(), defaultFollowerIdentity(), lookup, testNow); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(after apply failure) err=%v, want ErrEmergencyNotFound (compensating clear)", err)
	}
}

func TestHandlerPublishRollbackAuthorizationConcurrentForwardPublishSupersedesRollback(t *testing.T) {
	base := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-race-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := base.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-race-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	r2, _, err := base.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-race-v3",
		version:      3,
		previousHash: r2.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-race", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, &publishBeforeRollbackApplyStore{FileBundleStore: base, bundle: v3}, nil, resolver)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("rollback race status=%d body=%s, want 409", w.Code, w.Body.String())
	}
	latest := latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, latest, "bundle-handler-race-v3")
	servedAuth := latestRollbackAuthorization(t, handler, auth)
	if servedAuth.Code != http.StatusNoContent {
		t.Fatalf("rollback auth after race status=%d body=%s, want 204", servedAuth.Code, servedAuth.Body.String())
	}
}

func TestHandlerPublishRollbackAuthorizationAppliedThenSupersededKeepsRollbackMarker(t *testing.T) {
	base := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-applied-superseded-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := base.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-applied-superseded-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - applied-superseded2.example.com\n",
	})
	if _, _, err := base.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-applied-superseded-v3",
		version:      3,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - applied-superseded3.example.com\n",
	})
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-applied-superseded", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, &publishAfterRollbackApplyStore{FileBundleStore: base, bundle: v3}, nil, resolver)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("rollback applied-then-superseded status=%d body=%s, want 409", w.Code, w.Body.String())
	}
	latest := latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, latest, "bundle-handler-applied-superseded-v3")
	if _, ok := base.rollbackHeads[r1.StreamKey]; !ok {
		t.Fatal("rollback marker missing after applied rollback was superseded")
	}
	servedAuth := latestRollbackAuthorization(t, handler, auth)
	if servedAuth.Code != http.StatusNoContent {
		t.Fatalf("rollback auth after applied supersede status=%d body=%s, want 204", servedAuth.Code, servedAuth.Body.String())
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	if _, err := handler.emergencyControls.LatestRollbackAuthorization(t.Context(), defaultFollowerIdentity(), lookup, testNow); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(after applied supersede) err=%v, want ErrEmergencyNotFound", err)
	}
}

func TestHandlerPublishRollbackAuthorizationClearFailureResidualRecordIsNotServed(t *testing.T) {
	base := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-clear-fail-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := base.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-clear-fail-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - clear-fail2.example.com\n",
	})
	if _, _, err := base.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-clear-fail", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, applyRollbackFailureStore{BundleStore: base, err: errHandlerApplyRollbackFailed}, nil, resolver)
	handler.emergencyControls = newVerifiedEmergencyStore(rollbackClearFailureEmergencyStore{
		FileEmergencyStore: mustEmergencyStore(t),
		err:                errors.New("forced rollback clear failure"),
	}, resolver, nil, nil)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("rollback clear-fail status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	if record, err := handler.emergencyControls.LatestRollbackAuthorization(t.Context(), defaultFollowerIdentity(), lookup, testNow); err != nil || record.Authorization.AuthorizationID != auth.AuthorizationID {
		t.Fatalf("LatestRollbackAuthorization(clear failure) = %+v, %v; want residual record %q", record.Authorization, err, auth.AuthorizationID)
	}
	servedAuth := latestRollbackAuthorization(t, handler, auth)
	if servedAuth.Code != http.StatusNoContent {
		t.Fatalf("rollback residual auth after clear failure status=%d body=%s, want 204", servedAuth.Code, servedAuth.Body.String())
	}
}

func TestHandlerPublishRollbackAuthorizationSupersededAtPreviewFailsFastWithoutRecord(t *testing.T) {
	base := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-preview-superseded-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := base.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-preview-superseded-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	r2, _, err := base.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-preview-superseded-v3",
		version:      3,
		previousHash: r2.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	if _, _, err := base.Publish(t.Context(), v3, PublishOptions{Now: testNow.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("Publish(v3) error = %v", err)
	}
	// The authorization was signed to roll v2 -> v1, but the stream head has
	// already advanced to v3, so the rollback can never move the head. The
	// request must fail fast at preview time and never durably accept an
	// authorization it cannot apply (no accept-then-compensating-clear churn).
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-preview-superseded", v2, v1, testNow)
	// Spy on ApplyRollbackHead: the fast-fail must reject the superseded request
	// before any apply is attempted. Without the fast-fail the request would
	// still end at 409 (via the post-apply supersession check) after a wasted
	// accept+apply+compensating-clear, so asserting apply is never called is
	// what actually pins the fast-fail behavior.
	store := &applyRollbackSpyStore{FileBundleStore: base}
	handler := newTestHandlerWithOptions(t, store, nil, resolver)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("rollback superseded-at-preview status=%d body=%s, want 409", w.Code, w.Body.String())
	}
	if got := store.applyCalls(); got != 0 {
		t.Fatalf("ApplyRollbackHead called %d times for a superseded-at-preview request, want 0 (fast-fail before apply)", got)
	}
	latest := latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, latest, "bundle-handler-preview-superseded-v3")
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	// The fast-fail runs before PublishRollbackAuthorization, so no record is
	// ever created for the superseded authorization.
	if _, err := handler.emergencyControls.LatestRollbackAuthorization(t.Context(), defaultFollowerIdentity(), lookup, testNow); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(superseded at preview) err=%v, want ErrEmergencyNotFound (no record created)", err)
	}
}

func TestHandlerPublishRollbackAuthorizationReplayApplyFailureKeepsPersistedRecord(t *testing.T) {
	base := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-replay-fail-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := base.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-replay-fail-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := base.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-replay-fail", v2, v1, testNow)
	// Apply succeeds on the first request (head moves to the target and the
	// authorization is durably recorded) and errors on the replay.
	store := &applyRollbackFailOnReplayStore{FileBundleStore: base, err: errHandlerApplyRollbackFailed}
	handler := newTestHandlerWithOptions(t, store, nil, resolver)
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	first := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	first.Header.Set("X-Pipelock-Admin", "ok")
	fw := httptest.NewRecorder()
	handler.ServeHTTP(fw, first)
	if fw.Code != http.StatusCreated {
		t.Fatalf("rollback first publish status=%d body=%s, want 201", fw.Code, fw.Body.String())
	}

	// Replay the same authorization: PublishRollbackAuthorization reports
	// created=false, and the re-apply errors. Because the compensating clear is
	// gated on created, the replay must NOT clear the legitimately-persisted
	// record; the still-active rollback (head at target) keeps it servable.
	replay := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	replay.Header.Set("X-Pipelock-Admin", "ok")
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, replay)
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("rollback replay apply-fail status=%d body=%s, want 500", rw.Code, rw.Body.String())
	}
	lookup := RollbackLookup{
		CurrentBundleID: auth.CurrentBundleID,
		CurrentVersion:  auth.CurrentVersion,
		TargetBundleID:  auth.TargetBundleID,
		TargetVersion:   auth.TargetVersion,
	}
	if record, err := handler.emergencyControls.LatestRollbackAuthorization(t.Context(), defaultFollowerIdentity(), lookup, testNow); err != nil || record.Authorization.AuthorizationID != auth.AuthorizationID {
		t.Fatalf("LatestRollbackAuthorization(after replay apply failure) = %+v, %v; want persisted record %q (created=false must skip compensating clear)", record.Authorization, err, auth.AuthorizationID)
	}
	servedAuth := latestRollbackAuthorization(t, handler, auth)
	if servedAuth.Code != http.StatusOK {
		t.Fatalf("rollback auth after replay apply failure status=%d body=%s, want 200 (still active on head)", servedAuth.Code, servedAuth.Body.String())
	}
}

func TestHandlerPublishRollbackAuthorizationRecordFailureDoesNotMoveHead(t *testing.T) {
	base := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-handler-record-fail-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := base.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-handler-record-fail-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := base.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-handler-record-fail", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, base, nil, resolver)
	handler.emergencyControls = failingEmergencyStore{}
	body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
	if err != nil {
		t.Fatalf("Marshal(rollback): %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("rollback record-fail status=%d body=%s, want 500", w.Code, w.Body.String())
	}
	latest, err := base.Latest(t.Context(), defaultFollowerIdentity(), testNow)
	if err != nil {
		t.Fatalf("Latest(after record failure) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-handler-record-fail-v2" {
		t.Fatalf("Latest(after record failure) bundle_id = %q, want bundle-handler-record-fail-v2", latest.Bundle.BundleID)
	}
}

func TestHandlerPublishRollbackAuthorizationRejectsAudience(t *testing.T) {
	for _, tt := range []struct {
		name     string
		audience conductor.Audience
	}{
		{name: "instance_ids", audience: conductor.Audience{InstanceIDs: []string{"edge-01"}}},
		{name: "labels", audience: conductor.Audience{Labels: map[string]string{"tier": "prod"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := mustStore(t)
			signer := newTestSigner(t)
			v1 := signedControlBundle(t, signer, bundleSpec{
				id:       "bundle-handler-audience-v1-" + tt.name,
				version:  1,
				audience: conductor.Audience{InstanceIDs: []string{"*"}},
			})
			r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
			if err != nil {
				t.Fatalf("Publish(v1) error = %v", err)
			}
			v2 := signedControlBundle(t, signer, bundleSpec{
				id:           "bundle-handler-audience-v2-" + tt.name,
				version:      2,
				previousHash: r1.BundleHash,
				audience:     conductor.Audience{InstanceIDs: []string{"*"}},
				configYAML:   "mode: strict\napi_allowlist:\n  - audience2.example.com\n",
			})
			if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
				t.Fatalf("Publish(v2) error = %v", err)
			}
			auth := signedRollbackAuthorizationForBundles(t, "rollback-handler-audience-"+tt.name, v2, v1, testNow)
			auth.Audience = tt.audience
			signatures, resolver := signConductorPreimage(t, auth.SignablePreimage, signing.PurposePolicyBundleRollback, "rollback-signer-1", "rollback-signer-2")
			auth.Signatures = signatures
			if err := auth.Validate(); err != nil {
				t.Fatalf("Validate(legacy audience) error = %v, want nil", err)
			}
			handler := newTestHandlerWithOptions(t, store, nil, resolver)
			body, err := json.Marshal(publishRollbackAuthorizationRequest{Authorization: auth})
			if err != nil {
				t.Fatalf("Marshal(rollback): %v", err)
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RollbackAuthorizationsPath, strings.NewReader(string(body)))
			req.Header.Set("X-Pipelock-Admin", "ok")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "rollback audience must be empty") {
				t.Fatalf("rollback audience status=%d body=%s, want 422 audience error", w.Code, w.Body.String())
			}
		})
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

	publishRollbackTargetAndCurrent(t, handler, auth)
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
	publishRollbackTargetAndCurrent(t, failing, auth)
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

func latestPolicyBundle(t *testing.T, handler *Handler, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func latestRollbackAuthorization(t *testing.T, handler *Handler, auth conductor.RollbackAuthorization) *httptest.ResponseRecorder {
	t.Helper()
	target := fmt.Sprintf("%s?current_bundle_id=%s&current_version=%d&target_bundle_id=%s&target_version=%d",
		RollbackAuthorizationsPath,
		auth.CurrentBundleID,
		auth.CurrentVersion,
		auth.TargetBundleID,
		auth.TargetVersion,
	)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func assertLatestBundleID(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("latest status=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var got conductor.PolicyBundle
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode latest bundle: %v", err)
	}
	if got.BundleID != want {
		t.Fatalf("latest bundle_id=%q, want %q", got.BundleID, want)
	}
}

func signedRollbackAuthorizationForBundles(
	t *testing.T,
	id string,
	current conductor.PolicyBundle,
	target conductor.PolicyBundle,
	created time.Time,
) conductor.RollbackAuthorization {
	t.Helper()
	auth, _ := signedRollbackAuthorizationForBundlesWithResolver(t, id, current, target, created)
	return auth
}

func signedRollbackAuthorizationForBundlesWithResolver(
	t *testing.T,
	id string,
	current conductor.PolicyBundle,
	target conductor.PolicyBundle,
	created time.Time,
) (conductor.RollbackAuthorization, conductor.SignatureKeyResolver) {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: id,
		OrgID:           current.OrgID,
		FleetID:         current.FleetID,
		CurrentBundleID: current.BundleID,
		CurrentVersion:  current.Version,
		TargetBundleID:  target.BundleID,
		TargetVersion:   target.Version,
		Counter:         1,
		Reason:          "operator rollback",
		CreatedAt:       created,
		ExpiresAt:       created.Add(time.Hour),
	}
	var resolver conductor.SignatureKeyResolver
	auth.Signatures, resolver = signConductorPreimage(t, auth.SignablePreimage, signing.PurposePolicyBundleRollback, "rollback-signer-1", "rollback-signer-2")
	if err := auth.VerifySignaturesAt(created, resolver); err != nil {
		t.Fatalf("rollback authorization VerifySignaturesAt() error = %v", err)
	}
	if err := auth.Validate(); err != nil {
		t.Fatalf("rollback authorization Validate() error = %v", err)
	}
	return auth, resolver
}

func publishRollbackTargetAndCurrent(t *testing.T, handler *Handler, auth conductor.RollbackAuthorization) {
	t.Helper()
	signer := newTestSigner(t)
	target := signedControlBundle(t, signer, bundleSpec{
		id:       auth.TargetBundleID,
		version:  auth.TargetVersion,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	targetRecord, _, err := handler.store.Publish(t.Context(), target, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(rollback target) error = %v", err)
	}
	current := signedControlBundle(t, signer, bundleSpec{
		id:           auth.CurrentBundleID,
		version:      auth.CurrentVersion,
		previousHash: targetRecord.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - rollback-current.example.com\n",
	})
	if _, _, err := handler.store.Publish(t.Context(), current, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(rollback current) error = %v", err)
	}
}

var errHandlerApplyRollbackFailed = errors.New("forced rollback head apply failure")

type applyRollbackFailureStore struct {
	BundleStore
	err error
}

func (s applyRollbackFailureStore) ApplyRollbackHead(context.Context, conductor.RollbackAuthorization, time.Time) error {
	return s.err
}

func (s applyRollbackFailureStore) PreviewRollbackHead(ctx context.Context, auth conductor.RollbackAuthorization) (RollbackHeadPreview, error) {
	previewer, ok := s.BundleStore.(rollbackHeadPreviewer)
	if !ok {
		return RollbackHeadPreview{}, ErrRollbackHeadPreviewUnsupported
	}
	return previewer.PreviewRollbackHead(ctx, auth)
}

// applyRollbackSpyStore counts ApplyRollbackHead invocations while otherwise
// delegating to the real store, so a test can assert apply was never reached.
type applyRollbackSpyStore struct {
	*FileBundleStore
	mu    sync.Mutex
	calls int
}

func (s *applyRollbackSpyStore) ApplyRollbackHead(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.FileBundleStore.ApplyRollbackHead(ctx, auth, now)
}

func (s *applyRollbackSpyStore) applyCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// applyRollbackFailOnReplayStore applies the rollback normally on the first
// ApplyRollbackHead call and errors on every subsequent call, modeling a replay
// whose re-apply fails after the authorization was already durably recorded.
type applyRollbackFailOnReplayStore struct {
	*FileBundleStore
	err   error
	mu    sync.Mutex
	calls int
}

func (s *applyRollbackFailOnReplayStore) ApplyRollbackHead(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) error {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	if n > 1 {
		return s.err
	}
	return s.FileBundleStore.ApplyRollbackHead(ctx, auth, now)
}

type publishBeforeRollbackApplyStore struct {
	*FileBundleStore
	bundle conductor.PolicyBundle
	once   sync.Once
}

func (s *publishBeforeRollbackApplyStore) ApplyRollbackHead(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) error {
	var publishErr error
	s.once.Do(func() {
		_, _, publishErr = s.Publish(ctx, s.bundle, PublishOptions{Now: now.Add(time.Second)})
	})
	if publishErr != nil {
		return publishErr
	}
	return s.FileBundleStore.ApplyRollbackHead(ctx, auth, now)
}

type publishAfterRollbackApplyStore struct {
	*FileBundleStore
	bundle conductor.PolicyBundle
	once   sync.Once
}

func (s *publishAfterRollbackApplyStore) ApplyRollbackHead(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) error {
	if err := s.FileBundleStore.ApplyRollbackHead(ctx, auth, now); err != nil {
		return err
	}
	var publishErr error
	s.once.Do(func() {
		_, _, publishErr = s.Publish(ctx, s.bundle, PublishOptions{Now: now.Add(time.Second)})
	})
	return publishErr
}

type rollbackClearFailureEmergencyStore struct {
	*FileEmergencyStore
	err error
}

func (s rollbackClearFailureEmergencyStore) ClearRollbackAuthorization(context.Context, string) (bool, error) {
	return false, s.err
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
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
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
		AuditSink:   discardAuditSink{},
		AuditKeys:   rejectingAuditKeyResolver,
		Enrollments: enrollments,
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

func (failingEmergencyStore) ActiveRollbackForFollower(context.Context, FollowerIdentity, time.Time) (StoredRollbackAuthorization, bool, error) {
	return StoredRollbackAuthorization{}, false, errors.New("emergency store failed")
}
