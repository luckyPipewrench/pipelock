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
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestHandlerEnrollmentTokenIssuesEnrollsAndAuthenticatesAuditKey(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{}
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeAdmin: func(r *http.Request) error {
			if r.Header.Get("Authorization") != "Bearer admin-token" {
				return ErrPublisherForbidden
			}
			return nil
		},
		AuditSink:   sink,
		AuditKeys:   CompositeAuditKeyResolver(enrollments, nil),
		Enrollments: enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	createBody := createEnrollmentTokenRequest{
		TokenID:     "enroll-token-1",
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
		ExpiresAt:   testNow.Add(time.Hour),
	}
	body, err := json.Marshal(createBody)
	if err != nil {
		t.Fatalf("Marshal(create) error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create enrollment token status = %d body=%s, want 201", w.Code, w.Body.String())
	}
	var issued createEnrollmentTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode issued token: %v", err)
	}
	if issued.TokenID != "enroll-token-1" || !strings.HasPrefix(issued.Token, enrollmentTokenPrefix) {
		t.Fatalf("issued token = %+v", issued)
	}

	enrollBody, err := json.Marshal(enrollRequest{
		Token:          issued.Token,
		AuditKeyID:     "audit-key-1",
		AuditPublicKey: signing.EncodePublicKey(pub),
	})
	if err != nil {
		t.Fatalf("Marshal(enroll) error = %v", err)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollPath, bytes.NewReader(enrollBody)))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d body=%s, want 201", w.Code, w.Body.String())
	}
	var enrolled enrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &enrolled); err != nil {
		t.Fatalf("decode enrolled: %v", err)
	}
	if enrolled.OrgID != "org-main" || enrolled.FleetID != "prod" || enrolled.InstanceID != "pl-prod-1" || enrolled.AuditKeyID != "audit-key-1" {
		t.Fatalf("enrolled = %+v", enrolled)
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollPath, bytes.NewReader(enrollBody)))
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "consumed") {
		t.Fatalf("reused token status = %d body=%s, want generic 401", w.Code, w.Body.String())
	}

	payload := []byte(`{"entry":"from-enrolled-key"}`)
	w = postAuditBatch(t, handler, signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow))
	if w.Code != http.StatusAccepted {
		t.Fatalf("audit ingest with enrolled key status = %d body=%s, want 202", w.Code, w.Body.String())
	}
	if len(sink.batches) != 1 || string(sink.batches[0].Payload) != string(payload) {
		t.Fatalf("sink batches = %+v", sink.batches)
	}
}

func TestFileEnrollmentStoreRejectsDuplicateActiveInstance(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	first, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-1",
		Identity: defaultFollowerIdentity(),
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken(first) error = %v", err)
	}
	second, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-2",
		Identity: defaultFollowerIdentity(),
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken(second) error = %v", err)
	}
	pub, _ := testAuditSigner(t)
	consume := ConsumeEnrollmentTokenRequest{
		AuditKeyID: "audit-key-1",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}
	consume.Token = first.Token
	if _, err := store.ConsumeEnrollmentToken(context.Background(), consume); err != nil {
		t.Fatalf("ConsumeEnrollmentToken(first) error = %v", err)
	}
	consume.Token = second.Token
	if _, err := store.ConsumeEnrollmentToken(context.Background(), consume); !errors.Is(err, ErrEnrollmentActiveInstance) {
		t.Fatalf("ConsumeEnrollmentToken(second) error = %v, want ErrEnrollmentActiveInstance", err)
	}
}

func TestFileEnrollmentStoreSeparatesEnvironments(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	prod := defaultFollowerIdentity()
	dev := prod
	dev.Environment = "dev"
	first, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-prod",
		Identity: prod,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken(prod) error = %v", err)
	}
	second, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-dev",
		Identity: dev,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken(dev) error = %v", err)
	}
	pub, _ := testAuditSigner(t)
	consume := ConsumeEnrollmentTokenRequest{
		AuditKeyID: "audit-key-1",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}
	consume.Token = first.Token
	if _, err := store.ConsumeEnrollmentToken(context.Background(), consume); err != nil {
		t.Fatalf("ConsumeEnrollmentToken(prod) error = %v", err)
	}
	consume.Token = second.Token
	if _, err := store.ConsumeEnrollmentToken(context.Background(), consume); err != nil {
		t.Fatalf("ConsumeEnrollmentToken(dev) error = %v", err)
	}
	if _, err := store.ResolveEnrolledAuditKey(dev, "audit-key-1"); err != nil {
		t.Fatalf("ResolveEnrolledAuditKey(dev) error = %v", err)
	}
}

func TestFileEnrollmentStoreValidatesInputsAndPersists(t *testing.T) {
	if _, err := OpenFileEnrollmentStore(""); err == nil {
		t.Fatal("OpenFileEnrollmentStore(empty) error = nil, want error")
	}
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	if _, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "-bad",
		Identity: defaultFollowerIdentity(),
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	}); !errors.Is(err, conductor.ErrInvalidIdentifier) {
		t.Fatalf("CreateEnrollmentToken(invalid id) error = %v, want ErrInvalidIdentifier", err)
	}
	if _, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-expired",
		Identity: defaultFollowerIdentity(),
		Expires:  testNow,
		Now:      testNow,
	}); !errors.Is(err, conductor.ErrInvalidValidityWindow) {
		t.Fatalf("CreateEnrollmentToken(expired) error = %v, want ErrInvalidValidityWindow", err)
	}
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-1",
		Identity: defaultFollowerIdentity(),
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken(valid) error = %v", err)
	}
	if _, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-1",
		Identity: defaultFollowerIdentity(),
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	}); !errors.Is(err, ErrEnrollmentTokenConflict) {
		t.Fatalf("CreateEnrollmentToken(duplicate) error = %v, want ErrEnrollmentTokenConflict", err)
	}
	pub, _ := testAuditSigner(t)
	if _, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{}); !errors.Is(err, ErrEnrollmentTokenInvalid) {
		t.Fatalf("ConsumeEnrollmentToken(empty) error = %v, want ErrEnrollmentTokenInvalid", err)
	}
	if _, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "-bad",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}); !errors.Is(err, conductor.ErrInvalidIdentifier) {
		t.Fatalf("ConsumeEnrollmentToken(invalid key id) error = %v, want ErrInvalidIdentifier", err)
	}
	if _, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-1",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposePolicyBundleSigning,
		},
		Now: testNow,
	}); !errors.Is(err, ErrAuditKeyRequired) {
		t.Fatalf("ConsumeEnrollmentToken(wrong purpose) error = %v, want ErrAuditKeyRequired", err)
	}
	enrolled, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-1",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	})
	if err != nil {
		t.Fatalf("ConsumeEnrollmentToken(valid) error = %v", err)
	}
	if enrolled.Identity.InstanceID != defaultFollowerIdentity().InstanceID {
		t.Fatalf("enrolled identity = %+v", enrolled.Identity)
	}
	reopened, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore(reopen) error = %v", err)
	}
	if _, err := reopened.ResolveEnrolledAuditKey(defaultFollowerIdentity(), "audit-key-1"); err != nil {
		t.Fatalf("ResolveEnrolledAuditKey(reopened) error = %v", err)
	}
	if _, err := reopened.ResolveEnrolledAuditKey(FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "other"}, "audit-key-1"); !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("ResolveEnrolledAuditKey(wrong identity) error = %v, want ErrSignatureVerification", err)
	}
}

func TestFileEnrollmentStoreRejectsExpiredToken(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "token-1",
		Identity: defaultFollowerIdentity(),
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken() error = %v", err)
	}
	pub, _ := testAuditSigner(t)
	_, err = store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-1",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow.Add(time.Hour),
	})
	if !errors.Is(err, ErrEnrollmentTokenExpired) {
		t.Fatalf("ConsumeEnrollmentToken(expired) error = %v, want ErrEnrollmentTokenExpired", err)
	}
}

func TestCompositeAuditKeyResolverFallsBack(t *testing.T) {
	pub, _ := testAuditSigner(t)
	fallback := auditKeyResolverFor(pub)
	resolver := CompositeAuditKeyResolver(nil, fallback)
	if _, err := resolver(defaultFollowerIdentity(), "audit-key-1"); err != nil {
		t.Fatalf("resolver(fallback) error = %v", err)
	}
	resolver = CompositeAuditKeyResolver(nil, nil)
	if _, err := resolver(defaultFollowerIdentity(), "audit-key-1"); !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("resolver(no sources) error = %v, want ErrSignatureVerification", err)
	}
}

func TestHandlerEnrollmentEndpointErrors(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	handler := newEnrollmentTestHandler(t, store)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"token wrong method", http.MethodGet, EnrollmentTokensPath, http.StatusMethodNotAllowed},
		{"enroll wrong method", http.MethodGet, EnrollPath, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tc.want)
			}
		})
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, strings.NewReader(`{}`)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("create without admin status = %d body=%s, want 403", w.Code, w.Body.String())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, strings.NewReader(`{"token_id":"bad","expires_at":"not-time"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("create invalid JSON status = %d body=%s, want 400", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, strings.NewReader(`{"token_id":"token-1","org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-1","environment":"prod","expires_at":"`+testNow.Format(time.RFC3339Nano)+`"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("create expired status = %d body=%s, want 400", w.Code, w.Body.String())
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollPath, strings.NewReader(`{"token":"missing","audit_key_id":"audit-key-1","audit_public_key":"not-a-key"}`))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("enroll invalid key status = %d body=%s, want 400", w.Code, w.Body.String())
	}
	body, err := json.Marshal(enrollRequest{
		Token:          "missing",
		AuditKeyID:     "audit-key-1",
		AuditPublicKey: signing.EncodePublicKey(mustAuditPublicKey(t)),
	})
	if err != nil {
		t.Fatalf("Marshal(enroll missing token) error = %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollPath, bytes.NewReader(body))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("enroll missing token status = %d body=%s, want 401", w.Code, w.Body.String())
	}

	noStore := newEnrollmentTestHandler(t, nil)
	w = httptest.NewRecorder()
	noStore.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("create without store status = %d body=%s, want 501", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	noStore.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollPath, nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("enroll without store status = %d body=%s, want 501", w.Code, w.Body.String())
	}
}

func newEnrollmentTestHandler(t *testing.T, enrollments EnrollmentStore) *Handler {
	t.Helper()
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeAdmin: func(r *http.Request) error {
			if r.Header.Get("Authorization") == "Bearer admin-token" {
				return nil
			}
			return ErrPublisherForbidden
		},
		AuditSink:   discardAuditSink{},
		AuditKeys:   rejectingAuditKeyResolver,
		Enrollments: enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func mustAuditPublicKey(t *testing.T) []byte {
	t.Helper()
	pub, _ := testAuditSigner(t)
	return pub
}
