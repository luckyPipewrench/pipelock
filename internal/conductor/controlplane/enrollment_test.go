// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/luckyPipewrench/pipelock/internal/conductor"
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
