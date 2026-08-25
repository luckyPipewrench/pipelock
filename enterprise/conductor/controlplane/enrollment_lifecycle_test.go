//go:build enterprise

// Copyright 2026 Pipelock contributors
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

// newLifecycleTestHandler builds a handler wired to a fresh file enrollment
// store with an admin authorizer that accepts only "Bearer admin-token" and the
// supplied maximum enrollment-token TTL (0 = package default).
func newLifecycleTestHandler(t *testing.T, maxTTL time.Duration) (*Handler, *FileEnrollmentStore) {
	t.Helper()
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
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
		AuditSink:             &captureAuditSink{},
		AuditKeys:             CompositeAuditKeyResolver(enrollments, nil),
		Enrollments:           enrollments,
		EnrollmentTokenMaxTTL: maxTTL,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler, enrollments
}

func mintToken(t *testing.T, handler *Handler, tokenID string, expiresAt time.Time) createEnrollmentTokenResponse {
	t.Helper()
	body, err := json.Marshal(createEnrollmentTokenRequest{
		TokenID:     tokenID,
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		t.Fatalf("Marshal(create) error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint token status = %d body=%s, want 201", w.Code, w.Body.String())
	}
	var issued createEnrollmentTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode minted token: %v", err)
	}
	return issued
}

func TestHandlerEnrollmentTokenRejectsOverMaxTTL(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, time.Hour)
	body, err := json.Marshal(createEnrollmentTokenRequest{
		TokenID:     "too-long",
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
		ExpiresAt:   testNow.Add(2 * time.Hour), // exceeds the 1h max
	})
	if err != nil {
		t.Fatalf("Marshal(create) error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollmentTokensPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-max TTL status = %d body=%s, want 400", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "exceeds max") {
		t.Fatalf("over-max TTL body = %s, want mention of max", w.Body.String())
	}

	// A token exactly at the ceiling is accepted.
	atCeiling := mintToken(t, handler, "at-ceiling", testNow.Add(time.Hour))
	if atCeiling.TokenID != "at-ceiling" {
		t.Fatalf("at-ceiling token = %+v", atCeiling)
	}
}

func TestHandlerEnrollmentTokenListAndStatusNeverLeakSecret(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, 0)
	minted := mintToken(t, handler, "list-token-1", testNow.Add(time.Hour))

	// List.
	listReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, EnrollmentTokensPath, nil)
	listReq.Header.Set("Authorization", "Bearer admin-token")
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s, want 200", listW.Code, listW.Body.String())
	}
	listBody := listW.Body.String()
	if strings.Contains(listBody, minted.Token) {
		t.Fatalf("list response leaked the token secret: %s", listBody)
	}
	// The token_hash JSON key must never appear either.
	if strings.Contains(listBody, "token_hash") || strings.Contains(listBody, `"token"`) {
		t.Fatalf("list response contains secret-bearing field: %s", listBody)
	}
	var listResp listEnrollmentTokensResponse
	if err := json.Unmarshal(listW.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listResp.Count != 1 || listResp.Tokens[0].TokenID != "list-token-1" || listResp.Tokens[0].State != EnrollmentTokenStatePending {
		t.Fatalf("list resp = %+v", listResp)
	}

	// Status (single token via ?token_id=).
	statusReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, EnrollmentTokensPath+"?token_id=list-token-1", nil)
	statusReq.Header.Set("Authorization", "Bearer admin-token")
	statusW := httptest.NewRecorder()
	handler.ServeHTTP(statusW, statusReq)
	if statusW.Code != http.StatusOK {
		t.Fatalf("status status = %d body=%s, want 200", statusW.Code, statusW.Body.String())
	}
	if strings.Contains(statusW.Body.String(), minted.Token) ||
		strings.Contains(statusW.Body.String(), "token_hash") ||
		strings.Contains(statusW.Body.String(), `"token"`) {
		t.Fatalf("status response leaked secret: %s", statusW.Body.String())
	}
}

func TestHandlerEnrollmentTokenListRequiresAdmin(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, 0)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req := httptest.NewRequestWithContext(context.Background(), method, EnrollmentTokensPath, strings.NewReader(`{"token_id":"x"}`))
		req.Header.Set("Authorization", "Bearer not-the-admin-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s without admin token status = %d, want 403", method, w.Code)
		}
	}
}

func TestHandlerEnrollmentTokenRevokeInvalidatesPendingToken(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, 0)
	pub, _ := testAuditSigner(t)
	minted := mintToken(t, handler, "revoke-me", testNow.Add(time.Hour))

	// Revoke the pending token.
	revokeBody, err := json.Marshal(revokeEnrollmentTokenRequest{TokenID: "revoke-me"})
	if err != nil {
		t.Fatalf("Marshal(revoke) error = %v", err)
	}
	revokeReq := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, EnrollmentTokensPath, bytes.NewReader(revokeBody))
	revokeReq.Header.Set("Authorization", "Bearer admin-token")
	revokeW := httptest.NewRecorder()
	handler.ServeHTTP(revokeW, revokeReq)
	if revokeW.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s, want 200", revokeW.Code, revokeW.Body.String())
	}
	var summary EnrollmentTokenSummary
	if err := json.Unmarshal(revokeW.Body.Bytes(), &summary); err != nil {
		t.Fatalf("decode revoke summary: %v", err)
	}
	if summary.State != EnrollmentTokenStateRevoked || summary.RevokedAt == nil {
		t.Fatalf("revoke summary = %+v, want revoked with RevokedAt set", summary)
	}

	// Consuming the revoked token MUST fail closed.
	enrollBody, err := json.Marshal(enrollRequest{
		Token:          minted.Token,
		AuditKeyID:     "audit-key-1",
		AuditPublicKey: signing.EncodePublicKey(pub),
	})
	if err != nil {
		t.Fatalf("Marshal(enroll) error = %v", err)
	}
	enrollW := httptest.NewRecorder()
	handler.ServeHTTP(enrollW, httptest.NewRequestWithContext(context.Background(), http.MethodPost, EnrollPath, bytes.NewReader(enrollBody)))
	if enrollW.Code != http.StatusUnauthorized {
		t.Fatalf("consume-after-revoke status = %d body=%s, want 401", enrollW.Code, enrollW.Body.String())
	}

	// Re-revoking a revoked token is rejected (not pending -> 409).
	reRevokeReq := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, EnrollmentTokensPath, bytes.NewReader(revokeBody))
	reRevokeReq.Header.Set("Authorization", "Bearer admin-token")
	reRevokeW := httptest.NewRecorder()
	handler.ServeHTTP(reRevokeW, reRevokeReq)
	if reRevokeW.Code != http.StatusConflict {
		t.Fatalf("re-revoke status = %d body=%s, want 409", reRevokeW.Code, reRevokeW.Body.String())
	}

	// Revoking an unknown token is 404.
	unknownBody, _ := json.Marshal(revokeEnrollmentTokenRequest{TokenID: "no-such-token"})
	unknownReq := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, EnrollmentTokensPath, bytes.NewReader(unknownBody))
	unknownReq.Header.Set("Authorization", "Bearer admin-token")
	unknownW := httptest.NewRecorder()
	handler.ServeHTTP(unknownW, unknownReq)
	if unknownW.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown status = %d body=%s, want 404", unknownW.Code, unknownW.Body.String())
	}
}

func TestEnrollmentTokenRecordStateDerivation(t *testing.T) {
	consumed := testNow
	revoked := testNow
	cases := []struct {
		name string
		rec  enrollmentTokenRecord
		now  time.Time
		want EnrollmentTokenState
	}{
		{"pending", enrollmentTokenRecord{ExpiresAt: testNow.Add(time.Hour)}, testNow, EnrollmentTokenStatePending},
		{"expired", enrollmentTokenRecord{ExpiresAt: testNow.Add(time.Hour)}, testNow.Add(2 * time.Hour), EnrollmentTokenStateExpired},
		{"consumed-wins-past-expiry", enrollmentTokenRecord{ExpiresAt: testNow.Add(time.Hour), ConsumedAt: &consumed}, testNow.Add(2 * time.Hour), EnrollmentTokenStateConsumed},
		{"revoked-wins-over-expiry", enrollmentTokenRecord{ExpiresAt: testNow.Add(time.Hour), RevokedAt: &revoked}, testNow.Add(2 * time.Hour), EnrollmentTokenStateRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.tokenState(tc.now); got != tc.want {
				t.Fatalf("tokenState() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHandlerEnrollmentTokenListAppliesFiltersAndLimit(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, 0)
	mintToken(t, handler, "tok-a", testNow.Add(time.Hour))
	mintToken(t, handler, "tok-b", testNow.Add(time.Hour))

	// limit=1 bounds the result; the fleet_id filter matches both minted tokens.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, EnrollmentTokensPath+"?fleet_id=prod&limit=1", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("filtered list status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp listEnrollmentTokensResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode filtered list: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("limit=1 returned count=%d, want 1", resp.Count)
	}

	// A non-matching filter yields an empty set, not an error.
	missReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, EnrollmentTokensPath+"?fleet_id=nope", nil)
	missReq.Header.Set("Authorization", "Bearer admin-token")
	missW := httptest.NewRecorder()
	handler.ServeHTTP(missW, missReq)
	if missW.Code != http.StatusOK {
		t.Fatalf("non-matching filter status = %d, want 200", missW.Code)
	}
	var missResp listEnrollmentTokensResponse
	if err := json.Unmarshal(missW.Body.Bytes(), &missResp); err != nil {
		t.Fatalf("decode non-matching filter response: %v", err)
	}
	if missResp.Count != 0 || len(missResp.Tokens) != 0 {
		t.Fatalf("non-matching filter resp = %+v, want empty result set", missResp)
	}
}

func TestHandlerEnrollmentTokenListRejectsBadQueryParams(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, 0)
	for _, q := range []string{"?limit=0", "?limit=999999", "?limit=abc", "?org_id=bad%20id"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, EnrollmentTokensPath+q, nil)
		req.Header.Set("Authorization", "Bearer admin-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("query %q status = %d body=%s, want 400", q, w.Code, w.Body.String())
		}
	}
}

func TestHandlerEnrollmentTokenMethodNotAllowed(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, 0)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, EnrollmentTokensPath, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT status = %d, want 405", w.Code)
	}
}

func TestHandlerEnrollmentTokenRevokeRejectsBadBody(t *testing.T) {
	handler, _ := newLifecycleTestHandler(t, 0)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, EnrollmentTokensPath, strings.NewReader("not-json"))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("revoke bad body status = %d body=%s, want 400", w.Code, w.Body.String())
	}
}

func TestFileEnrollmentStoreRevokeIsDurableAndConsumedNotRevokable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}
	if _, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "durable-token",
		Identity: identity,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	}); err != nil {
		t.Fatalf("CreateEnrollmentToken() error = %v", err)
	}
	if _, err := store.RevokeEnrollmentToken(context.Background(), RevokeEnrollmentTokenRequest{TokenID: "durable-token", Now: testNow}); err != nil {
		t.Fatalf("RevokeEnrollmentToken() error = %v", err)
	}

	// Reopen the store from disk and confirm the revocation survived restart.
	reopened, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("reopen OpenFileEnrollmentStore() error = %v", err)
	}
	tokens, err := reopened.ListEnrollmentTokens(context.Background(), EnrollmentTokenListQuery{TokenID: "durable-token"})
	if err != nil {
		t.Fatalf("ListEnrollmentTokens() error = %v", err)
	}
	if len(tokens) != 1 || tokens[0].State != EnrollmentTokenStateRevoked {
		t.Fatalf("after reopen tokens = %+v, want one revoked token", tokens)
	}

	// A second store cannot re-revoke a revoked token.
	if _, err := reopened.RevokeEnrollmentToken(context.Background(), RevokeEnrollmentTokenRequest{TokenID: "durable-token", Now: testNow}); !errors.Is(err, ErrEnrollmentTokenNotPending) {
		t.Fatalf("re-revoke after restart error = %v, want ErrEnrollmentTokenNotPending", err)
	}
}

func TestRevokeEnrollmentTokenKeepsRevocationAfterPostRenameSyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	tokenID := strings.Join([]string{"post", "rename", "revoke"}, "-")
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  tokenID,
		Identity: identity,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken() error = %v", err)
	}

	originalSyncDirectory := syncDirectory
	syncDirectory = func(string) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() { syncDirectory = originalSyncDirectory })
	if _, err := store.RevokeEnrollmentToken(context.Background(), RevokeEnrollmentTokenRequest{TokenID: tokenID, Now: testNow}); !errors.Is(err, errDurableWritePostRename) {
		t.Fatalf("RevokeEnrollmentToken(post-rename sync failure) error = %v, want errDurableWritePostRename", err)
	}
	syncDirectory = originalSyncDirectory

	pub, _ := testAuditSigner(t)
	if _, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-post-rename-revoke",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}); !errors.Is(err, ErrEnrollmentTokenInvalid) {
		t.Fatalf("ConsumeEnrollmentToken(revoked token) error = %v, want ErrEnrollmentTokenInvalid", err)
	}

	reloaded, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore(reload) error = %v", err)
	}
	tokens, err := reloaded.ListEnrollmentTokens(context.Background(), EnrollmentTokenListQuery{TokenID: tokenID})
	if err != nil {
		t.Fatalf("ListEnrollmentTokens() error = %v", err)
	}
	if len(tokens) != 1 || tokens[0].State != EnrollmentTokenStateRevoked {
		t.Fatalf("tokens after reload = %+v, want one revoked token", tokens)
	}
}

func TestCreateEnrollmentTokenRollsBackBeforeRenameFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	tokenID := strings.Join([]string{"pre", "rename", "create"}, "-")
	store.path = filepath.Dir(path)
	if _, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  tokenID,
		Identity: identity,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	}); err == nil {
		t.Fatal("CreateEnrollmentToken() error = nil, want pre-rename write error")
	}
	store.path = path
	tokens, err := store.ListEnrollmentTokens(context.Background(), EnrollmentTokenListQuery{TokenID: tokenID, Now: testNow})
	if err != nil {
		t.Fatalf("ListEnrollmentTokens() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("tokens after pre-rename failure = %+v, want none", tokens)
	}
}

func TestCreateEnrollmentTokenKeepsPendingStateAfterPostRenameSyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	tokenID := strings.Join([]string{"post", "rename", "create"}, "-")
	originalSyncDirectory := syncDirectory
	syncDirectory = func(string) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() { syncDirectory = originalSyncDirectory })
	if _, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  tokenID,
		Identity: identity,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	}); !errors.Is(err, errDurableWritePostRename) {
		t.Fatalf("CreateEnrollmentToken(post-rename sync failure) error = %v, want errDurableWritePostRename", err)
	}
	syncDirectory = originalSyncDirectory
	tokens, err := store.ListEnrollmentTokens(context.Background(), EnrollmentTokenListQuery{TokenID: tokenID, Now: testNow})
	if err != nil {
		t.Fatalf("ListEnrollmentTokens() error = %v", err)
	}
	if len(tokens) != 1 || tokens[0].State != EnrollmentTokenStatePending {
		t.Fatalf("tokens after post-rename failure = %+v, want one pending token", tokens)
	}

	// The rename succeeded and only the directory sync failed, so the token is
	// already on disk. Asserting against the same in-memory store cannot show
	// that; reopening the file is what proves the retained state is durable.
	reopened, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore(reopen) error = %v", err)
	}
	persisted, err := reopened.ListEnrollmentTokens(context.Background(), EnrollmentTokenListQuery{TokenID: tokenID, Now: testNow})
	if err != nil {
		t.Fatalf("ListEnrollmentTokens(reopened) error = %v", err)
	}
	if len(persisted) != 1 || persisted[0].State != EnrollmentTokenStatePending {
		t.Fatalf("tokens from reopened store = %+v, want one pending token", persisted)
	}
}

func TestConsumeEnrollmentTokenRollsBackBeforeRenameFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	tokenID := strings.Join([]string{"pre", "rename", "consume"}, "-")
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{TokenID: tokenID, Identity: identity, Expires: testNow.Add(time.Hour), Now: testNow})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken() error = %v", err)
	}
	pub, _ := testAuditSigner(t)
	request := ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-pre-rename-consume",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}
	store.path = filepath.Dir(path)
	if _, err := store.ConsumeEnrollmentToken(context.Background(), request); err == nil {
		t.Fatal("ConsumeEnrollmentToken() error = nil, want pre-rename write error")
	}
	store.path = path
	if _, err := store.ConsumeEnrollmentToken(context.Background(), request); err != nil {
		t.Fatalf("ConsumeEnrollmentToken() after rollback error = %v, want success", err)
	}
}

func TestConsumeEnrollmentTokenKeepsConsumedStateAfterPostRenameSyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	tokenID := strings.Join([]string{"post", "rename", "consume"}, "-")
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{TokenID: tokenID, Identity: identity, Expires: testNow.Add(time.Hour), Now: testNow})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken() error = %v", err)
	}
	pub, _ := testAuditSigner(t)
	request := ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-post-rename-consume",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}
	originalSyncDirectory := syncDirectory
	syncDirectory = func(string) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() { syncDirectory = originalSyncDirectory })
	if _, err := store.ConsumeEnrollmentToken(context.Background(), request); !errors.Is(err, errDurableWritePostRename) {
		t.Fatalf("ConsumeEnrollmentToken(post-rename sync failure) error = %v, want errDurableWritePostRename", err)
	}
	syncDirectory = originalSyncDirectory
	if _, err := store.ConsumeEnrollmentToken(context.Background(), request); !errors.Is(err, ErrEnrollmentTokenConsumed) {
		t.Fatalf("ConsumeEnrollmentToken(retry) error = %v, want ErrEnrollmentTokenConsumed", err)
	}
	if _, err := store.ResolveEnrolledAuditKey(identity, request.AuditKeyID); err != nil {
		t.Fatalf("ResolveEnrolledAuditKey() error = %v, want enrolled key", err)
	}

	// Same reason as the create case: prove the consumed state and the enrolled
	// key survived to disk rather than only to the in-memory map.
	reopened, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore(reopen) error = %v", err)
	}
	if _, err := reopened.ConsumeEnrollmentToken(context.Background(), request); !errors.Is(err, ErrEnrollmentTokenConsumed) {
		t.Fatalf("ConsumeEnrollmentToken(reopened) error = %v, want ErrEnrollmentTokenConsumed", err)
	}
	if _, err := reopened.ResolveEnrolledAuditKey(identity, request.AuditKeyID); err != nil {
		t.Fatalf("ResolveEnrolledAuditKey(reopened) error = %v, want enrolled key", err)
	}
}

func TestRevokeEnrollmentTokenRollsBackBeforeRenameFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	tokenID := strings.Join([]string{"pre", "rename", "revoke"}, "-")
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{TokenID: tokenID, Identity: identity, Expires: testNow.Add(time.Hour), Now: testNow})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken() error = %v", err)
	}
	store.path = filepath.Dir(path)
	if _, err := store.RevokeEnrollmentToken(context.Background(), RevokeEnrollmentTokenRequest{TokenID: tokenID, Now: testNow}); err == nil {
		t.Fatal("RevokeEnrollmentToken() error = nil, want pre-rename write error")
	}
	store.path = path
	pub, _ := testAuditSigner(t)
	if _, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-pre-rename-revoke",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}); err != nil {
		t.Fatalf("ConsumeEnrollmentToken() after rollback error = %v, want success", err)
	}
}
