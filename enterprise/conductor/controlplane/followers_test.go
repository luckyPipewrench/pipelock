//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	followerAdminToken      = "admin-token"
	followerAuditorToken    = "auditor-token"
	followerOrgMainAuditTok = "org-main-auditor-token"
	followerOrgEmptyAdmin   = "org-empty-admin-token"
)

// mustEnrollFollower creates and immediately consumes an enrollment token,
// leaving an active enrolled follower in the store. It is the direct-store
// shortcut for the HTTP create-token + enroll round trip.
func mustEnrollFollower(t *testing.T, store *FileEnrollmentStore, tokenID string, identity FollowerIdentity, auditKeyID string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  tokenID,
		Identity: identity,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken(%s) error = %v", tokenID, err)
	}
	if _, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: auditKeyID,
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}); err != nil {
		t.Fatalf("ConsumeEnrollmentToken(%s) error = %v", tokenID, err)
	}
}

func newFollowersTestHandler(t *testing.T, enrollments EnrollmentStore) *Handler {
	t.Helper()
	followerAuth, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{
		{Token: followerAdminToken, Role: RoleAdmin, OrgID: "org-main"},
		{Token: followerAuditorToken, Role: RoleAuditor, OrgID: "org-main"},
		{Token: followerOrgMainAuditTok, Role: RoleAuditor, OrgID: "org-main"},
		{Token: followerOrgEmptyAdmin, Role: RoleAdmin, OrgID: "org-empty"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerFollowerListAuthorizer() error = %v", err)
	}
	adminAuth, err := ScopedBearerAdminAuthorizer([]ScopedBearerCredential{
		{Token: followerAdminToken, Role: RoleAdmin, OrgID: "org-main"},
		{Token: followerOrgEmptyAdmin, Role: RoleAdmin, OrgID: "org-empty"},
		{Token: followerAuditorToken, Role: RoleAuditor, OrgID: "org-main"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerAdminAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              mustStore(t),
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeFollowers: followerAuth,
		AuthorizeAdmin:     adminAuth,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func getFollowers(t *testing.T, handler *Handler, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func deleteFollower(t *testing.T, handler *Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, FollowersPath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestHandlerListFollowersReturnsScopedRoster(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	mustEnrollFollower(t, enrollments, "tok-main-1", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}, "audit-key-main-1")
	mustEnrollFollower(t, enrollments, "tok-main-2", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-2", Environment: "prod"}, "audit-key-main-2")
	mustEnrollFollower(t, enrollments, "tok-other-1", FollowerIdentity{OrgID: "org-other", FleetID: "prod", InstanceID: "pl-other-1", Environment: "prod"}, "audit-key-other-1")

	handler := newFollowersTestHandler(t, enrollments)

	w := getFollowers(t, handler, FollowersPath+"?org_id=org-main", followerAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp listFollowersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Count != 2 || len(resp.Followers) != 2 {
		t.Fatalf("count = %d followers = %+v, want 2 org-main followers", resp.Count, resp.Followers)
	}
	for _, f := range resp.Followers {
		if f.OrgID != "org-main" {
			t.Fatalf("leaked follower from org %q: %+v", f.OrgID, f)
		}
		if !f.Active {
			t.Fatalf("expected active follower, got %+v", f)
		}
	}
	// Deterministic ordering: instance ids sorted.
	if resp.Followers[0].InstanceID != "pl-prod-1" || resp.Followers[1].InstanceID != "pl-prod-2" {
		t.Fatalf("non-deterministic order: %+v", resp.Followers)
	}
}

func TestHandlerListFollowersRequiresAuthorization(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	mustEnrollFollower(t, enrollments, "tok-main-1", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}, "audit-key-main-1")
	handler := newFollowersTestHandler(t, enrollments)

	cases := []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"unknown token", "bogus-token"},
		{"follower-shaped bearer that is not an operator", "pl_enroll_abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := getFollowers(t, handler, FollowersPath+"?org_id=org-main", tc.token)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d body=%s, want 403", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandlerListFollowersDeniesCrossOrgRead(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	mustEnrollFollower(t, enrollments, "tok-main-1", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}, "audit-key-main-1")
	mustEnrollFollower(t, enrollments, "tok-other-1", FollowerIdentity{OrgID: "org-other", FleetID: "prod", InstanceID: "pl-other-1", Environment: "prod"}, "audit-key-other-1")
	handler := newFollowersTestHandler(t, enrollments)

	// org-main-scoped auditor reading its own org succeeds.
	w := getFollowers(t, handler, FollowersPath+"?org_id=org-main", followerOrgMainAuditTok)
	if w.Code != http.StatusOK {
		t.Fatalf("own-org read status = %d body=%s, want 200", w.Code, w.Body.String())
	}

	// org-main-scoped auditor attempting to read org-other is denied — the
	// authorizer binds credential scope to the requested org BEFORE the store
	// is touched, so no org-other roster ever leaves the process.
	w = getFollowers(t, handler, FollowersPath+"?org_id=org-other", followerOrgMainAuditTok)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-org read status = %d body=%s, want 403", w.Code, w.Body.String())
	}
}

func TestScopedBearerFollowerListAuthorizerConstructionRejectsUnscopedAndWhitespace(t *testing.T) {
	// Empty-org read creds are a cross-org enumeration token: reject at
	// construction, not at request time. Whitespace-only org normalizes to
	// empty and must be rejected identically (no whitespace bypass).
	for _, tc := range []struct {
		name string
		cred ScopedBearerCredential
	}{
		{"empty-org admin", ScopedBearerCredential{Token: "t", Role: RoleAdmin}},
		{"empty-org auditor", ScopedBearerCredential{Token: "t", Role: RoleAuditor}},
		{"whitespace-org admin", ScopedBearerCredential{Token: "t", Role: RoleAdmin, OrgID: "   "}},
		{"tab-org auditor", ScopedBearerCredential{Token: "t", Role: RoleAuditor, OrgID: "\t"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{tc.cred}); !errors.Is(err, ErrFollowerListForbidden) {
				t.Fatalf("ScopedBearerFollowerListAuthorizer(%+v) error = %v, want ErrFollowerListForbidden", tc.cred, err)
			}
		})
	}

	// A properly org-scoped cred constructs cleanly.
	if _, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{{Token: "t", Role: RoleAdmin, OrgID: "org-main"}}); err != nil {
		t.Fatalf("ScopedBearerFollowerListAuthorizer(scoped) error = %v, want nil", err)
	}
}

func TestHandlerListFollowersDeniesCrossFleetRead(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	mustEnrollFollower(t, enrollments, "tok-prod", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}, "audit-key-prod")
	mustEnrollFollower(t, enrollments, "tok-stg", FollowerIdentity{OrgID: "org-main", FleetID: "staging", InstanceID: "pl-stg-1", Environment: "staging"}, "audit-key-stg")

	// A fleet-scoped auditor (org-main/prod) may read its own fleet but not a
	// sibling fleet in the same org.
	fleetScoped, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{
		{Token: "prod-fleet-token", Role: RoleAuditor, OrgID: "org-main", FleetID: "prod"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerFollowerListAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              mustStore(t),
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeFollowers: fleetScoped,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Own fleet: allowed.
	if w := getFollowers(t, handler, FollowersPath+"?org_id=org-main&fleet_id=prod", "prod-fleet-token"); w.Code != http.StatusOK {
		t.Fatalf("own-fleet read status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	// Sibling fleet in same org: denied.
	if w := getFollowers(t, handler, FollowersPath+"?org_id=org-main&fleet_id=staging", "prod-fleet-token"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-fleet read status = %d body=%s, want 403", w.Code, w.Body.String())
	}
	// Org-only query (no fleet) with a fleet-scoped cred: denied — a
	// fleet-scoped token cannot widen to the whole org by omitting fleet_id.
	if w := getFollowers(t, handler, FollowersPath+"?org_id=org-main", "prod-fleet-token"); w.Code != http.StatusForbidden {
		t.Fatalf("org-wide read with fleet-scoped cred status = %d body=%s, want 403", w.Code, w.Body.String())
	}
}

func TestHandlerListFollowersRejectsMalformedQuery(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	handler := newFollowersTestHandler(t, enrollments)

	cases := []struct {
		name   string
		target string
		want   int
	}{
		{"missing org_id", FollowersPath, http.StatusBadRequest},
		{"unknown param", FollowersPath + "?org_id=org-main&bogus=1", http.StatusBadRequest},
		{"duplicate param", FollowersPath + "?org_id=org-main&org_id=org-other", http.StatusBadRequest},
		{"invalid identifier", FollowersPath + "?org_id=" + "bad%2Fid", http.StatusBadRequest},
		{"invalid limit", FollowersPath + "?org_id=org-main&limit=-3", http.StatusBadRequest},
		{"non-numeric limit", FollowersPath + "?org_id=org-main&limit=abc", http.StatusBadRequest},
		{"limit too high", FollowersPath + "?org_id=org-main&limit=1001", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use the admin token: a malformed query must be rejected at
			// parse time (400), BEFORE authorization. The parse failure is
			// the assertion here.
			w := getFollowers(t, handler, tc.target, followerAdminToken)
			if w.Code != tc.want {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

func TestHandlerListFollowersMethodAndStoreGuards(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}

	// POST is rejected before any auth/store work. GET and DELETE are the only
	// supported follower-roster methods.
	handler := newFollowersTestHandler(t, enrollments)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, FollowersPath+"?org_id=org-main", nil)
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", w.Code)
	}

	// A handler with no enrollment store returns 501, not a 500 or a panic.
	noStore := newFollowersTestHandler(t, nil)
	w = getFollowers(t, noStore, FollowersPath+"?org_id=org-main", followerAdminToken)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("no-store status = %d body=%s, want 501", w.Code, w.Body.String())
	}
}

func TestHandlerRemoveFollowerDecommissionsAuditKey(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	handler := newFollowersTestHandler(t, store)

	body := `{"org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-1","environment":"prod"}`
	w := deleteFollower(t, handler, followerAdminToken, body)
	if w.Code != http.StatusOK {
		t.Fatalf("remove status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var removed FollowerSummary
	if err := json.Unmarshal(w.Body.Bytes(), &removed); err != nil {
		t.Fatalf("decode remove response: %v", err)
	}
	if removed.Active {
		t.Fatalf("removed follower Active = true, want false: %+v", removed)
	}
	list, err := store.ListEnrolledFollowers(context.Background(), FollowerListQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("ListEnrolledFollowers() after remove error = %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("removed follower still appears in fleet status: %+v", list)
	}
	if _, err := store.ResolveEnrolledAuditKey(identity, "audit-key-main-1"); !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("ResolveEnrolledAuditKey() after remove error = %v, want signature verification failure", err)
	}

	// A second remove has no extra side effect, but it must fail loud so an
	// operator cannot accidentally treat a wrong id as a successful decommission.
	w = deleteFollower(t, handler, followerAdminToken, body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("second remove status = %d body=%s, want 404", w.Code, w.Body.String())
	}
}

func TestHandlerRemoveFollowerRequiresAdminAndExactIdentity(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	mustEnrollFollower(t, store, "tok-main-1", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}, "audit-key-main-1")
	handler := newFollowersTestHandler(t, store)

	body := `{"org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-1","environment":"prod"}`
	if w := deleteFollower(t, handler, followerAuditorToken, body); w.Code != http.StatusForbidden {
		t.Fatalf("auditor remove status = %d body=%s, want 403", w.Code, w.Body.String())
	}
	if w := deleteFollower(t, handler, followerAdminToken, `{"org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-1","environment":"staging"}`); w.Code != http.StatusNotFound {
		t.Fatalf("wrong environment remove status = %d body=%s, want 404", w.Code, w.Body.String())
	}
	if w := deleteFollower(t, handler, followerAdminToken, `{"org_id":"bad/id","fleet_id":"prod","instance_id":"pl-prod-1","environment":"prod"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid identity remove status = %d body=%s, want 400", w.Code, w.Body.String())
	}
}

func TestHandlerFollowersHundredFollowerRosterListsAndRemoves(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	for i := range 100 {
		identity := FollowerIdentity{
			OrgID:       "org-main",
			FleetID:     "prod",
			InstanceID:  fmt.Sprintf("pl-prod-%03d", i),
			Environment: "prod",
		}
		mustEnrollFollower(t, store, fmt.Sprintf("scale-token-%03d", i), identity, fmt.Sprintf("scale-audit-key-%03d", i))
	}
	handler := newFollowersTestHandler(t, store)

	w := getFollowers(t, handler, FollowersPath+"?org_id=org-main&fleet_id=prod&limit=100", followerAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("list 100 followers status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var listed listFollowersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode 100-follower response: %v", err)
	}
	if listed.Count != 100 || len(listed.Followers) != 100 {
		t.Fatalf("100-follower roster count=%d len=%d, want 100", listed.Count, len(listed.Followers))
	}
	if listed.Followers[0].InstanceID != "pl-prod-000" || listed.Followers[99].InstanceID != "pl-prod-099" {
		t.Fatalf("100-follower roster bounds = %s..%s, want pl-prod-000..pl-prod-099", listed.Followers[0].InstanceID, listed.Followers[99].InstanceID)
	}

	body := `{"org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-042","environment":"prod"}`
	w = deleteFollower(t, handler, followerAdminToken, body)
	if w.Code != http.StatusOK {
		t.Fatalf("remove from 100-follower roster status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	w = getFollowers(t, handler, FollowersPath+"?org_id=org-main&fleet_id=prod&limit=100", followerAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("list after remove status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode post-remove response: %v", err)
	}
	if listed.Count != 99 || len(listed.Followers) != 99 {
		t.Fatalf("post-remove roster count=%d len=%d, want 99", listed.Count, len(listed.Followers))
	}
	for _, follower := range listed.Followers {
		if follower.InstanceID == "pl-prod-042" {
			t.Fatalf("removed follower still listed in 100-follower roster: %+v", follower)
		}
	}
}

func TestFileEnrollmentStoreListEnrolledFollowersFiltersAndBounds(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	mustEnrollFollower(t, store, "tok-a", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "i-a", Environment: "prod"}, "k-a")
	mustEnrollFollower(t, store, "tok-b", FollowerIdentity{OrgID: "org-main", FleetID: "staging", InstanceID: "i-b", Environment: "staging"}, "k-b")
	mustEnrollFollower(t, store, "tok-c", FollowerIdentity{OrgID: "org-other", FleetID: "prod", InstanceID: "i-c", Environment: "prod"}, "k-c")

	// Org filter.
	got, err := store.ListEnrolledFollowers(context.Background(), FollowerListQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("ListEnrolledFollowers(org) error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("org filter returned %d, want 2", len(got))
	}

	// Org+fleet filter.
	got, err = store.ListEnrolledFollowers(context.Background(), FollowerListQuery{OrgID: "org-main", FleetID: "staging"})
	if err != nil {
		t.Fatalf("ListEnrolledFollowers(org+fleet) error = %v", err)
	}
	if len(got) != 1 || got[0].InstanceID != "i-b" {
		t.Fatalf("org+fleet filter returned %+v, want only i-b", got)
	}

	// Limit clamps the result count.
	got, err = store.ListEnrolledFollowers(context.Background(), FollowerListQuery{OrgID: "org-main", Limit: 1})
	if err != nil {
		t.Fatalf("ListEnrolledFollowers(limit) error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("limit=1 returned %d, want 1", len(got))
	}
	if got[0].InstanceID != "i-a" {
		t.Fatalf("limit=1 returned %+v, want sorted first follower i-a", got)
	}

	// nil receiver fails closed.
	var nilStore *FileEnrollmentStore
	if _, err := nilStore.ListEnrolledFollowers(context.Background(), FollowerListQuery{OrgID: "org-main"}); err == nil {
		t.Fatal("nil store ListEnrolledFollowers() error = nil, want error")
	}
}

func TestFileEnrollmentStoreListEnrolledFollowersCapsHugeRoster(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	store.mu.Lock()
	for i := maxFollowerListLimit + 25; i >= 0; i-- {
		identity := FollowerIdentity{
			OrgID:       "org-main",
			FleetID:     "prod",
			InstanceID:  fmt.Sprintf("i-%04d", i),
			Environment: "prod",
		}
		store.data.Followers[followerEnrollmentKey(identity)] = enrolledFollowerRecord{
			Identity:   identity,
			AuditKeyID: fmt.Sprintf("k-%04d", i),
			EnrolledAt: testNow,
			Active:     true,
		}
	}
	store.mu.Unlock()

	got, err := store.ListEnrolledFollowers(context.Background(), FollowerListQuery{
		OrgID: "org-main",
		Limit: maxFollowerListLimit + 100,
	})
	if err != nil {
		t.Fatalf("ListEnrolledFollowers(huge roster) error = %v", err)
	}
	if len(got) != maxFollowerListLimit {
		t.Fatalf("huge roster returned %d, want max %d", len(got), maxFollowerListLimit)
	}
	if got[0].InstanceID != "i-0000" || got[len(got)-1].InstanceID != "i-0999" {
		t.Fatalf("huge roster bounds = %s..%s, want sorted i-0000..i-0999", got[0].InstanceID, got[len(got)-1].InstanceID)
	}
}

func TestFollowerSummaryLessOrdersByAllKeys(t *testing.T) {
	base := FollowerSummary{OrgID: "o", FleetID: "f", InstanceID: "i", Environment: "e"}
	cases := []struct {
		name string
		a, b FollowerSummary
		want bool
	}{
		{"org tiebreak", FollowerSummary{OrgID: "a"}, FollowerSummary{OrgID: "b"}, true},
		{"fleet tiebreak", withFleet(base, "a"), withFleet(base, "b"), true},
		{"instance tiebreak", withInstance(base, "a"), withInstance(base, "b"), true},
		{"env tiebreak", withEnv(base, "a"), withEnv(base, "b"), true},
		{"equal is not less", base, base, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := followerSummaryLess(tc.a, tc.b); got != tc.want {
				t.Fatalf("followerSummaryLess() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestFollowerSummaryMaxHeapPopReturnsLargestSummary(t *testing.T) {
	h := followerSummaryMaxHeap{
		{OrgID: "org-main", FleetID: "prod", InstanceID: "i-a", Environment: "prod"},
		{OrgID: "org-main", FleetID: "prod", InstanceID: "i-c", Environment: "prod"},
		{OrgID: "org-main", FleetID: "prod", InstanceID: "i-b", Environment: "prod"},
	}
	heap.Init(&h)

	got := heap.Pop(&h).(FollowerSummary)
	if got.InstanceID != "i-c" {
		t.Fatalf("heap.Pop() instance = %q, want i-c", got.InstanceID)
	}
	if len(h) != 2 {
		t.Fatalf("heap length after Pop = %d, want 2", len(h))
	}
}

func withFleet(s FollowerSummary, fleet string) FollowerSummary {
	s.FleetID = fleet
	return s
}

func withInstance(s FollowerSummary, instance string) FollowerSummary {
	s.InstanceID = instance
	return s
}

func withEnv(s FollowerSummary, env string) FollowerSummary {
	s.Environment = env
	return s
}

func TestHandlerListFollowersEmptyRosterReturnsEmptyArray(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	handler := newFollowersTestHandler(t, enrollments)
	w := getFollowers(t, handler, FollowersPath+"?org_id=org-empty", followerOrgEmptyAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	// A nil slice must serialize as [] not null so clients can iterate safely.
	if !strings.Contains(w.Body.String(), `"followers":[]`) || !strings.Contains(w.Body.String(), `"count":0`) {
		t.Fatalf("body = %s, want empty followers array", w.Body.String())
	}
}

func TestNormalizeFollowerListLimit(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, defaultFollowerListLimit},
		{-5, defaultFollowerListLimit},
		{50, 50},
		{maxFollowerListLimit, maxFollowerListLimit},
		{maxFollowerListLimit + 1, maxFollowerListLimit},
	}
	for _, tc := range cases {
		if got := normalizeFollowerListLimit(tc.in); got != tc.want {
			t.Fatalf("normalizeFollowerListLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
