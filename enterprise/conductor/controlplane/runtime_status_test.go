//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func newRuntimeStatusTestHandler(t *testing.T, store *FileEnrollmentStore, identity FollowerIdentity) *Handler {
	t.Helper()
	followerAuth, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{
		{Token: followerAdminToken, Role: RoleAdmin, OrgID: "org-main"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerFollowerListAuthorizer() error = %v", err)
	}
	bundleAuth, err := ScopedBearerBundleAuthorizer([]ScopedBearerCredential{
		{Token: followerAdminToken, Role: RolePublisher, OrgID: "org-main", FleetID: "prod"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerBundleAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return identity, nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeBundle:    bundleAuth,
		AuthorizeFollowers: followerAuth,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        store,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func postRuntimeStatus(t *testing.T, handler *Handler, status FollowerRuntimeStatus) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(runtimeStatusRequest{Status: status})
	if err != nil {
		t.Fatalf("marshal runtime status: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, FollowerRuntimeStatusPath, bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func runtimeStatus(identity FollowerIdentity, version, hash string) FollowerRuntimeStatus {
	return FollowerRuntimeStatus{
		OrgID:                          identity.OrgID,
		FleetID:                        identity.FleetID,
		InstanceID:                     identity.InstanceID,
		Environment:                    identity.Environment,
		PipelockVersion:                version,
		GitCommit:                      "abc123",
		BuildDate:                      "2026-05-24T12:00:00Z",
		SchemaVersion:                  conductor.SchemaVersion,
		ActiveBundleID:                 "bundle-1",
		ActiveBundleVersion:            1,
		ActiveBundleHash:               hash,
		ActiveBundleMinPipelockVersion: "1.2.3",
		LastPolicyPollAt:               testNow,
		LastSuccessfulApplyAt:          testNow,
		LastSeenAt:                     testNow,
	}
}

func TestNormalizeRuntimeStatusValidationEdges(t *testing.T) {
	identity := defaultFollowerIdentity()
	valid := runtimeStatus(identity, "1.2.3", strings.Repeat("A", 64))
	valid.SchemaVersion = 0
	valid.LastSeenAt = time.Time{}
	valid.LastPolicyPollAt = testNow.In(time.FixedZone("offset", -5*60*60))
	valid.LastSuccessfulApplyAt = testNow.In(time.FixedZone("offset", 2*60*60))
	valid.PipelockVersion = " \t1.2.3\n "
	valid.GitCommit = " abc\x00\n123 "
	valid.BuildDate = " 2026-05-24T12:00:00Z "
	valid.ActiveBundleID = " bundle-1 "
	valid.ActiveBundleMinPipelockVersion = " 1.2.0 "
	valid.LastApplyErrorCode = " reload\x00failed "
	valid.LastApplyErrorMessage = " reload\x00\n\tfailed\xff ok "

	normalized, err := normalizeRuntimeStatus(valid, testNow)
	if err != nil {
		t.Fatalf("normalizeRuntimeStatus(valid) error = %v", err)
	}
	if normalized.SchemaVersion != conductor.SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", normalized.SchemaVersion, conductor.SchemaVersion)
	}
	if normalized.ActiveBundleHash != strings.Repeat("a", 64) {
		t.Fatalf("ActiveBundleHash = %q, want lowercase hash", normalized.ActiveBundleHash)
	}
	if !normalized.LastSeenAt.Equal(testNow.UTC()) {
		t.Fatalf("LastSeenAt = %s, want %s", normalized.LastSeenAt, testNow.UTC())
	}
	if normalized.PipelockVersion != "1.2.3" ||
		normalized.GitCommit != "abc 123" ||
		normalized.LastApplyErrorCode != "reload failed" ||
		normalized.LastApplyErrorMessage != "reload failed ok" {
		t.Fatalf("normalized strings = version=%q git=%q code=%q message=%q",
			normalized.PipelockVersion,
			normalized.GitCommit,
			normalized.LastApplyErrorCode,
			normalized.LastApplyErrorMessage,
		)
	}
	if normalized.LastPolicyPollAt.Location() != time.UTC || normalized.LastSuccessfulApplyAt.Location() != time.UTC {
		t.Fatalf("normalized times are not UTC: poll=%s apply=%s", normalized.LastPolicyPollAt.Location(), normalized.LastSuccessfulApplyAt.Location())
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*FollowerRuntimeStatus)
		wantErr error
	}{
		{name: "pipelock_version_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.PipelockVersion = strings.Repeat("9", maxRuntimeStatusStringBytes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "git_commit_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.GitCommit = strings.Repeat("a", maxRuntimeStatusStringBytes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "build_date_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.BuildDate = strings.Repeat("2", maxRuntimeStatusStringBytes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "active_bundle_id_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.ActiveBundleID = strings.Repeat("b", maxRuntimeStatusStringBytes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "active_bundle_hash_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.ActiveBundleHash = strings.Repeat("a", maxRuntimeStatusStringBytes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "active_bundle_min_version_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.ActiveBundleMinPipelockVersion = strings.Repeat("1", maxRuntimeStatusStringBytes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "last_apply_error_code_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.LastApplyErrorCode = strings.Repeat("e", maxRuntimeStatusStringBytes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "last_apply_error_message_rune_oversized", mutate: func(s *FollowerRuntimeStatus) {
			s.LastApplyErrorMessage = strings.Repeat("界", maxApplyErrorMessageRunes+1)
		}, wantErr: conductor.ErrPayloadTooLarge},
		{name: "hash_too_short", mutate: func(s *FollowerRuntimeStatus) {
			s.ActiveBundleHash = strings.Repeat("a", 63)
		}, wantErr: conductor.ErrInvalidHash},
		{name: "hash_not_hex", mutate: func(s *FollowerRuntimeStatus) {
			s.ActiveBundleHash = strings.Repeat("g", 64)
		}, wantErr: conductor.ErrInvalidHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))
			tc.mutate(&status)
			if _, err := normalizeRuntimeStatus(status, testNow); !errors.Is(err, tc.wantErr) {
				t.Fatalf("normalizeRuntimeStatus(%s) error = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestFollowerRuntimeStatusRejectsSpoofedIdentity(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	handler := newRuntimeStatusTestHandler(t, store, identity)

	spoofed := runtimeStatus(FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-2", Environment: "prod"}, "1.2.3", strings.Repeat("a", 64))
	w := postRuntimeStatus(t, handler, spoofed)
	if w.Code != http.StatusForbidden {
		t.Fatalf("spoofed status code = %d body=%s, want 403", w.Code, w.Body.String())
	}
	statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("spoofed status persisted: %+v", statuses)
	}
}

func TestFollowerRuntimeStatusRejectsSpoofOfExistingFollowerBeforeWrite(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	followerA := defaultFollowerIdentity()
	followerB := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-2", Environment: "prod"}
	mustEnrollFollower(t, store, "tok-main-1", followerA, "audit-key-main-1")
	mustEnrollFollower(t, store, "tok-main-2", followerB, "audit-key-main-2")
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), runtimeStatus(followerB, "1.2.3", strings.Repeat("b", 64))); err != nil {
		t.Fatalf("seed follower B status: %v", err)
	}
	handler := newRuntimeStatusTestHandler(t, store, followerA)

	w := postRuntimeStatus(t, handler, runtimeStatus(followerB, "9.9.9", strings.Repeat("c", 64)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("spoofed existing-follower status code = %d body=%s, want 403", w.Code, w.Body.String())
	}
	statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{
		OrgID:      followerB.OrgID,
		FleetID:    followerB.FleetID,
		InstanceID: followerB.InstanceID,
	})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("follower B statuses = %d, want 1", len(statuses))
	}
	if statuses[0].PipelockVersion != "1.2.3" || statuses[0].ActiveBundleHash != strings.Repeat("b", 64) {
		t.Fatalf("follower A overwrote follower B status: %+v", statuses[0])
	}
}

func TestFleetStatusClassifiesRuntimeHealth(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	store := mustStore(t)
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	published, _, err := store.Publish(context.Background(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	ids := []string{"ok", "unsupported", "apply-failed", "stale", "unknown"}
	for _, id := range ids {
		mustEnrollFollower(t, enrollments, "tok-"+id, FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: id, Environment: "prod"}, "audit-"+id)
	}
	statuses := []FollowerRuntimeStatus{
		runtimeStatus(FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "ok", Environment: "prod"}, "1.2.3", published.BundleHash),
		runtimeStatus(FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "unsupported", Environment: "prod"}, "1.0.0", published.BundleHash),
		runtimeStatus(FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "apply-failed", Environment: "prod"}, "1.2.3", published.BundleHash),
		runtimeStatus(FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "stale", Environment: "prod"}, "1.2.3", published.BundleHash),
	}
	statuses[2].LastApplyErrorCode = "reload_failed"
	statuses[2].LastApplyErrorMessage = "reload failed"
	statuses[3].LastSeenAt = testNow.Add(-10 * time.Minute)
	for _, status := range statuses {
		if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), status); err != nil {
			t.Fatalf("UpsertFollowerRuntimeStatus(%s) error = %v", status.InstanceID, err)
		}
	}

	followerAuth, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{{Token: followerAdminToken, Role: RoleAdmin, OrgID: "org-main"}})
	if err != nil {
		t.Fatalf("ScopedBearerFollowerListAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              store,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeFollowers: followerAuth,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	w := getFollowers(t, handler, FollowersPath+"?org_id=org-main&fleet_id=prod&limit=10", followerAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("fleet status code = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp listFollowersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	got := map[string]FleetHealth{}
	for _, follower := range resp.Followers {
		got[follower.InstanceID] = follower.Health
	}
	want := map[string]FleetHealth{
		"ok":           FleetHealthOK,
		"unsupported":  FleetHealthUnsupported,
		"apply-failed": FleetHealthApplyFailed,
		"stale":        FleetHealthStale,
		"unknown":      FleetHealthUnknown,
	}
	for instance, health := range want {
		if got[instance] != health {
			t.Fatalf("health[%s] = %q, want %q (all=%v)", instance, got[instance], health, got)
		}
	}
}

func TestFleetStatusMarksLabelAudienceUnverifiableWithoutLabels(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	store := mustStore(t)
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:      "bundle-label-1",
		version: 1,
		audience: conductor.Audience{Labels: map[string]string{
			"ring": "canary",
		}},
	})
	if _, _, err := store.Publish(context.Background(), bundle, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, enrollments, "tok-main-1", identity, "audit-key-main-1")
	if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}
	followerAuth, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{{Token: followerAdminToken, Role: RoleAdmin, OrgID: "org-main"}})
	if err != nil {
		t.Fatalf("ScopedBearerFollowerListAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              store,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return identity, nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeFollowers: followerAuth,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	w := getFollowers(t, handler, FollowersPath+"?org_id=org-main&fleet_id=prod&limit=10", followerAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("fleet status code = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp listFollowersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Followers) != 1 {
		t.Fatalf("followers = %d, want 1", len(resp.Followers))
	}
	got := resp.Followers[0]
	if got.Health != FleetHealthUnknown || got.Drift != "audience_labels_unavailable" || !got.ExpectedBundle.AudienceLabelsUnavailable {
		t.Fatalf("label audience health = health=%q drift=%q expected=%+v, want unknown/audience_labels_unavailable", got.Health, got.Drift, got.ExpectedBundle)
	}
}

func TestRemovedFollowerRuntimeStatusStopsAppearingHealthy(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}
	if _, err := store.RemoveEnrolledFollower(context.Background(), RemoveEnrolledFollowerRequest{Identity: identity, Now: testNow}); err != nil {
		t.Fatalf("RemoveEnrolledFollower() error = %v", err)
	}
	statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("removed follower status still listed: %+v", statuses)
	}
}

func TestRemovedFollowerRuntimeStatusPostRejectedAfterRemoval(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	handler := newRuntimeStatusTestHandler(t, store, identity)
	if _, err := store.RemoveEnrolledFollower(context.Background(), RemoveEnrolledFollowerRequest{Identity: identity, Now: testNow}); err != nil {
		t.Fatalf("RemoveEnrolledFollower() error = %v", err)
	}

	w := postRuntimeStatus(t, handler, runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("removed follower status code = %d body=%s, want 403", w.Code, w.Body.String())
	}
	statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("late removed-follower status persisted: %+v", statuses)
	}
}

func TestRuntimeStatusBoundsStringsAndRecordCount(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	status := runtimeStatus(identity, strings.Repeat("9", maxRuntimeStatusStringBytes), strings.Repeat("a", 64))
	status.LastApplyErrorMessage = strings.Repeat("x", maxApplyErrorMessageRunes)
	stored, err := store.UpsertFollowerRuntimeStatus(context.Background(), status)
	if err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus(capped strings) error = %v", err)
	}
	if len(stored.PipelockVersion) != maxRuntimeStatusStringBytes {
		t.Fatalf("PipelockVersion len = %d, want cap %d", len(stored.PipelockVersion), maxRuntimeStatusStringBytes)
	}
	if len([]rune(stored.LastApplyErrorMessage)) != maxApplyErrorMessageRunes {
		t.Fatalf("LastApplyErrorMessage runes = %d, want cap %d", len([]rune(stored.LastApplyErrorMessage)), maxApplyErrorMessageRunes)
	}

	full := make(map[string]FollowerRuntimeStatus, maxFollowerRuntimeStatusRecords)
	for i := range maxFollowerRuntimeStatusRecords {
		id := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "filler-" + strconv.Itoa(i), Environment: "prod"}
		full[followerEnrollmentKey(id)] = runtimeStatus(id, "1.2.3", strings.Repeat("b", 64))
	}
	store.mu.Lock()
	store.data.RuntimeStatus = full
	store.mu.Unlock()
	other := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "other", Environment: "prod"}
	mustEnrollFollower(t, store, "tok-other", other, "audit-other")
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), runtimeStatus(other, "1.2.3", strings.Repeat("c", 64))); !errors.Is(err, ErrRuntimeStatusLimitExceeded) {
		t.Fatalf("UpsertFollowerRuntimeStatus(over limit) error = %v, want ErrRuntimeStatusLimitExceeded", err)
	}
}

func TestRuntimeStatusRejectsOversizedStringsWithoutPersisting(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")

	for _, tc := range []struct {
		name   string
		mutate func(*FollowerRuntimeStatus)
	}{
		{name: "pipelock_version", mutate: func(s *FollowerRuntimeStatus) { s.PipelockVersion = strings.Repeat("9", maxRuntimeStatusStringBytes+1) }},
		{name: "git_commit", mutate: func(s *FollowerRuntimeStatus) { s.GitCommit = strings.Repeat("a", maxRuntimeStatusStringBytes+1) }},
		{name: "apply_error_message", mutate: func(s *FollowerRuntimeStatus) {
			s.LastApplyErrorMessage = strings.Repeat("x", maxApplyErrorMessageRunes+1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))
			tc.mutate(&status)
			if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), status); !errors.Is(err, conductor.ErrPayloadTooLarge) {
				t.Fatalf("UpsertFollowerRuntimeStatus(%s) error = %v, want ErrPayloadTooLarge", tc.name, err)
			}
			statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: "org-main"})
			if err != nil {
				t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
			}
			if len(statuses) != 0 {
				t.Fatalf("oversized status persisted after %s: %+v", tc.name, statuses)
			}
		})
	}
}

func TestRuntimeStatusAuthSeparatesFollowerIdentityFromPublisherToken(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")

	missingIdentity := newRuntimeStatusTestHandler(t, store, identity)
	missingIdentity.followerIdentity = func(*http.Request) (FollowerIdentity, error) {
		return FollowerIdentity{}, ErrFollowerRequired
	}
	body, err := json.Marshal(runtimeStatusRequest{Status: runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))})
	if err != nil {
		t.Fatalf("marshal runtime status: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, FollowerRuntimeStatusPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w := httptest.NewRecorder()
	missingIdentity.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status with publisher/admin token but no follower identity = %d body=%s, want 401", w.Code, w.Body.String())
	}

	followerOnly := newRuntimeStatusTestHandler(t, store, identity)
	followerOnly.authorizePublisher = func(*http.Request) error {
		t.Fatal("runtime status must not require publisher authorization")
		return ErrPublisherForbidden
	}
	w = postRuntimeStatus(t, followerOnly, runtimeStatus(identity, "1.2.3", strings.Repeat("b", 64)))
	if w.Code != http.StatusOK {
		t.Fatalf("status with follower identity only = %d body=%s, want 200", w.Code, w.Body.String())
	}
}

func TestRuntimeStatusHandlerErrorResponses(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	handler := newRuntimeStatusTestHandler(t, store, identity)
	handler.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	requestBody := func(status FollowerRuntimeStatus) string {
		t.Helper()
		body, err := json.Marshal(runtimeStatusRequest{Status: status})
		if err != nil {
			t.Fatalf("marshal runtime status: %v", err)
		}
		return string(body)
	}
	serve := func(h *Handler, method string, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), method, FollowerRuntimeStatusPath, strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := serve(handler, http.MethodGet, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET runtime status code = %d body=%s, want 405", w.Code, w.Body.String())
	}

	noStore := *handler
	noStore.enrollments = nil
	if w := serve(&noStore, http.MethodPost, `{}`); w.Code != http.StatusNotImplemented {
		t.Fatalf("runtime status without store code = %d body=%s, want 501", w.Code, w.Body.String())
	}

	if w := serve(handler, http.MethodPost, `{"status":`); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed runtime status code = %d body=%s, want 400", w.Code, w.Body.String())
	}

	tinyBodyLimit := *handler
	tinyBodyLimit.maxRequestBody = 4
	if w := serve(&tinyBodyLimit, http.MethodPost, requestBody(runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64)))); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized runtime status body code = %d body=%s, want 413", w.Code, w.Body.String())
	}

	invalidHash := runtimeStatus(identity, "1.2.3", strings.Repeat("g", 64))
	if w := serve(handler, http.MethodPost, requestBody(invalidHash)); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid hash runtime status code = %d body=%s, want 400", w.Code, w.Body.String())
	}

	overLimit := *handler
	overLimit.enrollments = runtimeStatusErrorStore{err: ErrRuntimeStatusLimitExceeded}
	if w := serve(&overLimit, http.MethodPost, requestBody(runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64)))); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("runtime status limit code = %d body=%s, want 413", w.Code, w.Body.String())
	}

	failingStore := *handler
	failingStore.enrollments = runtimeStatusErrorStore{err: errors.New("disk write failed")}
	if w := serve(&failingStore, http.MethodPost, requestBody(runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64)))); w.Code != http.StatusInternalServerError {
		t.Fatalf("runtime status internal store error code = %d body=%s, want 500", w.Code, w.Body.String())
	}
}

func TestPublishPreflightBlocksUnsupportedAndOverridePublishes(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, enrollments, "tok-main-1", identity, "audit-key-main-1")
	if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), runtimeStatus(identity, "1.0.0", strings.Repeat("a", 64))); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}
	handler := newRuntimeStatusTestHandler(t, enrollments, identity)
	adminAuth, err := ScopedBearerAdminAuthorizer([]ScopedBearerCredential{{
		Token: followerAdminToken,
		Role:  RoleAdmin,
	}})
	if err != nil {
		t.Fatalf("ScopedBearerAdminAuthorizer() error = %v", err)
	}
	handler.authorizeFleetSkewOverride = func(r *http.Request, _ conductor.PolicyBundle, _ string) error {
		return adminAuth(r)
	}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
	if err != nil {
		t.Fatalf("marshal publish request: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("publish unsupported code = %d body=%s, want 409", w.Code, w.Body.String())
	}
	var blocked struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &blocked); err != nil {
		t.Fatalf("decode blocked response: %v", err)
	}
	if blocked.Code != PublishConflictFleetSkew {
		t.Fatalf("blocked code = %q, want %q", blocked.Code, PublishConflictFleetSkew)
	}

	body, err = json.Marshal(publishPolicyBundleRequest{Bundle: bundle, AllowFleetSkew: true, FleetSkewReason: "break glass for canary rollout"})
	if err != nil {
		t.Fatalf("marshal override publish request: %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("override publish code = %d body=%s, want 201", w.Code, w.Body.String())
	}
	var published publishPolicyBundleResponse
	if err := json.Unmarshal(w.Body.Bytes(), &published); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !published.Preflight.AllowFleetSkew || published.Preflight.Unsupported != 1 || published.Preflight.FleetSkewReason != "break glass for canary rollout" {
		t.Fatalf("preflight = %+v, want override with one unsupported", published.Preflight)
	}
}

func TestPublishPreflightOverrideRequiresReasonAndAuthorization(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, enrollments, "tok-main-1", identity, "audit-key-main-1")
	if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), runtimeStatus(identity, "1.0.0", strings.Repeat("a", 64))); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}
	handler := newRuntimeStatusTestHandler(t, enrollments, identity)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-override-auth-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})

	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle, AllowFleetSkew: true})
	if err != nil {
		t.Fatalf("marshal missing reason publish request: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("override without reason code = %d body=%s, want 400", w.Code, w.Body.String())
	}

	body, err = json.Marshal(publishPolicyBundleRequest{Bundle: bundle, AllowFleetSkew: true, FleetSkewReason: "operator break glass"})
	if err != nil {
		t.Fatalf("marshal unauthorized override publish request: %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("override without override authorizer code = %d body=%s, want 403", w.Code, w.Body.String())
	}
}

func TestPublishPreflightBlocksLabelAudienceWhenLabelsUnavailable(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, enrollments, "tok-main-1", identity, "audit-key-main-1")
	if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), runtimeStatus(identity, "1.0.0", strings.Repeat("a", 64))); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}
	handler := newRuntimeStatusTestHandler(t, enrollments, identity)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:      "bundle-label-1",
		version: 1,
		audience: conductor.Audience{Labels: map[string]string{
			"ring": "canary",
		}},
	})
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
	if err != nil {
		t.Fatalf("marshal publish request: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("label-audience publish code = %d body=%s, want 409", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "label-scoped audience") {
		t.Fatalf("label-audience publish body = %s, want label-scoped preflight error", w.Body.String())
	}

	handler.authorizeFleetSkewOverride = func(*http.Request, conductor.PolicyBundle, string) error { return nil }
	body, err = json.Marshal(publishPolicyBundleRequest{Bundle: bundle, AllowFleetSkew: true, FleetSkewReason: "operator accepts skew"})
	if err != nil {
		t.Fatalf("marshal override publish request: %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("label-audience override publish code = %d body=%s, want 409", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "label-scoped audience") {
		t.Fatalf("label-audience override body = %s, want label-scoped preflight error", w.Body.String())
	}
}

func TestEvaluatePublishPreflightDefaultsStaleAfter(t *testing.T) {
	identity := defaultFollowerIdentity()
	followers := []FollowerSummary{{
		OrgID:       identity.OrgID,
		FleetID:     identity.FleetID,
		InstanceID:  identity.InstanceID,
		Environment: identity.Environment,
		Active:      true,
	}}
	statuses := []FollowerRuntimeStatus{{
		OrgID:           identity.OrgID,
		FleetID:         identity.FleetID,
		InstanceID:      identity.InstanceID,
		Environment:     identity.Environment,
		PipelockVersion: "1.2.3",
		LastSeenAt:      testNow.Add(-(defaultRuntimeStatusStaleAfter / 2)),
	}}
	bundle := conductor.PolicyBundle{
		OrgID:              identity.OrgID,
		FleetID:            identity.FleetID,
		Environment:        identity.Environment,
		MinPipelockVersion: "1.0.0",
		Audience:           conductor.Audience{InstanceIDs: []string{"*"}},
	}

	summary, err := evaluatePublishPreflight(followers, statuses, bundle, publishPreflightOptions{now: testNow})
	if err != nil {
		t.Fatalf("evaluatePublishPreflight() error = %v", err)
	}
	if summary.StaleAfterSeconds != int(defaultRuntimeStatusStaleAfter/time.Second) {
		t.Fatalf("StaleAfterSeconds = %d, want default %d", summary.StaleAfterSeconds, int(defaultRuntimeStatusStaleAfter/time.Second))
	}
	if summary.CanApply != 1 || summary.StaleUnseen != 0 {
		t.Fatalf("summary CanApply=%d StaleUnseen=%d, want current follower to use default stale window", summary.CanApply, summary.StaleUnseen)
	}
}

func TestPublishPreflightBlocksLastApplyFailureWithoutOverride(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, enrollments, "tok-main-1", identity, "audit-key-main-1")
	status := runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))
	status.LastApplyErrorCode = "reload_failed"
	if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), status); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}
	handler := newRuntimeStatusTestHandler(t, enrollments, identity)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-apply-failed-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
	if err != nil {
		t.Fatalf("marshal publish request: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("last-apply-failed publish code = %d body=%s, want 409", w.Code, w.Body.String())
	}
}

func TestPublishPreflightBlocksTruncatedRosterEvenWithOverride(t *testing.T) {
	store := truncatedPreflightEnrollmentStore{truncated: true}
	handler := &Handler{
		enrollments: store,
		now:         func() time.Time { return testNow },
	}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-truncated-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	summary, err := handler.publishPreflight(
		httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, http.NoBody),
		bundle,
		true,
		"operator accepted stale roster",
	)
	if !errors.Is(err, ErrFleetPreflightBlocked) {
		t.Fatalf("publishPreflight(truncated override) error = %v, want ErrFleetPreflightBlocked", err)
	}
	if !summary.AllowFleetSkew || summary.StaleUnseen != 1 || summary.FleetSkewReason != "operator accepted stale roster" {
		t.Fatalf("truncated preflight summary = %+v, want skew override recorded with one stale/unseen", summary)
	}
}

func TestPublishPreflightRequiresRuntimeStatusStore(t *testing.T) {
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-runtime-store-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, http.NoBody)
	for _, tc := range []struct {
		name        string
		enrollments EnrollmentStore
	}{
		{name: "nil_enrollment_store"},
		{name: "enrollment_store_without_runtime_status", enrollments: enrollmentOnlyStore{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{
				enrollments: tc.enrollments,
				now:         func() time.Time { return testNow },
			}
			if _, err := handler.publishPreflight(req, bundle, false, ""); !errors.Is(err, ErrRuntimeStatusStoreRequired) {
				t.Fatalf("publishPreflight(%s) error = %v, want ErrRuntimeStatusStoreRequired", tc.name, err)
			}
		})
	}
}

func TestRuntimeStatusPersistsAcrossRestartAndLastWriterWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	first := runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), first); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus(first) error = %v", err)
	}
	second := runtimeStatus(identity, "1.2.4", strings.Repeat("b", 64))
	second.LastSeenAt = testNow.Add(time.Second)
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), second); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus(second) error = %v", err)
	}

	reopened, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("reopen enrollment store: %v", err)
	}
	statuses, err := reopened.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses after restart = %d, want 1", len(statuses))
	}
	if statuses[0].PipelockVersion != "1.2.4" || statuses[0].ActiveBundleHash != strings.Repeat("b", 64) {
		t.Fatalf("restart status = %+v, want last writer", statuses[0])
	}
}

func TestRuntimeStatusConcurrentPosts(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	const followers = 16
	for i := range followers {
		identity := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-" + strconv.Itoa(i), Environment: "prod"}
		mustEnrollFollower(t, store, "tok-concurrent-"+strconv.Itoa(i), identity, "audit-concurrent-"+strconv.Itoa(i))
	}

	handlers := make([]*Handler, followers)
	identities := make([]FollowerIdentity, followers)
	for i := range followers {
		identities[i] = FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-" + strconv.Itoa(i), Environment: "prod"}
		handlers[i] = newRuntimeStatusTestHandler(t, store, identities[i])
	}
	var wg sync.WaitGroup
	for i := range followers {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := json.Marshal(runtimeStatusRequest{Status: runtimeStatus(identities[i], "1.2.3", strings.Repeat("a", 64))})
			if err != nil {
				t.Errorf("marshal runtime status: %v", err)
				return
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, FollowerRuntimeStatusPath, bytes.NewReader(body))
			w := httptest.NewRecorder()
			handlers[i].ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("concurrent post %d code = %d body=%s, want 200", i, w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: "org-main", Limit: followers})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != followers {
		t.Fatalf("statuses after concurrent posts = %d, want %d", len(statuses), followers)
	}
}

func TestConsumeEnrollmentTokenInitializesNilRuntimeStatusMap(t *testing.T) {
	store, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	issued, err := store.CreateEnrollmentToken(context.Background(), EnrollmentTokenSpec{
		TokenID:  "tok-main-1",
		Identity: identity,
		Expires:  testNow.Add(time.Hour),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken() error = %v", err)
	}
	store.mu.Lock()
	store.data.RuntimeStatus = nil
	store.mu.Unlock()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if _, err := store.ConsumeEnrollmentToken(context.Background(), ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-main-1",
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: testNow,
	}); err != nil {
		t.Fatalf("ConsumeEnrollmentToken() error = %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.data.RuntimeStatus == nil {
		t.Fatal("RuntimeStatus map = nil after consume, want initialized")
	}
}

func TestRuntimeStatusStoreNilReceiverErrors(t *testing.T) {
	var store *FileEnrollmentStore
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), FollowerRuntimeStatus{}); !errors.Is(err, ErrRuntimeStatusStoreRequired) {
		t.Fatalf("UpsertFollowerRuntimeStatus(nil) error = %v, want ErrRuntimeStatusStoreRequired", err)
	}
	if _, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{}); !errors.Is(err, ErrRuntimeStatusStoreRequired) {
		t.Fatalf("ListFollowerRuntimeStatus(nil) error = %v, want ErrRuntimeStatusStoreRequired", err)
	}
}

func TestRuntimeStatusUpsertPreservesLastSuccessfulApplyAndRollsBackOnSaveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	first := runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))
	first.LastSuccessfulApplyAt = testNow.Add(-time.Minute)
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), first); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus(first) error = %v", err)
	}
	second := runtimeStatus(identity, "1.2.4", strings.Repeat("b", 64))
	second.LastSuccessfulApplyAt = time.Time{}
	stored, err := store.UpsertFollowerRuntimeStatus(context.Background(), second)
	if err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus(second) error = %v", err)
	}
	if !stored.LastSuccessfulApplyAt.Equal(first.LastSuccessfulApplyAt) {
		t.Fatalf("LastSuccessfulApplyAt = %s, want preserved %s", stored.LastSuccessfulApplyAt, first.LastSuccessfulApplyAt)
	}

	store.path = filepath.Dir(path)
	third := runtimeStatus(identity, "1.2.5", strings.Repeat("c", 64))
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), third); err == nil || !strings.Contains(err.Error(), "write enrollment store") {
		t.Fatalf("UpsertFollowerRuntimeStatus(save failure) error = %v, want write error", err)
	}
	statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: identity.OrgID})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses after rollback = %d, want 1", len(statuses))
	}
	if statuses[0].PipelockVersion != "1.2.4" || statuses[0].ActiveBundleHash != strings.Repeat("b", 64) {
		t.Fatalf("status after failed save = %+v, want previous status", statuses[0])
	}
}

func TestRemoveEnrolledFollowerRestoresRuntimeStatusOnSaveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	store, err := OpenFileEnrollmentStore(path)
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, store, "tok-main-1", identity, "audit-key-main-1")
	wantStatus := runtimeStatus(identity, "1.2.3", strings.Repeat("a", 64))
	if _, err := store.UpsertFollowerRuntimeStatus(context.Background(), wantStatus); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}

	store.path = filepath.Dir(path)
	if _, err := store.RemoveEnrolledFollower(context.Background(), RemoveEnrolledFollowerRequest{Identity: identity, Now: testNow}); err == nil || !strings.Contains(err.Error(), "write enrollment store") {
		t.Fatalf("RemoveEnrolledFollower(save failure) error = %v, want write error", err)
	}
	statuses, err := store.ListFollowerRuntimeStatus(context.Background(), RuntimeStatusQuery{OrgID: identity.OrgID})
	if err != nil {
		t.Fatalf("ListFollowerRuntimeStatus() error = %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses after failed remove = %d, want 1", len(statuses))
	}
	if statuses[0].PipelockVersion != wantStatus.PipelockVersion {
		t.Fatalf("status after failed remove = %+v, want restored %+v", statuses[0], wantStatus)
	}
	followers, err := store.ListEnrolledFollowers(context.Background(), FollowerListQuery{OrgID: identity.OrgID})
	if err != nil {
		t.Fatalf("ListEnrolledFollowers() error = %v", err)
	}
	if len(followers) != 1 || !followers[0].Active {
		t.Fatalf("followers after failed remove = %+v, want active follower restored", followers)
	}
}

type truncatedPreflightEnrollmentStore struct {
	followers []FollowerSummary
	statuses  []FollowerRuntimeStatus
	truncated bool
}

type runtimeStatusErrorStore struct {
	truncatedPreflightEnrollmentStore
	err error
}

type enrollmentOnlyStore struct{}

func (enrollmentOnlyStore) CreateEnrollmentToken(context.Context, EnrollmentTokenSpec) (IssuedEnrollmentToken, error) {
	return IssuedEnrollmentToken{}, errors.New("not implemented")
}

func (enrollmentOnlyStore) ConsumeEnrollmentToken(context.Context, ConsumeEnrollmentTokenRequest) (EnrolledFollower, error) {
	return EnrolledFollower{}, errors.New("not implemented")
}

func (enrollmentOnlyStore) ResolveEnrolledAuditKey(FollowerIdentity, string) (conductor.SignatureKey, error) {
	return conductor.SignatureKey{}, ErrFollowerNotFound
}

func (enrollmentOnlyStore) ListEnrolledFollowers(context.Context, FollowerListQuery) ([]FollowerSummary, error) {
	return []FollowerSummary{}, nil
}

func (enrollmentOnlyStore) RemoveEnrolledFollower(context.Context, RemoveEnrolledFollowerRequest) (FollowerSummary, error) {
	return FollowerSummary{}, ErrFollowerNotFound
}

func (enrollmentOnlyStore) ListEnrollmentTokens(context.Context, EnrollmentTokenListQuery) ([]EnrollmentTokenSummary, error) {
	return []EnrollmentTokenSummary{}, nil
}

func (enrollmentOnlyStore) RevokeEnrollmentToken(context.Context, RevokeEnrollmentTokenRequest) (EnrollmentTokenSummary, error) {
	return EnrollmentTokenSummary{}, ErrEnrollmentTokenNotFound
}

func (s runtimeStatusErrorStore) UpsertFollowerRuntimeStatus(context.Context, FollowerRuntimeStatus) (FollowerRuntimeStatus, error) {
	return FollowerRuntimeStatus{}, s.err
}

func (s truncatedPreflightEnrollmentStore) CreateEnrollmentToken(context.Context, EnrollmentTokenSpec) (IssuedEnrollmentToken, error) {
	return IssuedEnrollmentToken{}, errors.New("unexpected CreateEnrollmentToken call")
}

func (s truncatedPreflightEnrollmentStore) ConsumeEnrollmentToken(context.Context, ConsumeEnrollmentTokenRequest) (EnrolledFollower, error) {
	return EnrolledFollower{}, errors.New("unexpected ConsumeEnrollmentToken call")
}

func (s truncatedPreflightEnrollmentStore) ResolveEnrolledAuditKey(FollowerIdentity, string) (conductor.SignatureKey, error) {
	return conductor.SignatureKey{}, errors.New("unexpected ResolveEnrolledAuditKey call")
}

func (s truncatedPreflightEnrollmentStore) ListEnrolledFollowers(context.Context, FollowerListQuery) ([]FollowerSummary, error) {
	return s.followers, nil
}

func (s truncatedPreflightEnrollmentStore) RemoveEnrolledFollower(context.Context, RemoveEnrolledFollowerRequest) (FollowerSummary, error) {
	return FollowerSummary{}, errors.New("unexpected RemoveEnrolledFollower call")
}

func (s truncatedPreflightEnrollmentStore) ListEnrollmentTokens(context.Context, EnrollmentTokenListQuery) ([]EnrollmentTokenSummary, error) {
	return nil, errors.New("unexpected ListEnrollmentTokens call")
}

func (s truncatedPreflightEnrollmentStore) RevokeEnrollmentToken(context.Context, RevokeEnrollmentTokenRequest) (EnrollmentTokenSummary, error) {
	return EnrollmentTokenSummary{}, errors.New("unexpected RevokeEnrollmentToken call")
}

func (s truncatedPreflightEnrollmentStore) UpsertFollowerRuntimeStatus(context.Context, FollowerRuntimeStatus) (FollowerRuntimeStatus, error) {
	return FollowerRuntimeStatus{}, errors.New("unexpected UpsertFollowerRuntimeStatus call")
}

func (s truncatedPreflightEnrollmentStore) ListFollowerRuntimeStatus(context.Context, RuntimeStatusQuery) ([]FollowerRuntimeStatus, error) {
	return s.statuses, nil
}

func (s truncatedPreflightEnrollmentStore) ListEnrolledFollowersForPreflight(context.Context, FollowerListQuery) ([]FollowerSummary, bool, error) {
	return s.followers, s.truncated, nil
}
