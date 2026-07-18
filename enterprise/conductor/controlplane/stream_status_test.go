//go:build enterprise

// Copyright 2026 Pipelock contributors
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
)

const (
	streamAdminToken    = "stream-admin-token"
	streamAuditorToken  = "stream-auditor-token"
	streamOtherOrgToken = "stream-other-org-token"
)

// publishStreamFixture publishes a two-version stream into the bundle store and
// returns the v1/v2 records so callers can build rollback authorizations.
func publishStreamFixture(t *testing.T, store *FileBundleStore) (PublishedBundle, PublishedBundle) {
	t.Helper()
	signer := newTestSigner(t)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}
	v1 := signedControlBundle(t, signer, bundleSpec{id: "bundle-v1", version: 1, audience: audience})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     audience,
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	r2, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	return r1, r2
}

func newStreamStatusTestHandler(t *testing.T, store BundleStore, emergency EmergencyStore, emergencyKeys ...conductor.SignatureKeyResolver) *Handler {
	t.Helper()
	streamAuth, err := ScopedBearerStreamStatusAuthorizer([]ScopedBearerCredential{
		{Token: streamAdminToken, Role: RoleAdmin, OrgID: "org-main"},
		{Token: streamAuditorToken, Role: RoleAuditor, OrgID: "org-main"},
		{Token: streamOtherOrgToken, Role: RoleAdmin, OrgID: "org-other"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerStreamStatusAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              store,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeStream:    streamAuth,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		EmergencyControls:  emergency,
		EmergencyKeys:      composeResolvers(emergencyKeys...),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

// composeResolvers returns a single SignatureKeyResolver that tries each
// supplied resolver in order, returning the first key that resolves. With no
// non-nil resolvers it returns nil so the verified emergency view fails closed
// (quarantines every record).
func composeResolvers(resolvers ...conductor.SignatureKeyResolver) conductor.SignatureKeyResolver {
	nonNil := make([]conductor.SignatureKeyResolver, 0, len(resolvers))
	for _, r := range resolvers {
		if r != nil {
			nonNil = append(nonNil, r)
		}
	}
	if len(nonNil) == 0 {
		return nil
	}
	return func(keyID string) (conductor.SignatureKey, error) {
		for _, resolve := range nonNil {
			if key, err := resolve(keyID); err == nil {
				return key, nil
			}
		}
		return conductor.SignatureKey{}, conductor.ErrSignatureVerification
	}
}

func getStreamStatus(t *testing.T, handler *Handler, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestFileBundleStoreStreamOverview(t *testing.T) {
	store := mustStore(t)
	r1, r2 := publishStreamFixture(t, store)

	summaries, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("StreamOverview() error = %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("StreamOverview() returned %d streams, want 1", len(summaries))
	}
	s := summaries[0]
	if s.HeadVersion != 2 || s.MaxVersion != 2 {
		t.Fatalf("head=%d max=%d, want 2/2", s.HeadVersion, s.MaxVersion)
	}
	if s.HeadBundleHash != r2.BundleHash {
		t.Fatalf("head hash = %q, want %q", s.HeadBundleHash, r2.BundleHash)
	}
	if s.RolledBack {
		t.Fatal("RolledBack = true, want false on a forward-only stream")
	}
	if len(s.BundleChain) != 2 {
		t.Fatalf("chain len = %d, want 2", len(s.BundleChain))
	}
	// Chain is ascending by version: v1 then v2.
	if s.BundleChain[0].Version != 1 || s.BundleChain[1].Version != 2 {
		t.Fatalf("chain order = [%d,%d], want [1,2]", s.BundleChain[0].Version, s.BundleChain[1].Version)
	}
	if s.BundleChain[0].BundleHash != r1.BundleHash {
		t.Fatalf("chain[0] hash = %q, want %q", s.BundleChain[0].BundleHash, r1.BundleHash)
	}
	if s.BundleChain[1].PreviousBundleHash != r1.BundleHash {
		t.Fatalf("chain[1] previous = %q, want %q", s.BundleChain[1].PreviousBundleHash, r1.BundleHash)
	}
}

func TestFileBundleStoreStreamOverviewRolledBack(t *testing.T) {
	store := mustStore(t)
	_, r2 := publishStreamFixture(t, store)
	// Build a rollback from v2 back to v1 and apply it.
	r1Latest, err := store.BundleByIDVersion(t.Context(), "bundle-v1", 1)
	if err != nil {
		t.Fatalf("BundleByIDVersion(v1) error = %v", err)
	}
	auth := signedRollbackAuthorizationForBundles(t, "rollback-overview", r2.Bundle, r1Latest.Bundle, testNow)
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow); err != nil {
		t.Fatalf("ApplyRollbackHead() error = %v", err)
	}
	summaries, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("StreamOverview() error = %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("got %d streams, want 1", len(summaries))
	}
	s := summaries[0]
	if !s.RolledBack {
		t.Fatal("RolledBack = false, want true after ApplyRollbackHead")
	}
	if s.HeadVersion != 1 {
		t.Fatalf("head version = %d, want 1 (capped by rollback)", s.HeadVersion)
	}
	if s.MaxVersion != 2 {
		t.Fatalf("max version = %d, want 2 (monotonicity gate is unchanged)", s.MaxVersion)
	}
	// The superseded v2 record stays in the chain as audit history.
	if len(s.BundleChain) != 2 {
		t.Fatalf("chain len = %d, want 2", len(s.BundleChain))
	}
}

// TestFileBundleStoreStreamOverviewRollbackResumes proves that a forward publish
// after a rollback clears RolledBack. The rollback marker is retained as audit
// context, so a marker-presence check would report rolled_back=true forever even
// though the head has resumed above the rollback ceiling; the operator view must
// track whether the rollback still caps the head, not whether a marker exists.
func TestFileBundleStoreStreamOverviewRollbackResumes(t *testing.T) {
	store := mustStore(t)
	r1, r2 := publishStreamFixture(t, store)
	r1Latest, err := store.BundleByIDVersion(t.Context(), "bundle-v1", 1)
	if err != nil {
		t.Fatalf("BundleByIDVersion(v1) error = %v", err)
	}
	auth := signedRollbackAuthorizationForBundles(t, "rollback-resume", r2.Bundle, r1Latest.Bundle, testNow)
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow); err != nil {
		t.Fatalf("ApplyRollbackHead() error = %v", err)
	}

	// Forward-publish v3. After the rollback the served head is v1 (r1), so the
	// new bundle chains off r1.BundleHash, and version 3 exceeds the stream max
	// of 2 (the monotonicity gate).
	signer := newTestSigner(t)
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-v3",
		version:      3,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v3, PublishOptions{Now: testNow.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("Publish(v3 forward-after-rollback) error = %v", err)
	}

	summaries, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "org-main"})
	if err != nil {
		t.Fatalf("StreamOverview() error = %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("got %d streams, want 1", len(summaries))
	}
	s := summaries[0]
	if s.RolledBack {
		t.Fatal("RolledBack = true, want false after a forward publish resumed past the rollback ceiling")
	}
	if s.HeadVersion != 3 {
		t.Fatalf("head version = %d, want 3 (forward publish is the new head)", s.HeadVersion)
	}
	if s.MaxVersion != 3 {
		t.Fatalf("max version = %d, want 3", s.MaxVersion)
	}
}

func TestFileBundleStoreStreamOverviewScopeAndValidation(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)

	t.Run("other org sees no streams", func(t *testing.T) {
		summaries, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "org-other"})
		if err != nil {
			t.Fatalf("StreamOverview() error = %v", err)
		}
		if len(summaries) != 0 {
			t.Fatalf("got %d streams for org-other, want 0", len(summaries))
		}
	})

	t.Run("mismatched fleet sees no streams", func(t *testing.T) {
		summaries, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "org-main", FleetID: "staging"})
		if err != nil {
			t.Fatalf("StreamOverview() error = %v", err)
		}
		if len(summaries) != 0 {
			t.Fatalf("got %d streams for fleet staging, want 0", len(summaries))
		}
	})

	t.Run("matching fleet sees the stream", func(t *testing.T) {
		summaries, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "org-main", FleetID: "prod"})
		if err != nil {
			t.Fatalf("StreamOverview() error = %v", err)
		}
		if len(summaries) != 1 {
			t.Fatalf("got %d streams for fleet prod, want 1", len(summaries))
		}
	})

	t.Run("invalid org rejected", func(t *testing.T) {
		if _, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "bad/org"}); err == nil {
			t.Fatal("StreamOverview(bad org) error = nil, want validation error")
		}
	})

	t.Run("invalid fleet rejected", func(t *testing.T) {
		if _, err := store.StreamOverview(t.Context(), StreamStatusQuery{OrgID: "org-main", FleetID: "bad/fleet"}); err == nil {
			t.Fatal("StreamOverview(bad fleet) error = nil, want validation error")
		}
	})
}

func TestFileBundleStoreStreamOverviewNilReceiver(t *testing.T) {
	var store *FileBundleStore
	if _, err := store.StreamOverview(context.Background(), StreamStatusQuery{OrgID: "org-main"}); !errors.Is(err, ErrStoreRequired) {
		t.Fatalf("StreamOverview(nil) error = %v, want ErrStoreRequired", err)
	}
}

func TestHandlerStreamStatusReturnsTopologyWithoutFollowerDrift(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)
	handler := newStreamStatusTestHandler(t, store, nil)

	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAuditorToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", w.Code, w.Body.String())
	}

	// HONESTY GUARD: the response must not claim any per-follower applied
	// version or drift. These tokens never appear in the Conductor stream view.
	body := w.Body.String()
	for _, forbidden := range []string{"applied_version", "applied_bundle_version", "drift", "last_contact", "last_seen"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("stream status response leaked per-follower field %q: %s", forbidden, body)
		}
	}

	var resp streamStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.StreamCount != 1 || len(resp.Streams) != 1 {
		t.Fatalf("stream count = %d, want 1", resp.StreamCount)
	}
	if resp.Streams[0].HeadVersion != 2 || resp.Streams[0].MaxVersion != 2 {
		t.Fatalf("head/max = %d/%d, want 2/2", resp.Streams[0].HeadVersion, resp.Streams[0].MaxVersion)
	}
	if resp.ActiveRemoteKills == nil || resp.ActiveRollbacks == nil {
		t.Fatal("active kill/rollback slices must be non-nil even when empty")
	}
	if resp.EmergencyControlsRead {
		t.Fatal("EmergencyControlsRead = true, want false when no emergency store is configured")
	}
}

func TestHandlerStreamStatusIncludesActiveEmergencyControls(t *testing.T) {
	store := mustStore(t)
	_, r2 := publishStreamFixture(t, store)
	emergency := mustEmergencyStore(t)

	// A valid active remote kill in scope.
	kill, killResolver := signedRemoteKillMessageWithResolver(t, "kill-1", 1, conductor.KillSwitchActive, testNow)
	if _, _, err := emergency.PublishRemoteKill(t.Context(), kill, testNow); err != nil {
		t.Fatalf("PublishRemoteKill() error = %v", err)
	}
	// A valid rollback authorization in scope (v2 -> v1).
	r1, err := store.BundleByIDVersion(t.Context(), "bundle-v1", 1)
	if err != nil {
		t.Fatalf("BundleByIDVersion(v1) error = %v", err)
	}
	auth, rollbackResolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-1", r2.Bundle, r1.Bundle, testNow)
	if _, _, err := emergency.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil {
		t.Fatalf("PublishRollbackAuthorization() error = %v", err)
	}

	handler := newStreamStatusTestHandler(t, store, emergency, killResolver, rollbackResolver)
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp streamStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.EmergencyControlsRead {
		t.Fatal("EmergencyControlsRead = false, want true when an enumerable emergency store is configured")
	}
	if len(resp.ActiveRemoteKills) != 1 || resp.ActiveRemoteKills[0].MessageID != "kill-1" {
		t.Fatalf("active kills = %+v, want 1 kill-1", resp.ActiveRemoteKills)
	}
	if resp.ActiveRemoteKills[0].State != conductor.KillSwitchActive {
		t.Fatalf("kill state = %q, want active", resp.ActiveRemoteKills[0].State)
	}
	if len(resp.ActiveRollbacks) != 1 || resp.ActiveRollbacks[0].AuthorizationID != "rollback-1" {
		t.Fatalf("active rollbacks = %+v, want 1 rollback-1", resp.ActiveRollbacks)
	}
	// The rollback authorization view must expose the validity-window start
	// (created_at), populated from the source RollbackAuthorization.CreatedAt,
	// so an operator can compute the window. The fixture was created at testNow.
	if got := resp.ActiveRollbacks[0].CreatedAt; !got.Equal(testNow) {
		t.Fatalf("rollback created_at = %s, want %s", got, testNow)
	}
}

func TestHandlerStreamStatusDropsExpiredAndOutOfScopeEmergencyControls(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)
	emergency := mustEmergencyStore(t)

	// An active kill, but published long ago so it is expired at testNow.
	expired, expiredResolver := signedRemoteKillMessageWithResolver(t, "kill-expired", 1, conductor.KillSwitchActive, testNow.Add(-48*time.Hour))
	if _, _, err := emergency.PublishRemoteKill(t.Context(), expired, testNow.Add(-48*time.Hour)); err != nil {
		t.Fatalf("PublishRemoteKill(expired) error = %v", err)
	}

	// Trust the signer so the record is dropped for expiry/scope, not quarantine.
	handler := newStreamStatusTestHandler(t, store, emergency, expiredResolver)

	// signedRemoteKillMessage's default scope is org "org-main" / fleet "prod".
	// Query a different fleet: the kill is org-main/prod, so a prod-mismatched
	// fleet scope must not surface it (and the expiry also drops it).
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main&fleet_id=staging", streamAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp streamStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.ActiveRemoteKills) != 0 {
		t.Fatalf("active kills = %+v, want 0 (expired + out of scope)", resp.ActiveRemoteKills)
	}
}

func TestHandlerStreamStatusDropsInactiveRemoteKill(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)
	emergency := mustEmergencyStore(t)

	inactive, inactiveResolver := signedRemoteKillMessageWithResolver(t, "kill-inactive", 1, conductor.KillSwitchInactive, testNow)
	if _, _, err := emergency.PublishRemoteKill(t.Context(), inactive, testNow); err != nil {
		t.Fatalf("PublishRemoteKill(inactive) error = %v", err)
	}

	// Trust the signer so the record is dropped for inactive state, not quarantine.
	handler := newStreamStatusTestHandler(t, store, emergency, inactiveResolver)
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	var resp streamStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.ActiveRemoteKills) != 0 {
		t.Fatalf("active kills = %+v, want 0 for inactive kill-switch message", resp.ActiveRemoteKills)
	}
	if !resp.EmergencyControlsRead {
		t.Fatal("EmergencyControlsRead = false, want true with enumerable emergency store")
	}
}

func TestHandlerStreamStatusAuthAndMethodNegatives(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)
	handler := newStreamStatusTestHandler(t, store, nil)

	t.Run("no token", func(t *testing.T) {
		w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", "")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
	})

	t.Run("cross-org scope rejected", func(t *testing.T) {
		// org-other admin token may not enumerate org-main streams.
		w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamOtherOrgToken)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d body=%s, want 403", w.Code, w.Body.String())
		}
	})

	t.Run("unknown token rejected", func(t *testing.T) {
		w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", "nope")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
	})

	t.Run("missing org rejected", func(t *testing.T) {
		w := getStreamStatus(t, handler, StreamStatusPath, streamAdminToken)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("unknown query param rejected", func(t *testing.T) {
		w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main&evil=1", streamAdminToken)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("duplicate query param rejected", func(t *testing.T) {
		w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main&org_id=org-other", streamAdminToken)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, StreamStatusPath+"?org_id=org-main", bytes.NewReader(nil))
		req.Header.Set("Authorization", "Bearer "+streamAdminToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", w.Code)
		}
	})
}

func TestHandlerStreamStatusFailClosedWithoutAuthorizer(t *testing.T) {
	// NewHandler with no AuthorizeStream installs a deny-all default.
	store := mustStore(t)
	publishStreamFixture(t, store)
	handler, err := NewHandler(HandlerOptions{
		Store:              store,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAdminToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (deny-all default authorizer)", w.Code)
	}
}

func TestScopedBearerStreamStatusAuthorizerConstruction(t *testing.T) {
	t.Run("rejects empty-org admin", func(t *testing.T) {
		if _, err := ScopedBearerStreamStatusAuthorizer([]ScopedBearerCredential{
			{Token: "t", Role: RoleAdmin},
		}); !errors.Is(err, ErrStreamStatusForbidden) {
			t.Fatalf("error = %v, want ErrStreamStatusForbidden", err)
		}
	})
	t.Run("rejects empty-org auditor", func(t *testing.T) {
		if _, err := ScopedBearerStreamStatusAuthorizer([]ScopedBearerCredential{
			{Token: "t", Role: RoleAuditor},
		}); !errors.Is(err, ErrStreamStatusForbidden) {
			t.Fatalf("error = %v, want ErrStreamStatusForbidden", err)
		}
	})
	t.Run("rejects empty credential list", func(t *testing.T) {
		if _, err := ScopedBearerStreamStatusAuthorizer(nil); err == nil {
			t.Fatal("error = nil, want forbidden on empty creds")
		}
	})
	t.Run("accepts scoped admin", func(t *testing.T) {
		if _, err := ScopedBearerStreamStatusAuthorizer([]ScopedBearerCredential{
			{Token: "t", Role: RoleAdmin, OrgID: "org-main"},
		}); err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
	})
}

func TestScopedBearerStreamStatusAuthorizerScopeEnforcement(t *testing.T) {
	auth, err := ScopedBearerStreamStatusAuthorizer([]ScopedBearerCredential{
		{Token: "fleet-tok", Role: RoleAuditor, OrgID: "org-main", FleetID: "prod"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerStreamStatusAuthorizer() error = %v", err)
	}
	bearer := func(token string) *http.Request {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, StreamStatusPath, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return req
	}
	if err := auth(bearer("fleet-tok"), StreamStatusQuery{OrgID: "org-main", FleetID: "prod"}); err != nil {
		t.Fatalf("auth(in-scope) error = %v, want nil", err)
	}
	if err := auth(bearer("fleet-tok"), StreamStatusQuery{OrgID: "org-main", FleetID: "staging"}); !errors.Is(err, ErrStreamStatusForbidden) {
		t.Fatalf("auth(wrong fleet) error = %v, want ErrStreamStatusForbidden", err)
	}
	if err := auth(bearer("fleet-tok"), StreamStatusQuery{OrgID: "org-other", FleetID: "prod"}); !errors.Is(err, ErrStreamStatusForbidden) {
		t.Fatalf("auth(wrong org) error = %v, want ErrStreamStatusForbidden", err)
	}
	if err := auth(bearer("unknown"), StreamStatusQuery{OrgID: "org-main", FleetID: "prod"}); !errors.Is(err, ErrStreamStatusForbidden) {
		t.Fatalf("auth(unknown token) error = %v, want ErrStreamStatusForbidden", err)
	}
}

func TestIsAuthConfigErrorIncludesStreamStatus(t *testing.T) {
	if !IsAuthConfigError(ErrStreamStatusForbidden) {
		t.Fatal("IsAuthConfigError(ErrStreamStatusForbidden) = false, want true")
	}
}

func TestRemoteKillsNilReceiver(t *testing.T) {
	var store *FileEmergencyStore
	if _, err := store.enumerateRemoteKills(context.Background()); !errors.Is(err, ErrEmergencyStoreRequired) {
		t.Fatalf("RemoteKills(nil) error = %v, want ErrEmergencyStoreRequired", err)
	}
}

// streamErrorStore satisfies BundleStore but fails StreamOverview, exercising
// the handler's store-error path (mapped to 500 via writeStoreError).
type streamErrorStore struct{ fakeStore }

func (streamErrorStore) StreamOverview(context.Context, StreamStatusQuery) ([]StreamSummary, error) {
	return nil, errors.New("stream overview boom")
}

// erroringEmergencyStore satisfies EmergencyStore and the enumerator interfaces
// but fails enumeration, exercising the handler's emergency-read error path.
type erroringEmergencyStore struct{ failingEmergencyStore }

func (erroringEmergencyStore) RemoteKills(context.Context) ([]StoredRemoteKill, error) {
	return nil, errors.New("remote kills boom")
}

func (erroringEmergencyStore) RollbackAuthorizations(context.Context) ([]StoredRollbackAuthorization, error) {
	return nil, errors.New("rollback enum boom")
}

func newLoggingStreamHandler(t *testing.T, store BundleStore, emergency EmergencyStore, logBuf *bytes.Buffer) *Handler {
	t.Helper()
	streamAuth, err := ScopedBearerStreamStatusAuthorizer([]ScopedBearerCredential{
		{Token: streamAdminToken, Role: RoleAdmin, OrgID: "org-main"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerStreamStatusAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              store,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeStream:    streamAuth,
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		EmergencyControls:  emergency,
		Logger:             slog.New(slog.NewJSONHandler(logBuf, nil)),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func TestHandlerStreamStatusStoreErrorLogsAndFailsClosed(t *testing.T) {
	var logBuf bytes.Buffer
	handler := newLoggingStreamHandler(t, streamErrorStore{}, nil, &logBuf)
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAdminToken)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s, want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal server error") {
		t.Fatalf("body = %s, want generic internal server error", w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "conductor_stream_overview_failed") {
		t.Fatalf("log missing stream overview failure event: %s", logBuf.String())
	}
}

func TestHandlerStreamStatusEmergencyReadErrorLogsAndFailsClosed(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)
	var logBuf bytes.Buffer
	handler := newLoggingStreamHandler(t, store, erroringEmergencyStore{}, &logBuf)
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAdminToken)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s, want 500", w.Code, w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "conductor_stream_emergency_read_failed") {
		t.Fatalf("log missing emergency read failure event: %s", logBuf.String())
	}
}

// rollbackOnlyErrorEmergencyStore enumerates remote kills successfully but fails
// rollback enumeration, exercising the second enumerator error branch in
// activeEmergencyControls.
type rollbackOnlyErrorEmergencyStore struct{ failingEmergencyStore }

func (rollbackOnlyErrorEmergencyStore) RemoteKills(context.Context) ([]StoredRemoteKill, error) {
	return nil, nil
}

func (rollbackOnlyErrorEmergencyStore) RollbackAuthorizations(context.Context) ([]StoredRollbackAuthorization, error) {
	return nil, errors.New("rollback enum boom")
}

func TestHandlerStreamStatusRollbackEnumErrorFailsClosed(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)
	var logBuf bytes.Buffer
	handler := newLoggingStreamHandler(t, store, rollbackOnlyErrorEmergencyStore{}, &logBuf)
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAdminToken)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s, want 500", w.Code, w.Body.String())
	}
}

func TestHandlerStreamStatusRejectsInvalidIdentifiers(t *testing.T) {
	store := mustStore(t)
	publishStreamFixture(t, store)
	handler := newStreamStatusTestHandler(t, store, nil)
	cases := []struct {
		name   string
		target string
	}{
		// These identifiers pass the allowlist (known keys) but fail
		// conductor.ValidateIdentifier, exercising the parse validation branches.
		{"invalid org", StreamStatusPath + "?org_id=" + "%2e%2e"},
		{"invalid fleet", StreamStatusPath + "?org_id=org-main&fleet_id=" + "%2e%2e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := getStreamStatus(t, handler, tc.target, streamAdminToken)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s, want 400", w.Code, w.Body.String())
			}
		})
	}
}

func TestLogStreamStatusFailureNilLogger(t *testing.T) {
	// A handler with no logger must not panic when the failure log helper runs.
	store := mustStore(t)
	publishStreamFixture(t, store)
	handler := newStreamStatusTestHandler(t, streamErrorStore{}, nil)
	w := getStreamStatus(t, handler, StreamStatusPath+"?org_id=org-main", streamAdminToken)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestEmergencyInScope(t *testing.T) {
	q := StreamStatusQuery{OrgID: "org-main", FleetID: "prod"}
	if !emergencyInScope("org-main", "prod", q) {
		t.Fatal("emergencyInScope(match) = false, want true")
	}
	if emergencyInScope("org-other", "prod", q) {
		t.Fatal("emergencyInScope(wrong org) = true, want false")
	}
	if emergencyInScope("org-main", "staging", q) {
		t.Fatal("emergencyInScope(wrong fleet) = true, want false")
	}
	// Empty fleet in query matches any fleet within the org.
	if !emergencyInScope("org-main", "anything", StreamStatusQuery{OrgID: "org-main"}) {
		t.Fatal("emergencyInScope(any fleet) = false, want true")
	}
}
