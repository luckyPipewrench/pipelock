//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
)

type heartbeatSinkStub struct {
	status AppliedStateHeartbeatStatus
	err    error
}

func (s heartbeatSinkStub) IngestAuditBatch(context.Context, AcceptedAuditBatch) (AuditIngestResult, error) {
	return AuditIngestResult{}, nil
}

func (s heartbeatSinkStub) IngestAppliedStateHeartbeat(context.Context, AcceptedAppliedStateHeartbeat) (AppliedStateHeartbeatStatus, error) {
	return s.status, s.err
}

func signedAppliedStateHeartbeat(t *testing.T, identity FollowerIdentity, priv ed25519.PrivateKey, id string, observed time.Time) conductor.AppliedStateHeartbeat {
	t.Helper()
	state := validTestAppliedState(observed)
	state.ProvenanceAt = observed
	heartbeat, err := auditbatcher.SignAppliedStateHeartbeat(conductor.AppliedStateHeartbeat{
		SchemaVersion: conductor.SchemaVersion,
		HeartbeatID:   id,
		OrgID:         identity.OrgID,
		FleetID:       identity.FleetID,
		InstanceID:    identity.InstanceID,
		EmittedAt:     observed,
		AppliedState:  state,
	}, "audit-key-1", priv)
	if err != nil {
		t.Fatalf("SignAppliedStateHeartbeat() error = %v", err)
	}
	return heartbeat
}

func postAppliedStateHeartbeat(t *testing.T, handler *Handler, heartbeat conductor.AppliedStateHeartbeat) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("Marshal(heartbeat) error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AppliedStateHeartbeatPath, strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestAppliedStateHeartbeat_EndToEndReplayAndRestart(t *testing.T) {
	pub, priv := testAuditSigner(t)
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store := openTestSQLiteAuditStore(t, dbPath)
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	identity := defaultFollowerIdentity()
	first := signedAppliedStateHeartbeat(t, identity, priv, "state-1", testNow.Add(-30*time.Second))

	if w := postAppliedStateHeartbeat(t, handler, first); w.Code != http.StatusAccepted {
		t.Fatalf("first heartbeat code = %d body=%s", w.Code, w.Body.String())
	}
	stored, ok, err := store.GetVerifiedAppliedState(context.Background(), identity.OrgID, identity.FleetID, identity.InstanceID)
	if err != nil || !ok {
		t.Fatalf("GetVerifiedAppliedState() = ok %v err %v", ok, err)
	}
	if stored.BatchID != first.HeartbeatID || !stored.Verified || !stored.AppliedState.ProvenanceAt.Equal(first.AppliedState.ProvenanceAt) {
		t.Fatalf("stored heartbeat = %+v", stored)
	}

	if w := postAppliedStateHeartbeat(t, handler, first); w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"status":"duplicate"`) {
		t.Fatalf("duplicate heartbeat code = %d body=%s", w.Code, w.Body.String())
	}
	older := signedAppliedStateHeartbeat(t, identity, priv, "state-old", testNow.Add(-40*time.Second))
	if w := postAppliedStateHeartbeat(t, handler, older); w.Code != http.StatusConflict {
		t.Fatalf("older replay code = %d body=%s, want 409", w.Code, w.Body.String())
	}
	sameTime := signedAppliedStateHeartbeat(t, identity, priv, "state-divergent", first.AppliedState.ObservedAt)
	sameTime.AppliedState.ActiveBundleID = "bundle-divergent"
	sameTime, err = auditbatcher.SignAppliedStateHeartbeat(sameTime, "audit-key-1", priv)
	if err != nil {
		t.Fatalf("resign divergent heartbeat: %v", err)
	}
	if w := postAppliedStateHeartbeat(t, handler, sameTime); w.Code != http.StatusConflict {
		t.Fatalf("same-time divergent heartbeat code = %d body=%s, want 409", w.Code, w.Body.String())
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened := openTestSQLiteAuditStore(t, dbPath)
	restartedHandler := newAuditIngestTestHandler(t, reopened, auditKeyResolverFor(pub), 0)
	if w := postAppliedStateHeartbeat(t, restartedHandler, older); w.Code != http.StatusConflict {
		t.Fatalf("post-restart replay code = %d body=%s, want 409", w.Code, w.Body.String())
	}
	newer := signedAppliedStateHeartbeat(t, identity, priv, "state-2", testNow.Add(-10*time.Second))
	if w := postAppliedStateHeartbeat(t, restartedHandler, newer); w.Code != http.StatusAccepted {
		t.Fatalf("post-restart newer code = %d body=%s", w.Code, w.Body.String())
	}
}

func TestAppliedStateHeartbeat_FailsClosedOnIdentitySignatureAndSkew(t *testing.T) {
	pub, priv := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	identity := defaultFollowerIdentity()

	spoofed := signedAppliedStateHeartbeat(t, identity, priv, "state-spoof", testNow)
	spoofed.InstanceID = "another-follower"
	spoofed, _ = auditbatcher.SignAppliedStateHeartbeat(spoofed, "audit-key-1", priv)
	if w := postAppliedStateHeartbeat(t, handler, spoofed); w.Code != http.StatusForbidden {
		t.Fatalf("spoofed identity code = %d body=%s, want 403", w.Code, w.Body.String())
	}

	_, wrongPriv := testAuditSigner(t)
	wrongKey := signedAppliedStateHeartbeat(t, identity, wrongPriv, "state-wrong-key", testNow)
	if w := postAppliedStateHeartbeat(t, handler, wrongKey); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong signature code = %d body=%s, want 401", w.Code, w.Body.String())
	}

	stale := signedAppliedStateHeartbeat(t, identity, priv, "state-stale", testNow.Add(-2*conductor.DefaultAuditMaxSkew))
	if w := postAppliedStateHeartbeat(t, handler, stale); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("stale heartbeat code = %d body=%s, want 422", w.Code, w.Body.String())
	}
}

func TestAppliedStateHeartbeat_DisabledWhenCapabilityRangeStopsAtV2(t *testing.T) {
	pub, priv := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	handler.capabilities.AuditBatch.Max = conductor.AuditEnvelopeSchemaVersion
	heartbeat := signedAppliedStateHeartbeat(t, defaultFollowerIdentity(), priv, "state-v2", testNow)
	if w := postAppliedStateHeartbeat(t, handler, heartbeat); w.Code != http.StatusNotImplemented {
		t.Fatalf("v2-only conductor heartbeat code = %d body=%s, want 501", w.Code, w.Body.String())
	}
}

func TestAppliedStateHeartbeat_HandlerErrors(t *testing.T) {
	pub, priv := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)

	for _, tc := range []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "method", method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "malformed_json", method: http.MethodPost, body: `{`, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), tc.method, AppliedStateHeartbeatPath, strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tc.want)
			}
		})
	}

	withoutSink := newAuditIngestTestHandler(t, discardAuditSink{}, auditKeyResolverFor(pub), 0)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AppliedStateHeartbeatPath, strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	withoutSink.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("missing sink status = %d body=%s, want 501", w.Code, w.Body.String())
	}

	limited := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 8)
	limited.maxRequestBody = 1
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, AppliedStateHeartbeatPath, strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	limited.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d body=%s, want 413", w.Code, w.Body.String())
	}

	identityFailure := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	identityFailure.followerIdentity = func(*http.Request) (FollowerIdentity, error) {
		return FollowerIdentity{}, errors.New("identity unavailable")
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, AppliedStateHeartbeatPath, strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	identityFailure.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("identity failure status = %d body=%s, want 401", w.Code, w.Body.String())
	}

	heartbeat := signedAppliedStateHeartbeat(t, defaultFollowerIdentity(), priv, "state-sink-error", testNow)
	for _, tc := range []struct {
		name string
		sink heartbeatSinkStub
		want int
	}{
		{name: "sink_error", sink: heartbeatSinkStub{err: errors.New("sink failed")}, want: http.StatusInternalServerError},
		{name: "empty_status_defaults", sink: heartbeatSinkStub{}, want: http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuditIngestTestHandler(t, tc.sink, auditKeyResolverFor(pub), 0)
			got := postAppliedStateHeartbeat(t, h, heartbeat)
			if got.Code != tc.want {
				t.Fatalf("status = %d body=%s, want %d", got.Code, got.Body.String(), tc.want)
			}
		})
	}
}

func TestAppliedStateHeartbeat_StoreRejectsInvalidAcceptedRecords(t *testing.T) {
	identity := defaultFollowerIdentity()
	_, priv := testAuditSigner(t)
	heartbeat := signedAppliedStateHeartbeat(t, identity, priv, "state-store-errors", testNow)
	hash, err := heartbeat.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	accepted := AcceptedAppliedStateHeartbeat{
		Identity:      identity,
		Heartbeat:     heartbeat,
		HeartbeatHash: hash,
		ReceivedAt:    testNow,
	}
	var nilStore *SQLiteAuditStore
	if _, err := nilStore.IngestAppliedStateHeartbeat(context.Background(), accepted); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("nil store error = %v, want ErrAuditSinkRequired", err)
	}
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	var missingContext context.Context
	if _, err := store.IngestAppliedStateHeartbeat(missingContext, accepted); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("missing context error = %v, want ErrAuditSinkRequired", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.IngestAppliedStateHeartbeat(canceled, accepted); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want context.Canceled", err)
	}
	mismatched := accepted
	mismatched.Identity.InstanceID = "another-instance"
	if _, err := store.IngestAppliedStateHeartbeat(context.Background(), mismatched); !errors.Is(err, conductor.ErrAudienceMismatch) {
		t.Fatalf("identity mismatch error = %v, want ErrAudienceMismatch", err)
	}
	badHash := accepted
	badHash.HeartbeatHash = strings.Repeat("0", 64)
	if _, err := store.IngestAppliedStateHeartbeat(context.Background(), badHash); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("hash mismatch error = %v, want ErrInvalidStoreRecord", err)
	}

	stale := accepted
	stale.ReceivedAt = testNow.Add(2 * conductor.DefaultAuditMaxSkew)
	if _, err := store.IngestAppliedStateHeartbeat(context.Background(), stale); !errors.Is(err, conductor.ErrSkewExceeded) {
		t.Fatalf("stale heartbeat error = %v, want ErrSkewExceeded", err)
	}

	closed := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "closed.db"))
	if err := closed.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := closed.IngestAppliedStateHeartbeat(context.Background(), accepted); err == nil {
		t.Fatal("closed store ingest = nil error")
	}
	broken := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "broken.db"))
	if _, err := broken.db.ExecContext(context.Background(), `DROP TABLE verified_applied_state`); err != nil {
		t.Fatalf("drop verified_applied_state: %v", err)
	}
	if _, err := broken.IngestAppliedStateHeartbeat(context.Background(), accepted); err == nil {
		t.Fatal("missing table ingest = nil error")
	}

	freshNow := time.Now().UTC()
	freshHeartbeat := signedAppliedStateHeartbeat(t, identity, priv, "state-zero-received", freshNow)
	freshHash, err := freshHeartbeat.CanonicalHash()
	if err != nil {
		t.Fatalf("fresh CanonicalHash: %v", err)
	}
	if status, err := store.IngestAppliedStateHeartbeat(context.Background(), AcceptedAppliedStateHeartbeat{
		Identity:      identity,
		Heartbeat:     freshHeartbeat,
		HeartbeatHash: freshHash,
	}); err != nil || status != AppliedStateHeartbeatAccepted {
		t.Fatalf("zero ReceivedAt ingest = %q, %v", status, err)
	}
}
