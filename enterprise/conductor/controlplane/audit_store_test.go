//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
)

const (
	testAuditBatchID  = "audit-batch-1"
	testAuditKeyID    = "audit-key-1"
	testAuditPayload  = `{"event":"ok"}`
	testAuditPayload2 = `{"event":"two"}`
)

func TestSQLiteAuditStoreIngestsQueriesAndDeduplicates(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "audit.db")
	store := openTestSQLiteAuditStore(t, storePath)
	defer func() { _ = store.Close() }()

	batch := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), testAuditBatchID, 10, 10, []byte(testAuditPayload), testNow)
	summary, err := store.put(context.Background(), batch)
	if err != nil {
		t.Fatalf("put() error = %v", err)
	}
	if summary.BatchID != testAuditBatchID || summary.EnvelopeHash != batch.EnvelopeHash || summary.PayloadBytes != uint64(len(batch.Payload)) {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.SignatureKeyIDs) != 1 || summary.SignatureKeyIDs[0] != testAuditKeyID {
		t.Fatalf("signature key ids = %#v", summary.SignatureKeyIDs)
	}

	if _, err := store.put(context.Background(), batch); err != nil {
		t.Fatalf("duplicate put() error = %v", err)
	}
	results, err := store.ListAuditBatches(context.Background(), AuditBatchQuery{
		OrgID:      batch.Identity.OrgID,
		FleetID:    batch.Identity.FleetID,
		InstanceID: batch.Identity.InstanceID,
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("ListAuditBatches() error = %v", err)
	}
	if len(results) != 1 || results[0].BatchID != batch.Envelope.BatchID {
		t.Fatalf("results = %#v", results)
	}
	got, ok, err := store.GetAuditBatch(context.Background(), batch.Identity.OrgID, batch.Identity.FleetID, batch.Identity.InstanceID, batch.Envelope.BatchID)
	if err != nil {
		t.Fatalf("GetAuditBatch() error = %v", err)
	}
	if !ok || got.EnvelopeHash != batch.EnvelopeHash {
		t.Fatalf("GetAuditBatch() = %+v ok=%v", got, ok)
	}

	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("Stat(store) error = %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("store mode = %v, want 0600", gotMode)
	}
}

func TestSQLiteAuditStoreRejectsConflictingBatchID(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	first := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), testAuditBatchID, 10, 10, []byte(`{"event":"one"}`), testNow)
	if _, err := store.put(context.Background(), first); err != nil {
		t.Fatalf("first put() error = %v", err)
	}
	conflict := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), testAuditBatchID, 10, 10, []byte(testAuditPayload2), testNow)
	if _, err := store.put(context.Background(), conflict); !errors.Is(err, ErrAuditBatchConflict) {
		t.Fatalf("conflicting put() error = %v, want ErrAuditBatchConflict", err)
	}
}

func TestSQLiteAuditStoreDetectsSequenceFork(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	first := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), testAuditBatchID, 10, 12, []byte(`{"event":"one"}`), testNow)
	if _, err := store.put(context.Background(), first); err != nil {
		t.Fatalf("first put() error = %v", err)
	}
	fork := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), "audit-batch-2", 11, 13, []byte(testAuditPayload2), testNow.Add(time.Second))
	if _, err := store.put(context.Background(), fork); !errors.Is(err, ErrAuditForkDetected) {
		t.Fatalf("fork put() error = %v, want ErrAuditForkDetected", err)
	}
	nonOverlapping := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), "audit-batch-3", 13, 13, []byte(`{"event":"three"}`), testNow.Add(2*time.Second))
	if _, err := store.put(context.Background(), nonOverlapping); err != nil {
		t.Fatalf("non-overlap put() error = %v", err)
	}
}

func TestSQLiteAuditStoreReturnsExistingSummaryOnIdempotentRetry(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	batch := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), testAuditBatchID, 10, 10, []byte(testAuditPayload), testNow)
	first, err := store.put(context.Background(), batch)
	if err != nil {
		t.Fatalf("first put() error = %v", err)
	}
	second, err := store.put(context.Background(), batch)
	if err != nil {
		t.Fatalf("idempotent put() error = %v", err)
	}
	if second.BatchID != first.BatchID || second.EnvelopeHash != first.EnvelopeHash || second.SeqStart != first.SeqStart {
		t.Fatalf("idempotent summary diverged: first=%+v second=%+v", first, second)
	}
}

func TestSQLiteAuditStoreListOrdersAndLimits(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	identity := defaultFollowerIdentity()
	for i := 0; i < 3; i++ {
		seq := uint64(10 + i)
		batch := signedAcceptedAuditBatch(t, identity, "batch-"+strconv.Itoa(i), seq, seq, []byte(testAuditPayload), testNow.Add(time.Duration(i)*time.Second))
		if _, err := store.put(context.Background(), batch); err != nil {
			t.Fatalf("put(%d) error = %v", i, err)
		}
	}
	all, err := store.ListAuditBatches(context.Background(), AuditBatchQuery{OrgID: identity.OrgID, Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditBatches() error = %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	// received_at DESC: the most recent batch (index 2) lands first.
	if all[0].BatchID != "batch-2" || all[2].BatchID != "batch-0" {
		t.Fatalf("ordering wrong: %s, %s, %s", all[0].BatchID, all[1].BatchID, all[2].BatchID)
	}
	clipped, err := store.ListAuditBatches(context.Background(), AuditBatchQuery{OrgID: identity.OrgID, Limit: 2})
	if err != nil {
		t.Fatalf("ListAuditBatches(limit=2) error = %v", err)
	}
	if len(clipped) != 2 {
		t.Fatalf("clipped len = %d, want 2", len(clipped))
	}
}

func TestSQLiteAuditStoreGetMissingBatch(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	_, ok, err := store.GetAuditBatch(context.Background(), "org-main", "prod", "pl-prod-1", "missing")
	if err != nil {
		t.Fatalf("GetAuditBatch(missing) error = %v", err)
	}
	if ok {
		t.Fatal("GetAuditBatch(missing) ok = true, want false")
	}
}

func TestSQLiteAuditStorePrunesBatchesBeforeCutoff(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	identity := defaultFollowerIdentity()
	oldBatch := signedAcceptedAuditBatch(t, identity, "audit-old", 10, 10, []byte(testAuditPayload), testNow.Add(-48*time.Hour))
	recentBatch := signedAcceptedAuditBatch(t, identity, "audit-recent", 11, 11, []byte(testAuditPayload2), testNow.Add(-time.Hour))
	if err := store.IngestAuditBatch(context.Background(), oldBatch); err != nil {
		t.Fatalf("IngestAuditBatch(old) error = %v", err)
	}
	if err := store.IngestAuditBatch(context.Background(), recentBatch); err != nil {
		t.Fatalf("IngestAuditBatch(recent) error = %v", err)
	}

	result, err := store.PruneAuditBatchesBefore(context.Background(), testNow.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PruneAuditBatchesBefore() error = %v", err)
	}
	if result.Deleted != 1 || !result.Before.Equal(testNow.Add(-24*time.Hour)) {
		t.Fatalf("prune result = %+v, want one deleted before cutoff", result)
	}
	if _, ok, err := store.GetAuditBatch(context.Background(), identity.OrgID, identity.FleetID, identity.InstanceID, oldBatch.Envelope.BatchID); err != nil || ok {
		t.Fatalf("GetAuditBatch(old) ok=%v err=%v, want pruned", ok, err)
	}
	if _, ok, err := store.GetAuditBatch(context.Background(), identity.OrgID, identity.FleetID, identity.InstanceID, recentBatch.Envelope.BatchID); err != nil || !ok {
		t.Fatalf("GetAuditBatch(recent) ok=%v err=%v, want retained", ok, err)
	}

	result, err = store.PruneAuditBatchesBefore(context.Background(), testNow.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PruneAuditBatchesBefore(second) error = %v", err)
	}
	if result.Deleted != 0 {
		t.Fatalf("second prune deleted = %d, want 0", result.Deleted)
	}
}

func TestSQLiteAuditStoreRejectsNilContext(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	var nilCtx context.Context
	batch := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), testAuditBatchID, 10, 10, []byte(testAuditPayload), testNow)
	if _, err := OpenSQLiteAuditStore(nilCtx, filepath.Join(t.TempDir(), "audit.db")); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("OpenSQLiteAuditStore(nil) error = %v, want ErrAuditSinkRequired", err)
	}
	if err := store.IngestAuditBatch(nilCtx, batch); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("IngestAuditBatch(nil) error = %v, want ErrAuditSinkRequired", err)
	}
	if _, err := store.ListAuditBatches(nilCtx, AuditBatchQuery{}); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("ListAuditBatches(nil) error = %v, want ErrAuditSinkRequired", err)
	}
	if _, _, err := store.GetAuditBatch(nilCtx, batch.Identity.OrgID, batch.Identity.FleetID, batch.Identity.InstanceID, batch.Envelope.BatchID); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("GetAuditBatch(nil) error = %v, want ErrAuditSinkRequired", err)
	}
	if _, err := store.PruneAuditBatchesBefore(nilCtx, testNow); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("PruneAuditBatchesBefore(nil) error = %v, want ErrAuditSinkRequired", err)
	}
	var nilStore *SQLiteAuditStore
	if _, err := nilStore.PruneAuditBatchesBefore(context.Background(), testNow); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("PruneAuditBatchesBefore(nil store) error = %v, want ErrAuditSinkRequired", err)
	}
	if _, err := store.PruneAuditBatchesBefore(context.Background(), time.Time{}); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("PruneAuditBatchesBefore(zero cutoff) error = %v, want ErrInvalidStoreRecord", err)
	}
}

func TestSQLiteAuditStorePruneReturnsExecError(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, err := store.PruneAuditBatchesBefore(context.Background(), testNow)
	if err == nil || !strings.Contains(err.Error(), "prune conductor audit batches") {
		t.Fatalf("PruneAuditBatchesBefore(closed) error = %v, want prune error", err)
	}
}

func TestSQLiteAuditStoreRevalidatesAcceptedBatchBoundary(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*AcceptedAuditBatch)
		wantErr error
	}{
		{
			name: "identity mismatch",
			mutate: func(batch *AcceptedAuditBatch) {
				batch.Identity.OrgID = "other"
			},
			wantErr: conductor.ErrAudienceMismatch,
		},
		{
			name: "bad envelope hash format",
			mutate: func(batch *AcceptedAuditBatch) {
				batch.EnvelopeHash = "bad"
			},
			wantErr: ErrInvalidStoreRecord,
		},
		{
			name: "canonical envelope hash mismatch",
			mutate: func(batch *AcceptedAuditBatch) {
				batch.EnvelopeHash = strings.Repeat("a", sha256.Size*2)
			},
			wantErr: ErrInvalidStoreRecord,
		},
		{
			name: "payload hash mismatch",
			mutate: func(batch *AcceptedAuditBatch) {
				batch.Payload = []byte(`{"event":"tampered"}`)
			},
			wantErr: conductor.ErrHashMismatch,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
			defer func() { _ = store.Close() }()

			batch := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), testAuditBatchID, 10, 10, []byte(testAuditPayload), testNow)
			c.mutate(&batch)
			if err := store.IngestAuditBatch(context.Background(), batch); !errors.Is(err, c.wantErr) {
				t.Fatalf("IngestAuditBatch() error = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestAuditIngestSurfacesSinkErrorsAsHTTP verifies that sink-level errors
// reach the wire as the right HTTP status (not the previous catch-all 500).
// Permanent rejections (batch_id conflict, sequence fork) MUST land as 409 so
// followers stop retrying; the old behavior of returning 500 made these
// indistinguishable from transient failures.
func TestAuditIngestSurfacesSinkErrorsAsHTTP(t *testing.T) {
	pub, priv := testAuditSigner(t)
	payload := []byte(testAuditPayload)
	cases := []struct {
		name     string
		sinkErr  error
		wantCode int
	}{
		{"conflict", ErrAuditBatchConflict, 409},
		{"fork", ErrAuditForkDetected, 409},
		{"audience mismatch", conductor.ErrAudienceMismatch, 403},
		{"invalid store record", ErrInvalidStoreRecord, 400},
		{"payload too large", conductor.ErrPayloadTooLarge, 413},
		{"hash mismatch", conductor.ErrHashMismatch, 422},
		{"expired", conductor.ErrExpired, 422},
		{"unclassified", errors.New("disk full"), 500},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sink := &captureAuditSink{err: c.sinkErr}
			handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)
			req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)
			w := postAuditBatch(t, handler, req)
			if w.Code != c.wantCode {
				t.Fatalf("sink err %q -> %d, want %d (body=%s)", c.sinkErr, w.Code, c.wantCode, w.Body.String())
			}
		})
	}
}

func TestHandlerListsAuditBatchSummaries(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()

	identity := defaultFollowerIdentity()
	first := signedAcceptedAuditBatch(t, identity, testAuditBatchID, 10, 10, []byte(testAuditPayload), testNow)
	second := signedAcceptedAuditBatch(t, identity, "audit-batch-2", 11, 11, []byte(testAuditPayload2), testNow.Add(time.Second))
	if err := store.IngestAuditBatch(context.Background(), first); err != nil {
		t.Fatalf("IngestAuditBatch(first) error = %v", err)
	}
	if err := store.IngestAuditBatch(context.Background(), second); err != nil {
		t.Fatalf("IngestAuditBatch(second) error = %v", err)
	}
	handler := newAuditQueryTestHandler(t, store)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"?org_id=org-main&fleet_id=prod&limit=1", nil)
	req.Header.Set("X-Pipelock-Auditor", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "payload_blob") || strings.Contains(w.Body.String(), testAuditPayload) {
		t.Fatalf("list response leaked raw payload data: %s", w.Body.String())
	}
	var got listAuditBatchesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if got.Count != 1 || len(got.Batches) != 1 {
		t.Fatalf("list count=%d len=%d, want 1", got.Count, len(got.Batches))
	}
	if got.Batches[0].BatchID != "audit-batch-2" || got.Batches[0].OrgID != identity.OrgID {
		t.Fatalf("list batch = %+v", got.Batches[0])
	}
}

// TestHandlerListsEmptyResultAsEmptyArray defends against future regressions
// where ListAuditBatches returns nil instead of an empty slice. Clients
// (operator UIs, CLI) parse the JSON `batches` field as an array; a `null`
// value crashes naive consumers. Pin the contract here.
func TestHandlerListsEmptyResultAsEmptyArray(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	handler := newAuditQueryTestHandler(t, store)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"?org_id=org-empty", nil)
	req.Header.Set("X-Pipelock-Auditor", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("empty list status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"batches":null`) {
		t.Fatalf("empty list emitted batches=null instead of []: %s", w.Body.String())
	}
	var got listAuditBatchesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode empty list: %v", err)
	}
	if got.Count != 0 || len(got.Batches) != 0 {
		t.Fatalf("empty list = %+v, want count=0", got)
	}
}

// TestHandlerListReturns501WhenSinkLacksQuerier locks the contract that a
// sink which only implements ingest and not query surfaces a permanent 501
// rather than a transient-looking 500. Operators learn it's a config gap,
// not a server-side fault to retry.
func TestHandlerListReturns501WhenSinkLacksQuerier(t *testing.T) {
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"?org_id=org-main", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d body=%s, want 501", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "audit query not supported") {
		t.Fatalf("501 body missing capability message: %s", w.Body.String())
	}
}

func TestHandlerListAuditBatchQueryValidation(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	handler := newAuditQueryTestHandler(t, store)

	cases := []struct {
		name       string
		target     string
		auditor    string
		wantStatus int
		wantBody   string
	}{
		{name: "auditor required", target: AuditBatchesPath + "?org_id=org-main", wantStatus: http.StatusForbidden, wantBody: ErrAuditQueryForbidden.Error()},
		{name: "org required", target: AuditBatchesPath, auditor: "ok", wantStatus: http.StatusBadRequest},
		{name: "invalid org", target: AuditBatchesPath + "?org_id=-org", auditor: "ok", wantStatus: http.StatusBadRequest},
		{name: "invalid limit", target: AuditBatchesPath + "?org_id=org-main&limit=0", auditor: "ok", wantStatus: http.StatusBadRequest},
		{name: "duplicate org", target: AuditBatchesPath + "?org_id=org-main&org_id=other", auditor: "ok", wantStatus: http.StatusBadRequest},
		{name: "unknown parameter", target: AuditBatchesPath + "?org_id=org-main&payload=true", auditor: "ok", wantStatus: http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, c.target, nil)
			if c.auditor != "" {
				req.Header.Set("X-Pipelock-Auditor", c.auditor)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != c.wantStatus {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), c.wantStatus)
			}
			if c.wantBody != "" && !strings.Contains(w.Body.String(), c.wantBody) {
				t.Fatalf("body = %s, want substring %q", w.Body.String(), c.wantBody)
			}
		})
	}
}

func TestHandlerListAuditBatchSurfacesSinkError(t *testing.T) {
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher:  func(*http.Request) error { return nil },
		AuthorizeAuditQuery: func(*http.Request, AuditBatchQuery) error { return nil },
		AuditSink:           failingAuditQuerySink{err: ErrAuditBatchConflict},
		AuditKeys:           rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"?org_id=org-main", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s, want 409", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), ErrAuditBatchConflict.Error()) {
		t.Fatalf("body = %s, want sink error", w.Body.String())
	}
}

func openTestSQLiteAuditStore(t *testing.T, path string) *SQLiteAuditStore {
	t.Helper()
	store, err := OpenSQLiteAuditStore(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenSQLiteAuditStore() error = %v", err)
	}
	return store
}

func newAuditQueryTestHandler(t *testing.T, auditStore *SQLiteAuditStore) *Handler {
	t.Helper()
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher: func(*http.Request) error {
			return errors.New("publisher authorizer must not authorize audit query")
		},
		AuthorizeAuditQuery: func(r *http.Request, _ AuditBatchQuery) error {
			if r.Header.Get("X-Pipelock-Auditor") == "ok" {
				return nil
			}
			return ErrAuditQueryForbidden
		},
		AuditSink: auditStore,
		AuditKeys: rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

type failingAuditQuerySink struct {
	err error
}

func (s failingAuditQuerySink) IngestAuditBatch(context.Context, AcceptedAuditBatch) error {
	return nil
}

func (s failingAuditQuerySink) ListAuditBatches(context.Context, AuditBatchQuery) ([]AuditBatchSummary, error) {
	return nil, s.err
}

func signedAcceptedAuditBatch(
	t *testing.T,
	identity FollowerIdentity,
	batchID string,
	seqStart uint64,
	seqEnd uint64,
	payload []byte,
	emittedAt time.Time,
) AcceptedAuditBatch {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(audit) error = %v", err)
	}
	recorderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(recorder) error = %v", err)
	}
	sum := sha256.Sum256(payload)
	envelope := conductor.AuditBatchEnvelope{
		SchemaVersion:      conductor.SchemaVersion,
		BatchID:            batchID,
		OrgID:              identity.OrgID,
		FleetID:            identity.FleetID,
		InstanceID:         identity.InstanceID,
		AuditSchemaVersion: conductor.SchemaVersion,
		EmittedAt:          emittedAt,
		SeqStart:           seqStart,
		SeqEnd:             seqEnd,
		EventCount:         seqEnd - seqStart + 1,
		PayloadSHA256:      hex.EncodeToString(sum[:]),
		PayloadBytes:       uint64(len(payload)),
		Dropped:            conductor.DroppedAccounting{},
		Chain: conductor.EvidenceChain{
			EntryVersion:           2,
			SegmentID:              "segment-1",
			SeqStart:               seqStart,
			SeqEnd:                 seqEnd,
			SegmentHeadHash:        auditStoreHash("head", batchID),
			SegmentTailHash:        auditStoreHash("tail", batchID),
			CheckpointSeq:          seqEnd,
			CheckpointHash:         auditStoreHash("checkpoint", batchID),
			CheckpointSignature:    conductor.SignaturePrefixEd25519 + strings.Repeat("a", 128),
			CheckpointSignerKeyID:  "receipt-key-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: hex.EncodeToString(recorderPub),
		},
	}
	signed, err := auditbatcher.SignEnvelope(envelope, testAuditKeyID, priv)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	envelopeHash, err := signed.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	return AcceptedAuditBatch{
		Identity:     identity,
		Envelope:     signed,
		EnvelopeHash: envelopeHash,
		Payload:      append([]byte(nil), payload...),
		ReceivedAt:   emittedAt.Add(time.Second),
	}
}

func auditStoreHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return hex.EncodeToString(sum[:])
}
