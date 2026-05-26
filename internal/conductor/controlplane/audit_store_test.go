// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/conductor/auditbatcher"
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

func openTestSQLiteAuditStore(t *testing.T, path string) *SQLiteAuditStore {
	t.Helper()
	store, err := OpenSQLiteAuditStore(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenSQLiteAuditStore() error = %v", err)
	}
	return store
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
