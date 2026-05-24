// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package auditbatcher

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
)

func TestQueueEnqueueClaimAckRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{MaxPending: 4})
	batch := signedTestBatch(t, "batch-roundtrip", priv)

	id, err := q.Enqueue(batch)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if !strings.HasSuffix(id, recordExt) {
		t.Fatalf("id = %q, want %q suffix", id, recordExt)
	}
	assertStats(t, q, Stats{Pending: 1})

	lease, err := q.Claim()
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if lease.ID != id {
		t.Fatalf("lease.ID = %q, want %q", lease.ID, id)
	}
	if string(lease.Batch.Payload) != string(batch.Payload) {
		t.Fatalf("payload = %q, want %q", lease.Batch.Payload, batch.Payload)
	}
	assertStats(t, q, Stats{Inflight: 1})

	if err := q.Ack(id); err != nil {
		t.Fatalf("Ack() error = %v", err)
	}
	assertStats(t, q, Stats{})
}

func TestQueuePersistsAcrossOpen(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	batch := signedTestBatch(t, "batch-persist", priv)
	if _, err := q.Enqueue(batch); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	lease, err := reopened.Claim()
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if lease.Batch.Envelope.BatchID != "batch-persist" {
		t.Fatalf("BatchID = %q, want batch-persist", lease.Batch.Envelope.BatchID)
	}
}

func TestQueueReleaseAndRecoverInflight(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	id, err := q.Enqueue(signedTestBatch(t, "batch-release", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if err := q.Release(id); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	assertStats(t, q, Stats{Pending: 1})

	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim(second) error = %v", err)
	}
	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	assertStats(t, reopened, Stats{Pending: 1})
}

func TestQueueFull(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{MaxPending: 1})
	if _, err := q.Enqueue(signedTestBatch(t, "batch-full-1", priv)); err != nil {
		t.Fatalf("Enqueue(first) error = %v", err)
	}
	_, err = q.Enqueue(signedTestBatch(t, "batch-full-2", priv))
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("Enqueue(second) = %v, want ErrQueueFull", err)
	}
}

func TestQueueRejectsInvalidPayloadHash(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	batch := signedTestBatch(t, "batch-bad-payload", priv)
	batch.Payload = []byte("tampered")

	_, err = q.Enqueue(batch)
	if !errors.Is(err, conductor.ErrHashMismatch) {
		t.Fatalf("Enqueue() = %v, want ErrHashMismatch", err)
	}
}

func TestQueueMovesCorruptRecordToDead(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	corruptID := "00000000000000000001-corrupt.json"
	deadSentinel := []byte(`{"version":1,"sentinel":"do-not-clobber-dead"}`)
	if err := os.WriteFile(filepath.Join(q.pendingDir, corruptID), []byte("{bad"), fileMode); err != nil {
		t.Fatalf("WriteFile(corrupt) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(q.deadDir, corruptID), deadSentinel, fileMode); err != nil {
		t.Fatalf("WriteFile(existing dead) error = %v", err)
	}
	id, err := q.Enqueue(signedTestBatch(t, "batch-after-corrupt", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	lease, err := q.Claim()
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if lease.ID != id {
		t.Fatalf("Claimed %q, want valid id %q", lease.ID, id)
	}
	assertStats(t, q, Stats{Inflight: 1, Dead: 2})
	got, err := os.ReadFile(filepath.Join(q.deadDir, corruptID))
	if err != nil {
		t.Fatalf("ReadFile(existing dead) error = %v", err)
	}
	if string(got) != string(deadSentinel) {
		t.Fatalf("existing dead record was clobbered: got %q", got)
	}
	if _, err := os.Stat(filepath.Join(q.deadDir, "dead-"+corruptID)); err != nil {
		t.Fatalf("Stat(dead-<id>) error = %v; corrupt record should have used unique dead path", err)
	}
}

func TestQueueCreatesPrivateDirectoriesAndFiles(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	id, err := q.Enqueue(signedTestBatch(t, "batch-modes", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	for _, dir := range []string{q.dir, q.pendingDir, q.inflightDir, q.deadDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", dir, err)
		}
		if got := info.Mode().Perm(); got != dirMode {
			t.Fatalf("%s mode = %o, want %o", dir, got, dirMode)
		}
	}
	info, err := os.Stat(filepath.Join(q.pendingDir, id))
	if err != nil {
		t.Fatalf("Stat(record) error = %v", err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("record mode = %o, want %o", got, fileMode)
	}
}

func TestOpenRejectsSymlinkQueueDir(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, dirMode); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	link := filepath.Join(root, "queue")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	_, err := Open(Config{Dir: link})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Open() = %v, want symlink rejection", err)
	}
}

func TestOpenSweepsStaleTempFiles(t *testing.T) {
	// .tmp-* files left by a previous process crash mid-durableWrite must
	// be cleaned up on Open. listRecordFiles already filters them so they
	// won't get claimed, but without sweep they accumulate forever.
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	// Seed crash debris in pending, inflight, and dead.
	for _, sub := range []string{q.pendingDir, q.inflightDir, q.deadDir} {
		if err := os.WriteFile(filepath.Join(sub, ".tmp-crash-1"), []byte("orphan"), fileMode); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", sub, err)
		}
		if err := os.WriteFile(filepath.Join(sub, ".tmp-crash-2"), []byte("orphan"), fileMode); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", sub, err)
		}
	}

	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	for _, sub := range []string{reopened.pendingDir, reopened.inflightDir, reopened.deadDir} {
		entries, err := os.ReadDir(sub)
		if err != nil {
			t.Fatalf("ReadDir(%s) error = %v", sub, err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				t.Fatalf("stale temp %s/%s survived Open sweep", sub, e.Name())
			}
		}
	}
}

func TestRecoverInflightHandlesNameCollision(t *testing.T) {
	// If pending/<id> AND pending/recovered-<id> both exist when recovery
	// runs (two crashes mid-recovery for the same id), the old code
	// silently clobbered the prior recovered file via os.Rename. The
	// uniqueRecoveryPath loop must escalate to recovered-N-<id> instead.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	batch := signedTestBatch(t, "batch-recover-collision", priv)
	id, err := q.Enqueue(batch)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	// Simulate prior recovery debris: pending/<id> and pending/recovered-<id>
	// both exist when the next Open() runs the recovery sweep.
	originalContent := []byte(`{"version":1,"sentinel":"do-not-clobber"}`)
	if err := os.WriteFile(filepath.Join(q.pendingDir, id), originalContent, fileMode); err != nil {
		t.Fatalf("WriteFile(pending/<id>) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(q.pendingDir, "recovered-"+id), originalContent, fileMode); err != nil {
		t.Fatalf("WriteFile(pending/recovered-<id>) error = %v", err)
	}

	if _, err := Open(Config{Dir: dir}); err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	// Both originals must be intact; recovery must have landed under a
	// fresh name (recovered-1-<id>).
	for _, p := range []string{
		filepath.Join(q.pendingDir, id),
		filepath.Join(q.pendingDir, "recovered-"+id),
	} {
		got, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", p, err)
		}
		if string(got) != string(originalContent) {
			t.Fatalf("%s was clobbered by recovery: got %q", p, got)
		}
	}
	if _, err := os.Stat(filepath.Join(q.pendingDir, "recovered-1-"+id)); err != nil {
		t.Fatalf("Stat(recovered-1-<id>) error = %v; recovery should have placed inflight under fresh name", err)
	}
}

func openTestQueue(t *testing.T, cfg Config) *Queue {
	t.Helper()
	cfg.Dir = t.TempDir()
	q, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return q
}

func assertStats(t *testing.T, q *Queue, want Stats) {
	t.Helper()
	got, err := q.Stats()
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if got != want {
		t.Fatalf("Stats() = %+v, want %+v", got, want)
	}
}

func signedTestBatch(t *testing.T, batchID string, priv ed25519.PrivateKey) Batch {
	t.Helper()
	payload := []byte(`{"events":[{"type":"decision","result":"allowed"}]}`)
	envelope := validUnsignedEnvelope(t, batchID, payload)
	signed, err := SignEnvelope(envelope, "audit-key-1", priv)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	return Batch{Envelope: signed, Payload: payload}
}

func validUnsignedEnvelope(t *testing.T, batchID string, payload []byte) conductor.AuditBatchEnvelope {
	t.Helper()
	payloadSum := sha256.Sum256(payload)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC)
	return conductor.AuditBatchEnvelope{
		SchemaVersion:      conductor.SchemaVersion,
		BatchID:            batchID,
		OrgID:              "org-main",
		FleetID:            "prod",
		InstanceID:         "pl-prod-1",
		AuditSchemaVersion: conductor.SchemaVersion,
		EmittedAt:          now,
		SeqStart:           10,
		SeqEnd:             10,
		EventCount:         1,
		PayloadSHA256:      hex.EncodeToString(payloadSum[:]),
		PayloadBytes:       uint64(len(payload)),
		Dropped:            conductor.DroppedAccounting{},
		Chain: conductor.EvidenceChain{
			EntryVersion:           2,
			SegmentID:              "segment-1",
			SeqStart:               10,
			SeqEnd:                 10,
			SegmentHeadHash:        testHash("head"),
			SegmentTailHash:        testHash("tail"),
			CheckpointSeq:          10,
			CheckpointHash:         testHash("checkpoint"),
			CheckpointSignature:    testEd25519Signature("checkpoint"),
			CheckpointSignerKeyID:  "receipt-key-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: hex.EncodeToString(pub),
			PreviousSegmentTail:    "",
		},
	}
}

func testHash(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func testEd25519Signature(seed string) string {
	sum := sha512.Sum512([]byte(seed))
	return "ed25519:" + hex.EncodeToString(sum[:])
}
