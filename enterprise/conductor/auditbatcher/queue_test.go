//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
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

func TestNilQueueMethodsReturnErrors(t *testing.T) {
	var q *Queue
	if _, err := q.Enqueue(Batch{}); err == nil {
		t.Fatal("Enqueue(nil) error = nil, want error")
	}
	if _, err := q.Claim(); err == nil {
		t.Fatal("Claim(nil) error = nil, want error")
	}
	if err := q.Ack("00000000000000000001-batch-random.json"); err == nil {
		t.Fatal("Ack(nil) error = nil, want error")
	}
	if err := q.Release("00000000000000000001-batch-random.json"); err == nil {
		t.Fatal("Release(nil) error = nil, want error")
	}
	if _, err := q.Stats(); err == nil {
		t.Fatal("Stats(nil) error = nil, want error")
	}
	if err := q.Close(); err == nil {
		t.Fatal("Close(nil) error = nil, want error")
	}
}

func TestQueueClaimEmpty(t *testing.T) {
	q := openTestQueue(t, Config{})
	_, err := q.Claim()
	if !errors.Is(err, ErrQueueEmpty) {
		t.Fatalf("Claim() = %v, want ErrQueueEmpty", err)
	}
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
	// Release the single-writer lock before reopening (simulates restart).
	if err := q.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	lease, err := reopened.Claim()
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if lease.Batch.Envelope.BatchID != "batch-persist" {
		t.Fatalf("BatchID = %q, want batch-persist", lease.Batch.Envelope.BatchID)
	}
}

// TestQueueOpenLocksDirectory proves the cross-process single-writer guard: a
// second Open on a dir already held by a live Queue fails closed with
// ErrQueueLocked rather than silently allowing two writers.
func TestQueueOpenLocksDirectory(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = q.Close() }()

	if _, err := Open(Config{Dir: dir}); !errors.Is(err, ErrQueueLocked) {
		t.Fatalf("Open(second) error = %v, want ErrQueueLocked", err)
	}
}

// TestQueueCloseReleasesLock proves the lock is released on Close so a fresh
// Open succeeds. flock auto-releases on process death, so a crashed prior owner
// (fd gone) is indistinguishable from an explicit Close here.
func TestQueueCloseReleasesLock(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// Idempotent: a second Close is a no-op.
	if err := q.Close(); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}

	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(after close) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
}

func TestQueueOperationsFailAfterClose(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	id, err := q.Enqueue(signedTestBatch(t, "batch-closed", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	batch := signedTestBatch(t, "batch-closed-new", priv)
	if _, err := q.Enqueue(batch); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Enqueue(after Close) = %v, want ErrQueueClosed", err)
	}
	if _, err := q.Enqueue(Batch{}); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Enqueue(invalid batch after Close) = %v, want ErrQueueClosed", err)
	}
	if _, err := q.Claim(); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Claim(after Close) = %v, want ErrQueueClosed", err)
	}
	if err := q.Ack(id); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Ack(after Close) = %v, want ErrQueueClosed", err)
	}
	if err := q.Release(id); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Release(after Close) = %v, want ErrQueueClosed", err)
	}
	if err := q.ReleaseWithRetry(id, "retry"); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("ReleaseWithRetry(after Close) = %v, want ErrQueueClosed", err)
	}
	if err := q.Drop(id, "drop"); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Drop(after Close) = %v, want ErrQueueClosed", err)
	}
	if _, err := q.Stats(); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Stats(after Close) = %v, want ErrQueueClosed", err)
	}
}

// TestQueueLockFileNotTreatedAsRecord proves the .lock file lives under the
// queue root but is invisible to Claim/Stats (it is not a .json record) and is
// not swept as a stale temp.
func TestQueueLockFileNotTreatedAsRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = q.Close() }()

	// Lock file exists at the queue root.
	if _, err := os.Stat(filepath.Join(q.dir, lockFileName)); err != nil {
		t.Fatalf("Stat(lock file) error = %v, want present", err)
	}
	// Fresh queue is empty - the lock file must not count as a record.
	assertStats(t, q, Stats{})

	if _, err := q.Enqueue(signedTestBatch(t, "batch-lock", priv)); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	assertStats(t, q, Stats{Pending: 1})
	lease, err := q.Claim()
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if lease.Batch.Envelope.BatchID != "batch-lock" {
		t.Fatalf("BatchID = %q, want batch-lock", lease.Batch.Envelope.BatchID)
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
	if err := q.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	assertStats(t, reopened, Stats{Pending: 1})
}

func TestQueueReleaseWithRetryPersistsAccounting(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	id, err := q.Enqueue(signedTestBatch(t, "batch-retry", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if err := q.ReleaseWithRetry(id, "HTTP 503 temporary outage"); err != nil {
		t.Fatalf("ReleaseWithRetry() error = %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	record, err := readRecord(filepath.Join(reopened.pendingDir, id), conductor.MaxAuditPayloadBytes)
	if err != nil {
		t.Fatalf("readRecord() error = %v", err)
	}
	if record.RetryCount != 1 {
		t.Fatalf("RetryCount = %d, want 1", record.RetryCount)
	}
	if record.LastAttemptAt == nil {
		t.Fatal("LastAttemptAt = nil, want timestamp")
	}
	if record.LastError != "http_503_temporary_outage" {
		t.Fatalf("LastError = %q, want normalized retry reason", record.LastError)
	}
	// A claim after restart must surface the durable RetryCount on the lease so
	// the transport's delivery-attempt ceiling survives a serve restart.
	lease, err := reopened.Claim()
	if err != nil {
		t.Fatalf("Claim(after reopen) error = %v", err)
	}
	if lease.RetryCount != 1 {
		t.Fatalf("lease.RetryCount = %d, want 1 (durable across restart)", lease.RetryCount)
	}
}

func TestQueueDropMovesInflightToDeadWithReason(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	id, err := q.Enqueue(signedTestBatch(t, "batch-drop", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if err := q.Drop(id, "HTTP 400 rejected"); err != nil {
		t.Fatalf("Drop() error = %v", err)
	}
	assertStats(t, q, Stats{Dead: 1})

	record, err := readRecord(filepath.Join(q.deadDir, id), conductor.MaxAuditPayloadBytes)
	if err != nil {
		t.Fatalf("readRecord(dead) error = %v", err)
	}
	if record.DroppedReason != "http_400_rejected" {
		t.Fatalf("DroppedReason = %q, want normalized drop reason", record.DroppedReason)
	}
	if record.DroppedAt == nil {
		t.Fatal("DroppedAt = nil, want timestamp")
	}
}

func TestQueueReleaseRejectsExistingPendingTarget(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	id, err := q.Enqueue(signedTestBatch(t, "batch-release-collision", priv))
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(q.pendingDir, id), []byte("collision"), fileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := q.Release(id); err == nil || !strings.Contains(err.Error(), "pending target already exists") {
		t.Fatalf("Release() = %v, want pending target collision", err)
	}
}

func TestQueueReleaseReportsTargetStatError(t *testing.T) {
	q := openTestQueue(t, Config{})
	pendingFile := filepath.Join(t.TempDir(), "pending-file")
	if err := os.WriteFile(pendingFile, []byte("not-a-dir"), fileMode); err != nil {
		t.Fatalf("WriteFile(pendingFile) error = %v", err)
	}
	q.pendingDir = pendingFile

	err := q.Release("00000000000000000001-batch.json")
	if err == nil || !strings.Contains(err.Error(), "stat target") {
		t.Fatalf("Release() = %v, want target stat error", err)
	}
}

func TestQueueReleaseReportsRenameError(t *testing.T) {
	q := openTestQueue(t, Config{})
	err := q.Release("00000000000000000001-missing.json")
	if err == nil || !strings.Contains(err.Error(), "release") {
		t.Fatalf("Release() = %v, want rename error", err)
	}
}

func TestQueueAckMissingInflightIsIdempotent(t *testing.T) {
	q := openTestQueue(t, Config{})
	if err := q.Ack("00000000000000000001-batch-missing.json"); err != nil {
		t.Fatalf("Ack(missing) error = %v", err)
	}
}

func TestQueueAckReportsRemoveErrors(t *testing.T) {
	q := openTestQueue(t, Config{})
	inflightFile := filepath.Join(t.TempDir(), "inflight-file")
	if err := os.WriteFile(inflightFile, []byte("not-a-dir"), fileMode); err != nil {
		t.Fatalf("WriteFile(inflightFile) error = %v", err)
	}
	q.inflightDir = inflightFile

	err := q.Ack("00000000000000000001-batch.json")
	if err == nil || !strings.Contains(err.Error(), "ack") {
		t.Fatalf("Ack() = %v, want remove error", err)
	}
}

func TestQueueMethodsRejectInvalidIDs(t *testing.T) {
	q := openTestQueue(t, Config{})
	if err := q.Ack("../escape.json"); err == nil {
		t.Fatal("Ack(invalid) error = nil, want error")
	}
	if err := q.Release("../escape.json"); err == nil {
		t.Fatal("Release(invalid) error = nil, want error")
	}
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

func TestQueueRejectsOversizePayloadBeforeEnvelopeValidation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{MaxPayloadBytes: 1})
	_, err = q.Enqueue(signedTestBatch(t, "batch-too-large", priv))
	if !errors.Is(err, conductor.ErrPayloadTooLarge) {
		t.Fatalf("Enqueue() = %v, want ErrPayloadTooLarge", err)
	}
}

func TestQueueReturnsDirectoryErrors(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	if err := os.Rename(q.pendingDir, q.pendingDir+"-gone"); err != nil {
		t.Fatalf("Rename(pending) error = %v", err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-dir-error", priv)); err == nil {
		t.Fatal("Enqueue() error = nil, want missing pending dir error")
	}
	if _, err := q.Claim(); err == nil {
		t.Fatal("Claim() error = nil, want missing pending dir error")
	}
	if _, err := q.Stats(); err == nil {
		t.Fatal("Stats() error = nil, want missing pending dir error")
	}
}

func TestQueueStatsReportsInflightAndDeadDirectoryErrors(t *testing.T) {
	q := openTestQueue(t, Config{})
	if err := os.RemoveAll(q.inflightDir); err != nil {
		t.Fatalf("RemoveAll(inflightDir) error = %v", err)
	}
	if _, err := q.Stats(); err == nil {
		t.Fatal("Stats() error = nil, want missing inflight dir error")
	}

	q = openTestQueue(t, Config{})
	if err := os.RemoveAll(q.deadDir); err != nil {
		t.Fatalf("RemoveAll(deadDir) error = %v", err)
	}
	if _, err := q.Stats(); err == nil {
		t.Fatal("Stats() error = nil, want missing dead dir error")
	}
}

func TestQueueClaimDoesNotDeadLetterOperationalReadError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	q := openTestQueue(t, Config{})
	id := "00000000000000000001-batch-operational.json"
	if err := writeDiskRecord(filepath.Join(q.pendingDir, id), validDiskRecord(signedTestBatch(t, "batch-operational", priv))); err != nil {
		t.Fatalf("writeDiskRecord() error = %v", err)
	}
	q.maxPayloadBytes = maxRecordReadBytes

	_, err = q.Claim()
	if err == nil || !strings.Contains(err.Error(), "max payload bytes too large") {
		t.Fatalf("Claim() = %v, want operational read error", err)
	}
	if errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("Claim() = %v, must not classify operational error as corrupt", err)
	}
	assertStats(t, q, Stats{Inflight: 1})
}

func TestQueueClaimCorruptRecordReportsDeadLetterPathErrors(t *testing.T) {
	q := openTestQueue(t, Config{})
	id := "00000000000000000001-corrupt.json"
	if err := os.WriteFile(filepath.Join(q.pendingDir, id), []byte("{bad"), fileMode); err != nil {
		t.Fatalf("WriteFile(corrupt) error = %v", err)
	}
	deadFile := filepath.Join(t.TempDir(), "dead-file")
	if err := os.WriteFile(deadFile, []byte("not-a-dir"), fileMode); err != nil {
		t.Fatalf("WriteFile(deadFile) error = %v", err)
	}
	q.deadDir = deadFile

	_, err := q.Claim()
	if err == nil || !strings.Contains(err.Error(), "stat dead-letter target") {
		t.Fatalf("Claim() = %v, want dead-letter path stat error", err)
	}
}

func TestQueueClaimCorruptRecordReportsMoveToDeadErrors(t *testing.T) {
	q := openTestQueue(t, Config{})
	id := "00000000000000000001-corrupt.json"
	if err := os.WriteFile(filepath.Join(q.pendingDir, id), []byte("{bad"), fileMode); err != nil {
		t.Fatalf("WriteFile(corrupt) error = %v", err)
	}
	if err := os.RemoveAll(q.deadDir); err != nil {
		t.Fatalf("RemoveAll(deadDir) error = %v", err)
	}

	_, err := q.Claim()
	if err == nil || !strings.Contains(err.Error(), "corrupt record") {
		t.Fatalf("Claim() = %v, want corrupt record move error", err)
	}
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("Claim() = %v, want ErrCorruptRecord", err)
	}
}

func TestOpenRequiresQueueDir(t *testing.T) {
	_, err := Open(Config{})
	if err == nil || !strings.Contains(err.Error(), "queue dir required") {
		t.Fatalf("Open() = %v, want queue dir required", err)
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

func TestUniqueDeadPathSkipsExistingCollisionChain(t *testing.T) {
	dir := t.TempDir()
	id := "00000000000000000001-corrupt.json"
	for _, name := range []string{id, "dead-" + id, "dead-1-" + id} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("occupied"), fileMode); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}
	path, err := uniqueDeadPath(dir, id)
	if err != nil {
		t.Fatalf("uniqueDeadPath() error = %v", err)
	}
	if got, want := filepath.Base(path), "dead-2-"+id; got != want {
		t.Fatalf("uniqueDeadPath() = %q, want %q", got, want)
	}
}

func TestValidateRecordID(t *testing.T) {
	for _, id := range []string{"", "../escape.json", "record.txt"} {
		if err := validateRecordID(id); err == nil {
			t.Fatalf("validateRecordID(%q) error = nil, want error", id)
		}
	}
	if err := validateRecordID("00000000000000000001-batch-ok.json"); err != nil {
		t.Fatalf("validateRecordID(valid) error = %v", err)
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

func TestOpenRejectsSymlinkQueueSubdir(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	if err := os.Mkdir(queueDir, dirMode); err != nil {
		t.Fatalf("Mkdir(queue) error = %v", err)
	}
	target := filepath.Join(root, "outside")
	if err := os.Mkdir(target, dirMode); err != nil {
		t.Fatalf("Mkdir(outside) error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(queueDir, "pending")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	_, err := Open(Config{Dir: queueDir})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Open() = %v, want symlink subdir rejection", err)
	}
}

func TestOpenRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, dirMode); err != nil {
		t.Fatalf("Mkdir(real) error = %v", err)
	}
	linkParent := filepath.Join(root, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	_, err := Open(Config{Dir: filepath.Join(linkParent, "queue")})
	if err == nil || !strings.Contains(err.Error(), "ancestor") || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Open() = %v, want symlink ancestor rejection", err)
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
	if err := q.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
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

func TestSweepStaleTempsAndListRecordFilesFilterEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".tmp-dir"), dirMode); err != nil {
		t.Fatalf("Mkdir(.tmp-dir) error = %v", err)
	}
	for _, name := range []string{".tmp-crash", "note.txt", "b.json", "a.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("record"), fileMode); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}
	if err := sweepStaleTempsLocked(dir); err != nil {
		t.Fatalf("sweepStaleTempsLocked() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-crash")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-dir")); err != nil {
		t.Fatalf("Stat(.tmp-dir) error = %v", err)
	}
	files, err := listRecordFiles(dir)
	if err != nil {
		t.Fatalf("listRecordFiles() error = %v", err)
	}
	if got, want := strings.Join(files, ","), "a.json,b.json"; got != want {
		t.Fatalf("listRecordFiles() = %q, want %q", got, want)
	}

	if err := sweepStaleTempsLocked(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("sweepStaleTempsLocked(missing) error = nil, want error")
	}
}

func TestRecoverInflightHandlesNameCollision(t *testing.T) {
	// If pending/<id> AND pending/<id>-recovered both exist when recovery
	// runs (two crashes mid-recovery for the same id), the recovery path
	// must escalate to <id>-recovered-N while preserving the full original
	// id prefix for FIFO ordering.
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
	recoveredID := id + "-recovered" + recordExt
	recoveredAgainID := id + "-recovered-1" + recordExt
	// Simulate prior recovery debris: pending/<id> and pending/<id>-recovered
	// both exist when the next Open() runs the recovery sweep.
	originalContent := []byte(`{"version":1,"sentinel":"do-not-clobber"}`)
	if err := os.WriteFile(filepath.Join(q.pendingDir, id), originalContent, fileMode); err != nil {
		t.Fatalf("WriteFile(pending/<id>) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(q.pendingDir, recoveredID), originalContent, fileMode); err != nil {
		t.Fatalf("WriteFile(pending/<id>-recovered) error = %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	// Both originals must be intact; recovery must have landed under a
	// fresh name (recovered-1-<id>).
	for _, p := range []string{
		filepath.Join(q.pendingDir, id),
		filepath.Join(q.pendingDir, recoveredID),
	} {
		got, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", p, err)
		}
		if string(got) != string(originalContent) {
			t.Fatalf("%s was clobbered by recovery: got %q", p, got)
		}
	}
	if _, err := os.Stat(filepath.Join(q.pendingDir, recoveredAgainID)); err != nil {
		t.Fatalf("Stat(<id>-recovered-1) error = %v; recovery should have placed inflight under fresh name", err)
	}
	files, err := listRecordFiles(q.pendingDir)
	if err != nil {
		t.Fatalf("listRecordFiles() error = %v", err)
	}
	if got, want := files[0], id; got != want {
		t.Fatalf("first pending file = %q, want original timestamp prefix %q", got, want)
	}
}

func TestRecoverInflightReportsListPathAndRenameErrors(t *testing.T) {
	q := &Queue{inflightDir: filepath.Join(t.TempDir(), "missing")}
	if err := q.recoverInflightLocked(); err == nil {
		t.Fatal("recoverInflightLocked() error = nil, want missing inflight dir error")
	}

	inflightDir := t.TempDir()
	id := "00000000000000000001-recover.json"
	if err := os.WriteFile(filepath.Join(inflightDir, id), []byte("record"), fileMode); err != nil {
		t.Fatalf("WriteFile(inflight) error = %v", err)
	}
	pendingFile := filepath.Join(t.TempDir(), "pending-file")
	if err := os.WriteFile(pendingFile, []byte("not-a-dir"), fileMode); err != nil {
		t.Fatalf("WriteFile(pendingFile) error = %v", err)
	}
	q = &Queue{inflightDir: inflightDir, pendingDir: pendingFile}
	if err := q.recoverInflightLocked(); err == nil || !strings.Contains(err.Error(), "stat recovery target") {
		t.Fatalf("recoverInflightLocked() = %v, want recovery path stat error", err)
	}

	inflightDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(inflightDir, id), []byte("record"), fileMode); err != nil {
		t.Fatalf("WriteFile(inflight) error = %v", err)
	}
	q = &Queue{inflightDir: inflightDir, pendingDir: filepath.Join(t.TempDir(), "missing", "pending")}
	if err := q.recoverInflightLocked(); err == nil || !strings.Contains(err.Error(), "recover inflight") {
		t.Fatalf("recoverInflightLocked() = %v, want rename error", err)
	}
}

func TestUniquePathHelpersReportStatAndExhaustionErrors(t *testing.T) {
	id := "00000000000000000001-collision.json"
	dirFile := filepath.Join(t.TempDir(), "dir-file")
	if err := os.WriteFile(dirFile, []byte("not-a-dir"), fileMode); err != nil {
		t.Fatalf("WriteFile(dirFile) error = %v", err)
	}
	if _, err := uniqueDeadPath(dirFile, id); err == nil || !strings.Contains(err.Error(), "stat dead-letter target") {
		t.Fatalf("uniqueDeadPath(file) = %v, want stat error", err)
	}
	if _, err := uniqueRecoveryPath(dirFile, id); err == nil || !strings.Contains(err.Error(), "stat recovery target") {
		t.Fatalf("uniqueRecoveryPath(file) = %v, want stat error", err)
	}

	deadDir := t.TempDir()
	for i := -1; i < 1024; i++ {
		name := id
		if i == 0 {
			name = "dead-" + id
		} else if i > 0 {
			name = fmt.Sprintf("dead-%d-%s", i, id)
		}
		if err := os.WriteFile(filepath.Join(deadDir, name), []byte("occupied"), fileMode); err != nil {
			t.Fatalf("WriteFile(dead collision %d) error = %v", i, err)
		}
	}
	if _, err := uniqueDeadPath(deadDir, id); err == nil || !strings.Contains(err.Error(), "too many existing dead-letter") {
		t.Fatalf("uniqueDeadPath(exhausted) = %v, want exhaustion error", err)
	}

	recoveryDir := t.TempDir()
	for i := -1; i < 1024; i++ {
		name := id
		if i == 0 {
			name = id + "-recovered" + recordExt
		} else if i > 0 {
			name = fmt.Sprintf("%s-recovered-%d%s", id, i, recordExt)
		}
		if err := os.WriteFile(filepath.Join(recoveryDir, name), []byte("occupied"), fileMode); err != nil {
			t.Fatalf("WriteFile(recovery collision %d) error = %v", i, err)
		}
	}
	if _, err := uniqueRecoveryPath(recoveryDir, id); err == nil || !strings.Contains(err.Error(), "too many existing recovery") {
		t.Fatalf("uniqueRecoveryPath(exhausted) = %v, want exhaustion error", err)
	}
}

func TestReadRecordStrictDecodeFailures(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	batch := signedTestBatch(t, "batch-read-strict", priv)
	record := validDiskRecord(batch)
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, record diskRecord) []byte
		want string
	}{
		{
			name: "unknown_field",
			edit: func(t *testing.T, record diskRecord) []byte {
				t.Helper()
				data, err := json.Marshal(struct {
					diskRecord
					Unexpected string `json:"unexpected"`
				}{diskRecord: record, Unexpected: "nope"})
				if err != nil {
					t.Fatalf("Marshal() error = %v", err)
				}
				return data
			},
			want: "unknown field",
		},
		{
			name: "trailing_json",
			edit: func(t *testing.T, record diskRecord) []byte {
				t.Helper()
				data, err := json.Marshal(record)
				if err != nil {
					t.Fatalf("Marshal() error = %v", err)
				}
				return append(data, []byte("\n{}")...)
			},
			want: "trailing JSON document",
		},
		{
			name: "unsupported_version",
			edit: func(t *testing.T, record diskRecord) []byte {
				t.Helper()
				record.Version++
				data, err := json.Marshal(record)
				if err != nil {
					t.Fatalf("Marshal() error = %v", err)
				}
				return data
			},
			want: "record version",
		},
		{
			name: "missing_enqueued_at",
			edit: func(t *testing.T, record diskRecord) []byte {
				t.Helper()
				record.EnqueuedAt = time.Time{}
				data, err := json.Marshal(record)
				if err != nil {
					t.Fatalf("Marshal() error = %v", err)
				}
				return data
			},
			want: "missing enqueued_at",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "record.json")
			if err := os.WriteFile(path, tc.edit(t, record), fileMode); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			_, err := readRecord(path, conductor.MaxAuditPayloadBytes)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("readRecord() = %v, want %q", err, tc.want)
			}
			if !errors.Is(err, ErrCorruptRecord) {
				t.Fatalf("readRecord() = %v, want ErrCorruptRecord", err)
			}
		})
	}
}

func TestReadRecordRejectsOversizeRecordBeforeDecode(t *testing.T) {
	limit, err := recordReadLimit(1)
	if err != nil {
		t.Fatalf("recordReadLimit() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "oversize.json")
	data := make([]byte, 0)
	for i := int64(0); i <= limit; i++ {
		data = append(data, 0)
	}
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = readRecord(path, 1)
	if !errors.Is(err, conductor.ErrPayloadTooLarge) {
		t.Fatalf("readRecord() = %v, want ErrPayloadTooLarge", err)
	}
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("readRecord() = %v, want ErrCorruptRecord", err)
	}
}

func TestReadRecordRejectsSymlinkRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := writeDiskRecord(target, validDiskRecord(signedTestBatch(t, "batch-symlink-record", priv))); err != nil {
		t.Fatalf("writeDiskRecord() error = %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	_, err = readRecord(link, conductor.MaxAuditPayloadBytes)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("readRecord() = %v, want symlink rejection", err)
	}
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("readRecord() = %v, want ErrCorruptRecord", err)
	}
}

func TestReadRecordRejectsNonRegularRecord(t *testing.T) {
	_, err := readRecord(t.TempDir(), conductor.MaxAuditPayloadBytes)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("readRecord() = %v, want non-regular file rejection", err)
	}
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("readRecord() = %v, want ErrCorruptRecord", err)
	}
}

func TestReadRecordOperationalErrorsAreNotCorrupt(t *testing.T) {
	_, err := readRecord(filepath.Join(t.TempDir(), "missing.json"), conductor.MaxAuditPayloadBytes)
	if err == nil || !strings.Contains(err.Error(), "stat record") {
		t.Fatalf("readRecord(missing) = %v, want stat error", err)
	}
	if errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("readRecord(missing) = %v, must not be corrupt classification", err)
	}
}

func TestReadRecordRejectsInvalidMaxPayloadLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte("{}"), fileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := readRecord(path, maxRecordReadBytes)
	if err == nil || !strings.Contains(err.Error(), "max payload bytes too large") {
		t.Fatalf("readRecord() = %v, want max payload limit error", err)
	}
	if errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("readRecord() = %v, must not classify config limit error as corrupt", err)
	}
}

func TestReadRecordRejectsPayloadValidationFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	record := validDiskRecord(signedTestBatch(t, "batch-read-bad-payload", priv))
	record.Payload = []byte("tampered")
	path := filepath.Join(t.TempDir(), "record.json")
	if err := writeDiskRecord(path, record); err != nil {
		t.Fatalf("writeDiskRecord() error = %v", err)
	}

	_, err = readRecord(path, conductor.MaxAuditPayloadBytes)
	if !errors.Is(err, conductor.ErrHashMismatch) {
		t.Fatalf("readRecord() = %v, want ErrHashMismatch", err)
	}
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("readRecord() = %v, want ErrCorruptRecord", err)
	}
}

func TestValidateBatchAndRecordLimitErrors(t *testing.T) {
	if err := validateBatch(Batch{}, conductor.MaxAuditPayloadBytes); err == nil {
		t.Fatal("validateBatch() error = nil, want invalid envelope error")
	}
	if _, err := uint64ToInt64(maxRecordReadBytes + 1); err == nil {
		t.Fatal("uint64ToInt64() error = nil, want oversize error")
	}
}

func TestEnsurePrivateDirRejectsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue")
	if err := os.WriteFile(path, []byte("not-dir"), fileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := ensurePrivateDir(path)
	if err == nil {
		t.Fatal("ensurePrivateDir() error = nil, want error")
	}
}

func TestRejectSymlinkAncestorsMissingAndNonDirectory(t *testing.T) {
	if err := rejectSymlinkAncestors(filepath.Join(t.TempDir(), "missing", "queue")); err != nil {
		t.Fatalf("rejectSymlinkAncestors(missing chain) error = %v", err)
	}
	parentFile := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(parentFile, []byte("not-a-dir"), fileMode); err != nil {
		t.Fatalf("WriteFile(parentFile) error = %v", err)
	}
	if err := rejectSymlinkAncestors(filepath.Join(parentFile, "queue")); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("rejectSymlinkAncestors(file parent) = %v, want non-directory error", err)
	}
}

func TestEnsurePrivateDirChmodsDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	resolved, err := ensurePrivateDir(path)
	if err != nil {
		t.Fatalf("ensurePrivateDir() error = %v", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != dirMode {
		t.Fatalf("mode = %o, want %o", got, dirMode)
	}
}

func TestEnsurePathContainedRejectsEscape(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	escaped := filepath.Join(filepath.Dir(root), "root-escape", "pending")
	if err := ensurePathContained(root, escaped); err == nil {
		t.Fatal("ensurePathContained() error = nil, want escape rejection")
	}
}

func TestFsyncDirMissingPath(t *testing.T) {
	err := fsyncDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "open dir for fsync") {
		t.Fatalf("fsyncDir() = %v, want open error", err)
	}
}

func TestDurableWriteAndMoveToDeadErrorPaths(t *testing.T) {
	if err := durableWrite(filepath.Join(t.TempDir(), "missing", "record.json"), []byte("record")); err == nil {
		t.Fatal("durableWrite(missing parent) error = nil, want create temp error")
	}
	existingDir := filepath.Join(t.TempDir(), "existing-dir")
	if err := os.Mkdir(existingDir, dirMode); err != nil {
		t.Fatalf("Mkdir(existingDir) error = %v", err)
	}
	if err := durableWrite(existingDir, []byte("record")); err == nil || !strings.Contains(err.Error(), "rename temp") {
		t.Fatalf("durableWrite(existing dir) = %v, want rename error", err)
	}
	if err := moveToDead(filepath.Join(t.TempDir(), "missing.json"), filepath.Join(t.TempDir(), "dead.json")); err == nil {
		t.Fatal("moveToDead(missing source) error = nil, want rename error")
	}
}

func openTestQueue(t *testing.T, cfg Config) *Queue {
	t.Helper()
	cfg.Dir = t.TempDir()
	q, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
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

func validDiskRecord(batch Batch) diskRecord {
	return diskRecord{
		Version:    recordVersion,
		EnqueuedAt: time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC),
		Envelope:   batch.Envelope,
		Payload:    batch.Payload,
	}
}

func writeDiskRecord(path string, record diskRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, fileMode)
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
