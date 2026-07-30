//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package auditbatcher provides follower-side durable queuing primitives for
// Conductor-bound audit batches. It intentionally sits outside emit.Emitter
// because Conductor audit delivery must track retry and drop state instead of
// being fire-and-forget.
//
// Concurrency model: a Queue is SINGLE-PROCESS per directory. The mutex
// serializes access within one process; an exclusive advisory flock on a
// .lock file under the queue root (taken at Open, released at Close or on
// process death) enforces single-writer across processes on one host / local
// filesystem. This is not a distributed lock: cross-host single-writer on a
// shared RWX/network/overlay PVC is a deployment responsibility. Use a RWO
// volume, leader election, or one durable_audit_queue_dir per pod for that
// shape.
package auditbatcher

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const (
	dirMode  = 0o750
	fileMode = 0o600

	defaultMaxPending      = 1024
	maxRecordMetadataBytes = 128 * 1024
	maxRecordReadBytes     = uint64(1<<63 - 1)
	recordVersion          = 1
	recordExt              = ".json"
)

const (
	lockFileName       = ".lock"
	queueStateFileName = "queue-state.json"
)

const maxQueueStateBytes = 1024

var (
	ErrQueueEmpty    = errors.New("auditbatcher: queue empty")
	ErrQueueFull     = errors.New("auditbatcher: queue full")
	ErrCorruptRecord = errors.New("auditbatcher: corrupt record")
	ErrQueueLocked   = errors.New("auditbatcher: queue already locked by another process")
	ErrQueueClosed   = errors.New("auditbatcher: queue closed")
)

var errQueueEncryptionPreviouslySeen = errors.New("auditbatcher: durable audit queue previously ran encrypted; refusing plaintext open without a keyring")

type Config struct {
	Dir             string
	MaxPending      int
	MaxPayloadBytes uint64
	Keyring         *Keyring
	AllowPlaintext  bool
}

type Batch struct {
	Envelope conductor.AuditBatchEnvelope
	Payload  []byte
}

type Lease struct {
	ID    string
	Batch Batch
	// RetryCount is the number of prior delivery attempts that released this
	// record back to pending. A freshly enqueued record leases with 0. The
	// transport uses it to enforce a max-delivery-attempts ceiling before
	// dead-lettering a poison batch.
	RetryCount uint64
}

type Stats struct {
	Pending  int
	Inflight int
	Dead     int
}

type Queue struct {
	dir             string
	pendingDir      string
	inflightDir     string
	deadDir         string
	maxPending      int
	maxPayloadBytes uint64
	keyring         *Keyring
	now             func() time.Time
	mu              sync.Mutex
	closed          bool
	// lockFile holds the exclusive advisory lock on the queue root for the
	// Queue's lifetime. The OS releases the flock automatically when this fd is
	// closed OR when the owning process dies, so a crashed prior owner never
	// deadlocks a fresh Open.
	lockFile *os.File
}

type diskRecord struct {
	Version       int                          `json:"version"`
	EnqueuedAt    time.Time                    `json:"enqueued_at"`
	Envelope      conductor.AuditBatchEnvelope `json:"envelope"`
	Payload       []byte                       `json:"payload"`
	RetryCount    uint64                       `json:"retry_count,omitempty"`
	LastAttemptAt *time.Time                   `json:"last_attempt_at,omitempty"`
	LastError     string                       `json:"last_error,omitempty"`
	DroppedAt     *time.Time                   `json:"dropped_at,omitempty"`
	DroppedReason string                       `json:"dropped_reason,omitempty"`
}

type queueState struct {
	EncryptionSeen bool `json:"encryption_seen"`
}

func Open(cfg Config) (*Queue, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, errors.New("auditbatcher: queue dir required")
	}
	cleanDir := filepath.Clean(cfg.Dir)
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = defaultMaxPending
	}
	if cfg.MaxPayloadBytes == 0 {
		cfg.MaxPayloadBytes = conductor.MaxAuditPayloadBytes
	}
	if cfg.Keyring == nil && !cfg.AllowPlaintext {
		return nil, errors.New("auditbatcher: queue encryption keyring required")
	}
	dir, pendingDir, inflightDir, deadDir, err := ensurePrivateQueueDirs(cleanDir)
	if err != nil {
		return nil, err
	}
	lockFile, err := acquireQueueLock(dir)
	if err != nil {
		return nil, err
	}
	q := &Queue{
		dir:             dir,
		pendingDir:      pendingDir,
		inflightDir:     inflightDir,
		deadDir:         deadDir,
		maxPending:      cfg.MaxPending,
		maxPayloadBytes: cfg.MaxPayloadBytes,
		keyring:         cfg.Keyring,
		now:             func() time.Time { return time.Now().UTC() },
		lockFile:        lockFile,
	}
	// Any failure after the lock is held must release it, otherwise a failed
	// Open leaves the queue dir locked until process exit.
	opened := false
	defer func() {
		if !opened {
			_ = q.releaseLock()
		}
	}()
	// Sweep .tmp-* debris from any prior crash mid-write. Live writes use
	// CreateTemp+rename; only crashes leave .tmp-* files behind, and they
	// otherwise accumulate forever (listRecordFiles correctly ignores them,
	// so they're invisible to claim but visible to df). Opening fresh is the
	// only safe time to remove them - no other writer could legitimately
	// have a .tmp-* in flight before Open returns.
	for _, dir := range []string{q.dir, q.pendingDir, q.inflightDir, q.deadDir} {
		if err := sweepStaleTempsLocked(dir); err != nil {
			return nil, err
		}
	}
	if q.keyring == nil {
		if err := q.verifyPlaintextOpenAllowedLocked(); err != nil {
			return nil, err
		}
	} else if err := q.markEncryptionSeenLocked(); err != nil {
		return nil, err
	}
	if err := q.migrateRecordsLocked(); err != nil {
		return nil, err
	}
	if err := q.recoverInflightLocked(); err != nil {
		return nil, err
	}
	opened = true
	return q, nil
}

// Close marks the queue closed and releases the exclusive queue lock so another
// process may Open the same directory. It is safe to call multiple times.
// Subsequent queue operations fail closed with ErrQueueClosed.
func (q *Queue) Close() error {
	if q == nil {
		return errors.New("auditbatcher: nil queue")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	return q.releaseLock()
}

func (q *Queue) checkOpenLocked() error {
	if q.closed {
		return ErrQueueClosed
	}
	if q.lockFile == nil {
		return ErrQueueClosed
	}
	return nil
}

func (q *Queue) Enqueue(batch Batch) (string, error) {
	if q == nil {
		return "", errors.New("auditbatcher: nil queue")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkOpenLocked(); err != nil {
		return "", err
	}
	if err := validateBatch(batch, q.maxPayloadBytes); err != nil {
		return "", err
	}

	pending, err := listRecordFiles(q.pendingDir)
	if err != nil {
		return "", err
	}
	if len(pending) >= q.maxPending {
		return "", fmt.Errorf("%w: pending=%d max=%d", ErrQueueFull, len(pending), q.maxPending)
	}
	id, err := q.nextIDLocked(batch.Envelope.BatchID)
	if err != nil {
		return "", err
	}
	record := diskRecord{
		Version:    recordVersion,
		EnqueuedAt: q.now().UTC(),
		Envelope:   batch.Envelope,
		Payload:    append([]byte(nil), batch.Payload...),
	}
	data, err := marshalQueueRecord(record, q.keyring)
	if err != nil {
		return "", fmt.Errorf("auditbatcher: marshal record: %w", err)
	}
	path := filepath.Join(q.pendingDir, id)
	if err := durableWrite(path, data); err != nil {
		return "", err
	}
	return id, nil
}

func (q *Queue) Claim() (*Lease, error) {
	if q == nil {
		return nil, errors.New("auditbatcher: nil queue")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkOpenLocked(); err != nil {
		return nil, err
	}

	for {
		files, err := listRecordFiles(q.pendingDir)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, ErrQueueEmpty
		}
		id := files[0]
		pendingPath := filepath.Join(q.pendingDir, id)
		inflightPath := filepath.Join(q.inflightDir, id)
		if err := os.Rename(pendingPath, inflightPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("auditbatcher: claim %s: %w", id, err)
		}
		if err := fsyncDir(q.pendingDir); err != nil {
			return nil, err
		}
		if err := fsyncDir(q.inflightDir); err != nil {
			return nil, err
		}
		record, _, _, err := readRecordWithKeyring(inflightPath, q.maxPayloadBytes, q.keyring)
		if err != nil {
			if !errors.Is(err, ErrCorruptRecord) {
				return nil, err
			}
			deadPath, pathErr := uniqueDeadPath(q.deadDir, id)
			if pathErr != nil {
				return nil, fmt.Errorf("auditbatcher: corrupt record %s: %w", id, errors.Join(err, pathErr))
			}
			if moveErr := moveToDead(inflightPath, deadPath); moveErr != nil {
				return nil, fmt.Errorf("auditbatcher: corrupt record %s: %w", id, errors.Join(err, moveErr))
			}
			continue
		}
		return &Lease{ID: id, Batch: Batch{Envelope: record.Envelope, Payload: record.Payload}, RetryCount: record.RetryCount}, nil
	}
}

func (q *Queue) Ack(id string) error {
	if q == nil {
		return errors.New("auditbatcher: nil queue")
	}
	if err := validateRecordID(id); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkOpenLocked(); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(q.inflightDir, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("auditbatcher: ack %s: %w", id, err)
	}
	return fsyncDir(q.inflightDir)
}

func (q *Queue) Release(id string) error {
	if q == nil {
		return errors.New("auditbatcher: nil queue")
	}
	if err := validateRecordID(id); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkOpenLocked(); err != nil {
		return err
	}
	return q.releaseLocked(id)
}

// ReleaseWithRetry returns an inflight record to pending and durably annotates
// the retry count/reason before the rename. If the process crashes after the
// annotation but before the rename, Open's inflight recovery preserves the
// updated accounting when it moves the record back to pending.
func (q *Queue) ReleaseWithRetry(id, reason string) error {
	if q == nil {
		return errors.New("auditbatcher: nil queue")
	}
	if err := validateRecordID(id); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkOpenLocked(); err != nil {
		return err
	}
	if err := q.updateInflightRecordLocked(id, func(record *diskRecord) {
		now := q.now().UTC()
		record.RetryCount++
		record.LastAttemptAt = &now
		record.LastError = normalizeAccountingReason(reason)
	}); err != nil {
		return err
	}
	return q.releaseLocked(id)
}

// Drop moves an inflight record to the dead-letter directory and durably stamps
// the terminal drop reason first. Dead records remain inspectable by operators.
func (q *Queue) Drop(id, reason string) error {
	if q == nil {
		return errors.New("auditbatcher: nil queue")
	}
	if err := validateRecordID(id); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkOpenLocked(); err != nil {
		return err
	}
	if err := q.updateInflightRecordLocked(id, func(record *diskRecord) {
		now := q.now().UTC()
		record.DroppedAt = &now
		record.DroppedReason = normalizeAccountingReason(reason)
		record.LastError = record.DroppedReason
	}); err != nil {
		return err
	}
	src := filepath.Join(q.inflightDir, id)
	dst, err := uniqueDeadPath(q.deadDir, id)
	if err != nil {
		return err
	}
	return moveToDead(src, dst)
}

func (q *Queue) releaseLocked(id string) error {
	src := filepath.Join(q.inflightDir, id)
	dst := filepath.Join(q.pendingDir, id)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("auditbatcher: release %s: pending target already exists", id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("auditbatcher: release %s stat target: %w", id, err)
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("auditbatcher: release %s: %w", id, err)
	}
	if err := fsyncDir(q.inflightDir); err != nil {
		return err
	}
	return fsyncDir(q.pendingDir)
}

func (q *Queue) Stats() (Stats, error) {
	if q == nil {
		return Stats{}, errors.New("auditbatcher: nil queue")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.checkOpenLocked(); err != nil {
		return Stats{}, err
	}
	pending, err := listRecordFiles(q.pendingDir)
	if err != nil {
		return Stats{}, err
	}
	inflight, err := listRecordFiles(q.inflightDir)
	if err != nil {
		return Stats{}, err
	}
	dead, err := listRecordFiles(q.deadDir)
	if err != nil {
		return Stats{}, err
	}
	return Stats{Pending: len(pending), Inflight: len(inflight), Dead: len(dead)}, nil
}

func (q *Queue) recoverInflightLocked() error {
	files, err := listRecordFiles(q.inflightDir)
	if err != nil {
		return err
	}
	for _, id := range files {
		src := filepath.Join(q.inflightDir, id)
		dst, err := uniqueRecoveryPath(q.pendingDir, id)
		if err != nil {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("auditbatcher: recover inflight %s: %w", id, err)
		}
	}
	if err := fsyncDir(q.inflightDir); err != nil {
		return err
	}
	return fsyncDir(q.pendingDir)
}

// migrateRecordsLocked encrypts legacy plaintext records and re-encrypts
// records written under retained rotation keys. It runs while Open holds the
// exclusive queue lock and before inflight recovery, so no worker can observe
// a partially migrated queue. Each replacement is individually atomic and
// durable; a crash simply resumes from the remaining records on next Open.
func (q *Queue) migrateRecordsLocked() error {
	if q.keyring == nil {
		return q.verifyPlaintextRecordsLocked()
	}
	active := q.keyring.ActiveKeyID()
	for _, dir := range []string{q.pendingDir, q.inflightDir, q.deadDir} {
		files, err := listRecordFiles(dir)
		if err != nil {
			return err
		}
		for _, id := range files {
			path := filepath.Join(dir, id)
			record, keyID, legacy, err := readRecordWithKeyring(path, q.maxPayloadBytes, q.keyring)
			if err != nil {
				if errors.Is(err, errQueueKeyUnavailable) || !errors.Is(err, ErrCorruptRecord) {
					return fmt.Errorf("auditbatcher: migrate queue record %s: %w", id, err)
				}
				// Dead-letter records are already quarantined evidence. An unreadable
				// one must not turn a later restart into a permanent availability
				// failure. Corrupt live records are quarantined atomically here so
				// the remaining queue can migrate and start.
				if dir == q.deadDir {
					continue
				}
				deadPath, pathErr := uniqueDeadPath(q.deadDir, id)
				if pathErr != nil {
					return fmt.Errorf("auditbatcher: quarantine queue record %s: %w", id, errors.Join(err, pathErr))
				}
				if moveErr := moveToDead(path, deadPath); moveErr != nil {
					return fmt.Errorf("auditbatcher: quarantine queue record %s: %w", id, errors.Join(err, moveErr))
				}
				continue
			}
			if !legacy && keyID == active {
				continue
			}
			data, err := encryptDiskRecord(record, q.keyring)
			if err != nil {
				return fmt.Errorf("auditbatcher: encrypt queue record %s: %w", id, err)
			}
			if err := durableWrite(path, data); err != nil {
				return fmt.Errorf("auditbatcher: migrate queue record %s: %w", id, err)
			}
		}
	}
	return nil
}

func (q *Queue) verifyPlaintextRecordsLocked() error {
	for _, dir := range []string{q.pendingDir, q.inflightDir, q.deadDir} {
		files, err := listRecordFiles(dir)
		if err != nil {
			return err
		}
		for _, id := range files {
			path := filepath.Join(dir, id)
			_, _, _, err := readRecordWithKeyring(path, q.maxPayloadBytes, nil)
			if err == nil {
				continue
			}
			// Fail closed on a v2 encrypted record found in plaintext mode (a
			// keyring was configured and then removed): errQueueKeyUnavailable is
			// not ErrCorruptRecord, so it takes this branch and blocks startup
			// rather than silently dropping still-encrypted evidence.
			if errors.Is(err, errQueueKeyUnavailable) || !errors.Is(err, ErrCorruptRecord) {
				return fmt.Errorf("auditbatcher: plaintext queue record %s: %w", id, err)
			}
			// A corrupt record already quarantined in dead/ must not turn a later
			// restart into a permanent availability failure. Mirror encrypted-mode
			// migration: skip dead-letter corruption, quarantine a corrupt live
			// record so the remaining queue can still open.
			if dir == q.deadDir {
				continue
			}
			deadPath, pathErr := uniqueDeadPath(q.deadDir, id)
			if pathErr != nil {
				return fmt.Errorf("auditbatcher: quarantine queue record %s: %w", id, errors.Join(err, pathErr))
			}
			if moveErr := moveToDead(path, deadPath); moveErr != nil {
				return fmt.Errorf("auditbatcher: quarantine queue record %s: %w", id, errors.Join(err, moveErr))
			}
		}
	}
	return nil
}

func (q *Queue) verifyPlaintextOpenAllowedLocked() error {
	seen, err := q.queueEncryptionSeenLocked()
	if err != nil {
		return err
	}
	if seen {
		return errQueueEncryptionPreviouslySeen
	}
	return nil
}

func (q *Queue) markEncryptionSeenLocked() error {
	seen, err := q.queueEncryptionSeenLocked()
	if err != nil {
		return err
	}
	if seen {
		return nil
	}
	// Defense-in-depth against accidental downgrade-after-encryption, such as a
	// config or Secret regression after the queue drains empty. This is not a
	// cryptographic guarantee: a writer on the queue volume can delete the marker.
	// Encrypted v2 records remain the strong signal when any records exist.
	data, err := json.Marshal(queueState{EncryptionSeen: true})
	if err != nil {
		return fmt.Errorf("auditbatcher: marshal queue state: %w", err)
	}
	if err := durableWrite(q.queueStatePath(), append(data, '\n')); err != nil {
		return fmt.Errorf("auditbatcher: write queue state: %w", err)
	}
	return nil
}

func (q *Queue) queueEncryptionSeenLocked() (bool, error) {
	data, err := securefile.Read(q.queueStatePath(), securefile.Options{
		MaxBytes:      maxQueueStateBytes,
		RejectSymlink: true,
		OwnedState:    true,
	})
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("auditbatcher: read queue state: %w", err)
	}
	var state queueState
	if err := json.Unmarshal(data, &state); err != nil {
		return false, fmt.Errorf("auditbatcher: decode queue state: %w", err)
	}
	return state.EncryptionSeen, nil
}

func (q *Queue) queueStatePath() string {
	return filepath.Join(q.dir, queueStateFileName)
}

// uniqueRecoveryPath finds a free filename in pendingDir for a recovered
// inflight record. The plain id is tried first; if taken, recovery suffixes
// are appended after the full original id so recovered records keep the same
// timestamp prefix and do not sort behind newer queue entries.
func uniqueRecoveryPath(pendingDir, id string) (string, error) {
	return uniqueRecoverySuffixPath(pendingDir, id)
}

// uniqueDeadPath finds a free filename in deadDir for a quarantined corrupt
// record. It preserves any existing dead-letter evidence with the same id.
func uniqueDeadPath(deadDir, id string) (string, error) {
	return uniquePrefixedPath(deadDir, id, "dead", "dead-letter")
}

func uniquePrefixedPath(dir, id, prefix, label string) (string, error) {
	candidate := filepath.Join(dir, id)
	if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
		return candidate, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("auditbatcher: stat %s target: %w", label, err)
	}
	for i := 0; i < 1024; i++ {
		var name string
		if i == 0 {
			name = prefix + "-" + id
		} else {
			name = fmt.Sprintf("%s-%d-%s", prefix, i, id)
		}
		candidate = filepath.Join(dir, name)
		_, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("auditbatcher: stat %s target: %w", label, err)
		}
	}
	return "", fmt.Errorf("auditbatcher: too many existing %s candidates for %s", label, id)
}

func uniqueRecoverySuffixPath(dir, id string) (string, error) {
	candidate := filepath.Join(dir, id)
	if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
		return candidate, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("auditbatcher: stat recovery target: %w", err)
	}
	for i := 0; i < 1024; i++ {
		var name string
		if i == 0 {
			name = id + "-recovered" + recordExt
		} else {
			name = fmt.Sprintf("%s-recovered-%d%s", id, i, recordExt)
		}
		candidate = filepath.Join(dir, name)
		_, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("auditbatcher: stat recovery target: %w", err)
		}
	}
	return "", fmt.Errorf("auditbatcher: too many existing recovery candidates for %s", id)
}

// sweepStaleTempsLocked removes .tmp-* files left behind by a previous
// process crash mid-durableWrite. Safe to call only at Open time, before any
// goroutine can call Enqueue and create a legitimate .tmp-* file.
func sweepStaleTempsLocked(dir string) error {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("auditbatcher: scan for stale temps in %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, ".tmp-") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("auditbatcher: remove stale temp %s: %w", name, err)
		}
	}
	return nil
}

func (q *Queue) nextIDLocked(batchID string) (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("auditbatcher: random queue id: %w", err)
	}
	return fmt.Sprintf("%020d-%s-%s%s", q.now().UTC().UnixNano(), batchID, hex.EncodeToString(random), recordExt), nil
}

func validateBatch(batch Batch, maxPayloadBytes uint64) error {
	if uint64(len(batch.Payload)) > maxPayloadBytes {
		return fmt.Errorf("%w: payload=%d max=%d", conductor.ErrPayloadTooLarge, len(batch.Payload), maxPayloadBytes)
	}
	if err := batch.Envelope.Validate(); err != nil {
		return err
	}
	return batch.Envelope.ValidatePayload(batch.Payload)
}

func readRecord(path string, maxPayloadBytes uint64) (diskRecord, error) {
	record, _, _, err := readRecordWithKeyring(path, maxPayloadBytes, nil)
	return record, err
}

func (q *Queue) readRecord(path string) (diskRecord, error) {
	record, _, _, err := readRecordWithKeyring(path, q.maxPayloadBytes, q.keyring)
	return record, err
}

func readRecordWithKeyring(path string, maxPayloadBytes uint64, keyring *Keyring) (diskRecord, string, bool, error) {
	path = filepath.Clean(path)
	limit, err := recordReadLimit(maxPayloadBytes)
	if err != nil {
		return diskRecord{}, "", false, err
	}
	if keyring != nil {
		limit, err = encryptedRecordReadLimit(limit)
		if err != nil {
			return diskRecord{}, "", false, err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return diskRecord{}, "", false, fmt.Errorf("auditbatcher: stat record: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return diskRecord{}, "", false, corruptRecordError(fmt.Errorf("auditbatcher: record %s must not be a symlink", path))
	}
	if !info.Mode().IsRegular() {
		return diskRecord{}, "", false, corruptRecordError(fmt.Errorf("auditbatcher: record %s is not a regular file", path))
	}
	if info.Size() > limit {
		return diskRecord{}, "", false, corruptRecordError(fmt.Errorf("%w: record_bytes=%d cap=%d", conductor.ErrPayloadTooLarge, info.Size(), limit))
	}
	// OwnedState: this is Pipelock own durable audit-queue state, written by
	// durableWrite at 0600. Kubernetes fsGroup re-widens it to 0660 on every
	// mount, so a strict group-write refusal would keep a non-root follower from
	// recovering or delivering queued audit batches after restart. A refusal here
	// becomes ErrCorruptRecord and Claim moves the record to dead/, so strictness
	// costs delivery of that audit data rather than merely delaying it.
	//
	// When a keyring is configured, queue records are encrypted before
	// durableWrite under a keyring required to live outside this queue directory.
	// Group access to the widened volume can therefore expose ciphertext and
	// metadata, but not the audit payload. Plaintext compatibility mode is
	// explicit and keeps the pre-encryption v1 record format.
	data, err := securefile.Read(path, securefile.Options{
		MaxBytes:      limit,
		RejectSymlink: true,
		OwnedState:    true,
	})
	if err != nil {
		return diskRecord{}, "", false, corruptRecordError(fmt.Errorf("auditbatcher: read record: %w", err))
	}

	record, keyID, legacy, err := decryptDiskRecord(data, keyring)
	if err != nil {
		if errors.Is(err, errQueueKeyUnavailable) || errors.Is(err, ErrRecordAuthFailed) {
			return diskRecord{}, keyID, legacy, err
		}
		return diskRecord{}, keyID, legacy, corruptRecordError(err)
	}
	if record.Version != recordVersion {
		return diskRecord{}, keyID, legacy, corruptRecordError(fmt.Errorf("auditbatcher: plaintext version=%d want=%d", record.Version, recordVersion))
	}
	if record.EnqueuedAt.IsZero() {
		return diskRecord{}, keyID, legacy, corruptRecordError(errors.New("auditbatcher: missing enqueued_at"))
	}
	batch := Batch{Envelope: record.Envelope, Payload: record.Payload}
	if err := validateBatch(batch, maxPayloadBytes); err != nil {
		return diskRecord{}, keyID, legacy, corruptRecordError(err)
	}
	return record, keyID, legacy, nil
}

func corruptRecordError(err error) error {
	return fmt.Errorf("%w: %w", ErrCorruptRecord, err)
}

func recordReadLimit(maxPayloadBytes uint64) (int64, error) {
	if maxPayloadBytes > ((maxRecordReadBytes-maxRecordMetadataBytes)/4)*3-2 {
		return 0, fmt.Errorf("auditbatcher: max payload bytes too large: %d", maxPayloadBytes)
	}
	encodedPayloadBytes := ((maxPayloadBytes + 2) / 3) * 4
	if encodedPayloadBytes > maxRecordReadBytes-maxRecordMetadataBytes {
		return 0, fmt.Errorf("auditbatcher: max payload bytes too large: %d", maxPayloadBytes)
	}
	return uint64ToInt64(encodedPayloadBytes + maxRecordMetadataBytes)
}

func encryptedRecordReadLimit(plaintextLimit int64) (int64, error) {
	if plaintextLimit < 0 {
		return 0, fmt.Errorf("auditbatcher: encrypted record plaintext limit must not be negative: %d", plaintextLimit)
	}
	plaintextBytes := uint64(plaintextLimit)
	if plaintextBytes > maxRecordReadBytes-queueAEADOverheadBytes {
		return 0, fmt.Errorf("auditbatcher: encrypted record plaintext limit too large: %d", plaintextLimit)
	}
	ciphertextBytes := plaintextBytes + queueAEADOverheadBytes
	// encoding/json represents []byte as padded standard base64. Check before
	// multiplying so a hostile configured limit cannot wrap the calculation.
	if ciphertextBytes > ((maxRecordReadBytes-encryptedRecordMetadataBytes)/4)*3-2 {
		return 0, fmt.Errorf("auditbatcher: encrypted record ciphertext limit too large: %d", ciphertextBytes)
	}
	encodedCiphertextBytes := ((ciphertextBytes + 2) / 3) * 4
	return uint64ToInt64(encodedCiphertextBytes + encryptedRecordMetadataBytes)
}

func uint64ToInt64(value uint64) (int64, error) {
	if value > maxRecordReadBytes {
		return 0, fmt.Errorf("auditbatcher: record read limit too large: %d", value)
	}
	converted, err := strconv.ParseInt(strconv.FormatUint(value, 10), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("auditbatcher: convert record read limit: %w", err)
	}
	return converted, nil
}

func (q *Queue) updateInflightRecordLocked(id string, mutate func(*diskRecord)) error {
	path := filepath.Join(q.inflightDir, id)
	record, _, _, err := readRecordWithKeyring(path, q.maxPayloadBytes, q.keyring)
	if err != nil {
		return fmt.Errorf("auditbatcher: annotate inflight %s: %w", id, err)
	}
	mutate(&record)
	data, err := marshalQueueRecord(record, q.keyring)
	if err != nil {
		return fmt.Errorf("auditbatcher: marshal annotated record %s: %w", id, err)
	}
	if err := durableWrite(path, data); err != nil {
		return fmt.Errorf("auditbatcher: write annotated record %s: %w", id, err)
	}
	return nil
}

func marshalQueueRecord(record diskRecord, keyring *Keyring) ([]byte, error) {
	if keyring == nil {
		return json.Marshal(record)
	}
	return encryptDiskRecord(record, keyring)
}

func normalizeAccountingReason(reason string) string {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return "unspecified"
	}
	var b strings.Builder
	b.Grow(len(reason))
	lastUnderscore := false
	for _, r := range reason {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if ok {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if (r == '_' || r == '-' || r == '.') && b.Len() > 0 {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore && b.Len() > 0 {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	normalized := strings.Trim(b.String(), "_-.")
	if normalized == "" {
		return "unspecified"
	}
	if len(normalized) > conductor.MaxDropReasonBytes {
		normalized = normalized[:conductor.MaxDropReasonBytes]
		normalized = strings.TrimRight(normalized, "_-.")
	}
	if normalized == "" {
		return "unspecified"
	}
	return normalized
}

func listRecordFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: list %s: %w", dir, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, recordExt) {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func ensurePrivateQueueDirs(dir string) (string, string, string, string, error) {
	resolvedDir, err := ensurePrivateDir(dir)
	if err != nil {
		return "", "", "", "", err
	}
	pendingDir := filepath.Join(resolvedDir, "pending")
	inflightDir := filepath.Join(resolvedDir, "inflight")
	deadDir := filepath.Join(resolvedDir, "dead")
	for _, subdir := range []*string{&pendingDir, &inflightDir, &deadDir} {
		resolvedSubdir, err := ensurePrivateDir(*subdir)
		if err != nil {
			return "", "", "", "", err
		}
		if err := ensurePathContained(resolvedDir, resolvedSubdir); err != nil {
			return "", "", "", "", err
		}
		*subdir = resolvedSubdir
	}
	return resolvedDir, pendingDir, inflightDir, deadDir, nil
}

func ensurePrivateDir(dir string) (string, error) {
	clean := filepath.Clean(dir)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("auditbatcher: absolute dir %s: %w", dir, err)
	}
	if err := rejectSymlinkAncestors(abs); err != nil {
		return "", err
	}
	if err := os.MkdirAll(clean, dirMode); err != nil {
		return "", fmt.Errorf("auditbatcher: create dir %s: %w", dir, err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("auditbatcher: stat dir %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("auditbatcher: dir %s must not be a symlink", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("auditbatcher: %s is not a directory", dir)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("auditbatcher: resolve dir %s: %w", dir, err)
	}
	resolvedInfo, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("auditbatcher: stat resolved dir %s: %w", resolved, err)
	}
	if resolvedInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("auditbatcher: resolved dir %s must not be a symlink", resolved)
	}
	if !resolvedInfo.IsDir() {
		return "", fmt.Errorf("auditbatcher: resolved path %s is not a directory", resolved)
	}
	if resolvedInfo.Mode().Perm() != dirMode {
		if err := os.Chmod(resolved, dirMode); err != nil {
			return "", fmt.Errorf("auditbatcher: chmod dir %s: %w", resolved, err)
		}
	}
	return resolved, nil
}

func rejectSymlinkAncestors(abs string) error {
	dir := filepath.Dir(abs)
	parents := make([]string, 0, 8)
	for {
		parents = append(parents, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	for i := len(parents) - 1; i >= 0; i-- {
		info, err := os.Lstat(parents[i])
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return fmt.Errorf("auditbatcher: stat dir ancestor %s: %w", parents[i], err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("auditbatcher: dir ancestor %s must not be a symlink", parents[i])
		}
		if !info.IsDir() {
			return fmt.Errorf("auditbatcher: dir ancestor %s is not a directory", parents[i])
		}
	}
	return nil
}

func ensurePathContained(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return fmt.Errorf("auditbatcher: resolve queue subdir %s: %w", path, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("auditbatcher: queue subdir %s escapes root %s", path, root)
	}
	return nil
}

func durableWrite(path string, data []byte) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("auditbatcher: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auditbatcher: write temp: %w", err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auditbatcher: chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auditbatcher: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("auditbatcher: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("auditbatcher: rename temp: %w", err)
	}
	cleanup = false
	return fsyncDir(dir)
}

func moveToDead(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	if err := fsyncDir(filepath.Dir(src)); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(dst))
}

func fsyncDir(dir string) error {
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("auditbatcher: open dir for fsync %s: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		if ignoreDirSyncError(err) {
			return nil
		}
		return fmt.Errorf("auditbatcher: fsync dir %s: %w", dir, err)
	}
	return nil
}

func validateRecordID(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("auditbatcher: empty queue id")
	}
	if filepath.Base(id) != id || strings.ContainsAny(id, `/\`) {
		return fmt.Errorf("auditbatcher: invalid queue id %q", id)
	}
	if !strings.HasSuffix(id, recordExt) {
		return fmt.Errorf("auditbatcher: invalid queue id extension %q", id)
	}
	return nil
}
