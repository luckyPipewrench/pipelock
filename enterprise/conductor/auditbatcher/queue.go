//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package auditbatcher provides follower-side durable queuing primitives for
// Conductor-bound audit batches. It intentionally sits outside emit.Emitter
// because Conductor audit delivery must track retry and drop state instead of
// being fire-and-forget.
//
// Concurrency model: a Queue is SINGLE-PROCESS per directory. The mutex
// serializes access within one process; nothing prevents a second pipelock
// process from opening the same dir and corrupting the queue via concurrent
// renames. Operators must enforce one writer per durable_audit_queue_dir via
// systemd, k8s leadership election, or simple deployment discipline.
package auditbatcher

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
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

var (
	ErrQueueEmpty    = errors.New("auditbatcher: queue empty")
	ErrQueueFull     = errors.New("auditbatcher: queue full")
	ErrCorruptRecord = errors.New("auditbatcher: corrupt record")
)

type Config struct {
	Dir             string
	MaxPending      int
	MaxPayloadBytes uint64
}

type Batch struct {
	Envelope conductor.AuditBatchEnvelope
	Payload  []byte
}

type Lease struct {
	ID    string
	Batch Batch
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
	now             func() time.Time
	mu              sync.Mutex
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
	dir, pendingDir, inflightDir, deadDir, err := ensurePrivateQueueDirs(cleanDir)
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
		now:             func() time.Time { return time.Now().UTC() },
	}
	// Sweep .tmp-* debris from any prior crash mid-write. Live writes use
	// CreateTemp+rename; only crashes leave .tmp-* files behind, and they
	// otherwise accumulate forever (listRecordFiles correctly ignores them,
	// so they're invisible to claim but visible to df). Opening fresh is the
	// only safe time to remove them — no other writer could legitimately
	// have a .tmp-* in flight before Open returns.
	for _, dir := range []string{q.pendingDir, q.inflightDir, q.deadDir} {
		if err := sweepStaleTempsLocked(dir); err != nil {
			return nil, err
		}
	}
	if err := q.recoverInflightLocked(); err != nil {
		return nil, err
	}
	return q, nil
}

func (q *Queue) Enqueue(batch Batch) (string, error) {
	if q == nil {
		return "", errors.New("auditbatcher: nil queue")
	}
	if err := validateBatch(batch, q.maxPayloadBytes); err != nil {
		return "", err
	}
	q.mu.Lock()
	defer q.mu.Unlock()

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
	data, err := json.Marshal(record)
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
		record, err := readRecord(inflightPath, q.maxPayloadBytes)
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
		return &Lease{ID: id, Batch: Batch{Envelope: record.Envelope, Payload: record.Payload}}, nil
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
	path = filepath.Clean(path)
	limit, err := recordReadLimit(maxPayloadBytes)
	if err != nil {
		return diskRecord{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return diskRecord{}, fmt.Errorf("auditbatcher: stat record: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return diskRecord{}, corruptRecordError(fmt.Errorf("auditbatcher: record %s must not be a symlink", path))
	}
	if !info.Mode().IsRegular() {
		return diskRecord{}, corruptRecordError(fmt.Errorf("auditbatcher: record %s is not a regular file", path))
	}
	if info.Size() > limit {
		return diskRecord{}, corruptRecordError(fmt.Errorf("%w: record_bytes=%d cap=%d", conductor.ErrPayloadTooLarge, info.Size(), limit))
	}
	f, err := os.Open(path)
	if err != nil {
		return diskRecord{}, fmt.Errorf("auditbatcher: open record: %w", err)
	}
	defer func() { _ = f.Close() }()

	var record diskRecord
	decoder := json.NewDecoder(io.LimitReader(f, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return diskRecord{}, corruptRecordError(fmt.Errorf("auditbatcher: decode record: %w", err))
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return diskRecord{}, corruptRecordError(errors.New("auditbatcher: trailing JSON document"))
	}
	if record.Version != recordVersion {
		return diskRecord{}, corruptRecordError(fmt.Errorf("auditbatcher: record version=%d want=%d", record.Version, recordVersion))
	}
	if record.EnqueuedAt.IsZero() {
		return diskRecord{}, corruptRecordError(errors.New("auditbatcher: missing enqueued_at"))
	}
	batch := Batch{Envelope: record.Envelope, Payload: record.Payload}
	if err := validateBatch(batch, maxPayloadBytes); err != nil {
		return diskRecord{}, corruptRecordError(err)
	}
	return record, nil
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
	record, err := readRecord(path, q.maxPayloadBytes)
	if err != nil {
		return fmt.Errorf("auditbatcher: annotate inflight %s: %w", id, err)
	}
	mutate(&record)
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("auditbatcher: marshal annotated record %s: %w", id, err)
	}
	if err := durableWrite(path, data); err != nil {
		return fmt.Errorf("auditbatcher: write annotated record %s: %w", id, err)
	}
	return nil
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
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
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
