//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// ErrReplayConflict is returned by CommitIfNew when a record's nonce or transfer
// has already been committed. It is a fail-closed replay rejection, distinct
// from a store I/O error.
var ErrReplayConflict = errors.New("counterparty record replays a committed nonce or transfer")

var (
	replayStoreLockTimeout       = 5 * time.Second
	replayStoreLockRetryInterval = 10 * time.Millisecond
)

// ReplayEntry is the durable unit of replay state for one accepted record. Two
// uniqueness constraints are enforced: NonceKey rejects the identical signed
// record, TransferKey rejects the same two receipts + payload re-signed under a
// fresh nonce (coverage-count inflation).
type ReplayEntry struct {
	NonceKey    NonceKey    `json:"nonce_key"`
	TransferKey TransferKey `json:"transfer_key"`
	RecordHash  string      `json:"record_hash"`
	Timestamp   time.Time   `json:"ts"`
}

// ReplayStore records accepted counterparty records and rejects replays. The
// verifier calls CommitIfNew only after every non-mutating check has passed, so
// a rejected record never consumes state. Implementations must be safe for
// concurrent use and must fail closed (return a non-conflict error) on any
// condition where they cannot prove non-replay.
type ReplayStore interface {
	// CommitIfNew atomically rejects the entry if either its NonceKey or its
	// TransferKey was already committed (ErrReplayConflict), otherwise persists
	// it and returns nil. On any I/O, lock, or corruption failure it returns a
	// non-ErrReplayConflict error so the verifier fails closed.
	CommitIfNew(entry ReplayEntry) error
}

// MemReplayStore is a thread-safe in-memory replay set. It provides no
// durability across process restarts; use FileReplayStore for that.
type MemReplayStore struct {
	mu        sync.Mutex
	nonces    map[NonceKey]struct{}
	transfers map[TransferKey]struct{}
}

// NewMemReplayStore returns an empty in-memory replay store.
func NewMemReplayStore() *MemReplayStore {
	return &MemReplayStore{
		nonces:    make(map[NonceKey]struct{}),
		transfers: make(map[TransferKey]struct{}),
	}
}

// CommitIfNew implements ReplayStore.
func (s *MemReplayStore) CommitIfNew(entry ReplayEntry) error {
	if err := validateReplayEntry(entry); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nonces[entry.NonceKey]; ok {
		return fmt.Errorf("%w: nonce already committed", ErrReplayConflict)
	}
	if _, ok := s.transfers[entry.TransferKey]; ok {
		return fmt.Errorf("%w: transfer already committed", ErrReplayConflict)
	}
	s.nonces[entry.NonceKey] = struct{}{}
	s.transfers[entry.TransferKey] = struct{}{}
	return nil
}

// FileReplayStore is a durable, append-only replay store backed by a JSONL file.
// Each accepted entry is written as one line and fsync'd before CommitIfNew
// returns, so a committed record survives a restart. A malformed line at open
// makes the store unhealthy and every CommitIfNew fails closed rather than
// silently dropping replay history.
type FileReplayStore struct {
	mu         sync.Mutex
	path       string
	file       *os.File
	nonces     map[NonceKey]struct{}
	transfers  map[TransferKey]struct{}
	readOffset int64
	healthy    bool
}

// OpenFileReplayStore opens (creating if needed) a durable replay store at path.
// It loads and indexes every existing entry; a corrupt line returns an error and
// leaves no usable store, so callers fail closed instead of losing history.
//
// The store is safe to share across processes: each CommitIfNew re-indexes any
// entries other processes appended under an exclusive cross-process file lock
// before deciding, so two processes cannot both accept the same entry.
//
// Durability limitation: the newly created store file's directory entry is
// fsync'd best-effort (directory fsync is not portable). On a platform without
// directory fsync, a power loss in the narrow window between first creation and
// the first committed entry becoming durable could lose the file. Operators
// requiring strict first-write durability there should pre-create the store file.
//
// Enforcement limitation: this store treats a missing or empty file at open as a
// fresh store (O_CREATE). Truncation WHILE a store is running is detected and
// fails closed (see reindexLocked), but if the file is deleted or truncated
// out-of-band while no process holds it open, previously accepted nonces are
// forgotten on the next open and could be re-accepted. A deployment that must
// survive out-of-band deletion/truncation should keep the store on
// non-truncating persistent storage or pair it with an external checkpoint.
func OpenFileReplayStore(path string) (*FileReplayStore, error) {
	if path == "" {
		return nil, errors.New("replay store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create replay store dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open replay store: %w", err)
	}
	fsyncDir(filepath.Dir(path)) // best-effort: persist the new dir entry where supported
	s := &FileReplayStore{
		path:      path,
		file:      f,
		nonces:    make(map[NonceKey]struct{}),
		transfers: make(map[TransferKey]struct{}),
	}
	release, err := acquireReplayStoreLock(s.file)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	err = s.reindexLocked()
	release()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	s.healthy = true
	return s, nil
}

// reindexLocked indexes every complete line appended since the last read offset.
// The caller must hold both the in-process mutex and the cross-process file lock.
// A corrupt or torn (newline-less) trailing line fails closed rather than being
// silently dropped or overwritten.
func (s *FileReplayStore) reindexLocked() error {
	info, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("stat replay store: %w", err)
	}
	if info.Size() < s.readOffset {
		return fmt.Errorf("replay store %s shrank from %d to %d bytes; refusing to lose replay history", s.path, s.readOffset, info.Size())
	}
	if _, err := s.file.Seek(s.readOffset, io.SeekStart); err != nil {
		return fmt.Errorf("seek replay store: %w", err)
	}
	reader := bufio.NewReader(s.file)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return fmt.Errorf("replay store %s has an incomplete trailing line", s.path)
			}
			if indexErr := s.indexLine(line[:len(line)-1]); indexErr != nil {
				return indexErr
			}
			s.readOffset += int64(len(line))
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read replay store: %w", err)
		}
	}
	return nil
}

func (s *FileReplayStore) indexLine(raw []byte) error {
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("replay store %s is corrupt: %w", s.path, err)
	}
	var entry ReplayEntry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entry); err != nil {
		return fmt.Errorf("replay store %s is corrupt: %w", s.path, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("replay store %s has trailing tokens: %w", s.path, err)
		}
		return fmt.Errorf("replay store %s has trailing tokens", s.path)
	}
	if err := validateReplayEntry(entry); err != nil {
		return fmt.Errorf("replay store %s has an invalid entry: %w", s.path, err)
	}
	s.nonces[entry.NonceKey] = struct{}{}
	s.transfers[entry.TransferKey] = struct{}{}
	return nil
}

// CommitIfNew implements ReplayStore with durable, fsync'd, cross-process-safe
// persistence. Under an exclusive file lock it re-indexes entries appended by
// other processes, checks for a nonce or transfer conflict, then appends and
// fsyncs, so concurrent processes sharing one store cannot both accept an entry.
func (s *FileReplayStore) CommitIfNew(entry ReplayEntry) error {
	if err := validateReplayEntry(entry); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.healthy {
		return errors.New("replay store is unhealthy")
	}
	release, err := acquireReplayStoreLock(s.file)
	if err != nil {
		return fmt.Errorf("lock replay store: %w", err)
	}
	defer release()

	if err := verifyStorePathInode(s.file, s.path); err != nil {
		s.healthy = false
		return err
	}
	if err := s.reindexLocked(); err != nil {
		s.healthy = false
		return err
	}
	if _, ok := s.nonces[entry.NonceKey]; ok {
		return fmt.Errorf("%w: nonce already committed", ErrReplayConflict)
	}
	if _, ok := s.transfers[entry.TransferKey]; ok {
		return fmt.Errorf("%w: transfer already committed", ErrReplayConflict)
	}
	encodedLen, err := s.appendEntryLocked(entry)
	if err != nil {
		s.healthy = false
		return err
	}
	s.nonces[entry.NonceKey] = struct{}{}
	s.transfers[entry.TransferKey] = struct{}{}
	s.readOffset += int64(encodedLen)
	return nil
}

func (s *FileReplayStore) appendEntryLocked(entry ReplayEntry) (int, error) {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return 0, fmt.Errorf("marshal replay entry: %w", err)
	}
	encoded = append(encoded, '\n')
	n, err := s.file.Write(encoded)
	if err != nil {
		return 0, fmt.Errorf("write replay entry: %w", err)
	}
	if n != len(encoded) {
		return 0, fmt.Errorf("write replay entry: %w", io.ErrShortWrite)
	}
	if err := s.file.Sync(); err != nil {
		return 0, fmt.Errorf("fsync replay entry: %w", err)
	}
	if err := verifyStorePathInode(s.file, s.path); err != nil {
		return 0, err
	}
	return len(encoded), nil
}

// fsyncDir best-effort flushes a directory entry to disk. Directory fsync is not
// portable (it is a no-op or unsupported on some platforms), so failures are
// ignored; on Linux it persists a newly created store file's directory entry.
func fsyncDir(dir string) {
	d, err := os.Open(filepath.Clean(dir)) // #nosec G304 -- dir derives from the operator-configured replay store path
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

func validateReplayEntry(entry ReplayEntry) error {
	if err := validateToken("replay nonce side_record_key_id", entry.NonceKey.SideRecordKeyID); err != nil {
		return err
	}
	if err := validateToken("replay nonce sender_identity", entry.NonceKey.SenderIdentity); err != nil {
		return err
	}
	if err := validateToken("replay nonce receiver_identity", entry.NonceKey.ReceiverIdentity); err != nil {
		return err
	}
	if err := validateToken("replay nonce nonce", entry.NonceKey.Nonce); err != nil {
		return err
	}
	if err := validateToken("replay transfer sender_identity", entry.TransferKey.SenderIdentity); err != nil {
		return err
	}
	if err := validateToken("replay transfer receiver_identity", entry.TransferKey.ReceiverIdentity); err != nil {
		return err
	}
	if err := validateHash("replay transfer payload_hash", entry.TransferKey.PayloadHash); err != nil {
		return err
	}
	if err := validateToken("replay transfer sender_receipt_id", entry.TransferKey.SenderReceiptID); err != nil {
		return err
	}
	if err := validateToken("replay transfer receiver_receipt_id", entry.TransferKey.ReceiverReceiptID); err != nil {
		return err
	}
	if err := validateHash("replay transfer sender_action_hash", entry.TransferKey.SenderActionHash); err != nil {
		return err
	}
	if err := validateHash("replay transfer receiver_action_hash", entry.TransferKey.ReceiverActionHash); err != nil {
		return err
	}
	if err := validateHash("replay record_hash", entry.RecordHash); err != nil {
		return err
	}
	if entry.Timestamp.IsZero() {
		return fmt.Errorf("%w: replay timestamp is required", ErrMalformedBinding)
	}
	return nil
}

// Close releases the underlying file.
func (s *FileReplayStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = false
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
