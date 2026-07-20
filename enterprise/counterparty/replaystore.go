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
// fresh nonce (coverage-count inflation). Timestamp is the signed side-record
// timestamp used to retain the nonce key. TransferTimestamp is the older signed
// receipt timestamp used to retain the transfer key; unlike the side-record
// timestamp, it cannot be refreshed by re-signing the same transfer. The pruned
// flags persist partial compaction so a retained JSONL entry does not restore a
// key whose retention horizon has already expired after restart.
type ReplayEntry struct {
	NonceKey          NonceKey    `json:"nonce_key"`
	TransferKey       TransferKey `json:"transfer_key"`
	RecordHash        string      `json:"record_hash"`
	Timestamp         time.Time   `json:"ts"`
	TransferTimestamp time.Time   `json:"transfer_ts"`
	NoncePruned       bool        `json:"nonce_pruned,omitempty"`
	TransferPruned    bool        `json:"transfer_pruned,omitempty"`
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

// CompactableReplayStore is the optional replay-store maintenance interface.
// VerifyCounterparty intentionally depends only on ReplayStore; compaction is a
// caller-driven operation with a security-critical retention contract.
type CompactableReplayStore interface {
	ReplayStore

	// Compact removes entries only after both replay keys represented by that
	// entry are strictly before before and returns the number removed. Nonce
	// retention is based on ReplayEntry.Timestamp; transfer retention is based
	// on ReplayEntry.TransferTimestamp.
	//
	// SECURITY CONTRACT: callers MUST pass a horizon that is no newer than the
	// verifier freshness cutoff for every verifier using this store
	// (before <= Now - MaxAge). Passing a newer horizon re-opens replay for the
	// pruned time window; the store cannot validate MaxAge because MaxAge is a
	// verify-time parameter.
	Compact(before time.Time) (removed int, err error)
}

// MemReplayStore is a thread-safe in-memory replay set. It provides no
// durability across process restarts; use FileReplayStore for that.
type MemReplayStore struct {
	mu        sync.Mutex
	nonces    map[NonceKey]time.Time
	transfers map[TransferKey]time.Time
	entries   map[replayEntryKey]ReplayEntry
}

type replayEntryKey struct {
	nonce    NonceKey
	transfer TransferKey
}

// NewMemReplayStore returns an empty in-memory replay store.
func NewMemReplayStore() *MemReplayStore {
	return &MemReplayStore{
		nonces:    make(map[NonceKey]time.Time),
		transfers: make(map[TransferKey]time.Time),
		entries:   make(map[replayEntryKey]ReplayEntry),
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
	s.nonces[entry.NonceKey] = entry.Timestamp
	s.transfers[entry.TransferKey] = entry.TransferTimestamp
	s.entries[replayEntryKey{nonce: entry.NonceKey, transfer: entry.TransferKey}] = entry
	return nil
}

// Compact implements CompactableReplayStore; see CompactableReplayStore for the
// caller's freshness contract.
func (s *MemReplayStore) Compact(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newNonces := make(map[NonceKey]time.Time)
	newTransfers := make(map[TransferKey]time.Time)
	removed := 0
	for key, entry := range s.entries {
		keepNonce := !entry.Timestamp.Before(before)
		keepTransfer := !entry.TransferTimestamp.Before(before)
		if keepNonce {
			newNonces[key.nonce] = entry.Timestamp
		}
		if keepTransfer {
			newTransfers[key.transfer] = entry.TransferTimestamp
		}
		if !keepNonce && !keepTransfer {
			delete(s.entries, key)
			removed++
		}
	}
	s.nonces = newNonces
	s.transfers = newTransfers
	return removed, nil
}

// FileReplayStore is a durable, append-only replay store backed by a JSONL file.
// Each accepted entry is written as one line and fsync'd before CommitIfNew
// returns, so a committed record survives a restart. A malformed line at open
// makes the store unhealthy and every CommitIfNew fails closed rather than
// silently dropping replay history.
type FileReplayStore struct {
	opMu       sync.Mutex
	mu         sync.Mutex
	path       string
	file       *os.File
	nonces     map[NonceKey]time.Time
	transfers  map[TransferKey]time.Time
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
		nonces:    make(map[NonceKey]time.Time),
		transfers: make(map[TransferKey]time.Time),
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
	entry, err := parseReplayEntryLine(s.path, raw)
	if err != nil {
		return err
	}
	if entry.retainsNonce() {
		s.nonces[entry.NonceKey] = entry.Timestamp
	}
	if entry.retainsTransfer() {
		s.transfers[entry.TransferKey] = entry.TransferTimestamp
	}
	return nil
}

func parseReplayEntryLine(path string, raw []byte) (ReplayEntry, error) {
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return ReplayEntry{}, fmt.Errorf("replay store %s is corrupt: %w", path, err)
	}
	var entry ReplayEntry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entry); err != nil {
		return ReplayEntry{}, fmt.Errorf("replay store %s is corrupt: %w", path, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		if err != nil {
			return ReplayEntry{}, fmt.Errorf("replay store %s has trailing tokens: %w", path, err)
		}
		return ReplayEntry{}, fmt.Errorf("replay store %s has trailing tokens", path)
	}
	if entry.TransferTimestamp.IsZero() {
		entry.TransferTimestamp = entry.Timestamp
	}
	if err := validateReplayEntry(entry); err != nil {
		return ReplayEntry{}, fmt.Errorf("replay store %s has an invalid entry: %w", path, err)
	}
	return entry, nil
}

// CommitIfNew implements ReplayStore with durable, fsync'd, cross-process-safe
// persistence. Under an exclusive file lock it re-indexes entries appended by
// other processes, checks for a nonce or transfer conflict, then appends and
// fsyncs, so concurrent processes sharing one store cannot both accept an entry.
func (s *FileReplayStore) CommitIfNew(entry ReplayEntry) error {
	if err := validateReplayEntry(entry); err != nil {
		return err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
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
	s.nonces[entry.NonceKey] = entry.Timestamp
	s.transfers[entry.TransferKey] = entry.TransferTimestamp
	s.readOffset += int64(encodedLen)
	return nil
}

// Compact implements CompactableReplayStore. It rewrites the durable JSONL file
// atomically and keeps any entry whose nonce or transfer key is still inside its
// retention horizon. See CompactableReplayStore for the caller's freshness
// contract.
func (s *FileReplayStore) Compact(before time.Time) (removed int, err error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	fail := func(err error) (int, error) {
		s.healthy = false
		s.mu.Unlock()
		return removed, err
	}
	if !s.healthy {
		return fail(errors.New("replay store is unhealthy"))
	}
	release, err := acquireReplayStoreLock(s.file)
	if err != nil {
		return fail(fmt.Errorf("lock replay store: %w", err))
	}
	locked := true
	defer func() {
		if locked {
			release()
		}
	}()

	if err := verifyStorePathInode(s.file, s.path); err != nil {
		return fail(err)
	}
	if err := s.reindexLocked(); err != nil {
		return fail(err)
	}
	path := s.path
	activeFile := s.file
	dir := filepath.Dir(path)
	s.mu.Unlock()

	failUnlocked := func(err error) (int, error) {
		s.mu.Lock()
		s.healthy = false
		s.mu.Unlock()
		return removed, err
	}
	tmp, err := os.CreateTemp(filepath.Clean(dir), filepath.Base(s.path)+".compact-*")
	if err != nil {
		return failUnlocked(fmt.Errorf("create compacted replay store: %w", err))
	}
	tmpPath := tmp.Name()
	renamed := false
	// Remove the temp file unless it was renamed into place. A double Close on
	// the already-closed temp is harmless; the guard keeps every error branch a
	// single return.
	defer func() {
		if !renamed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := activeFile.Seek(0, io.SeekStart); err != nil {
		return failUnlocked(fmt.Errorf("seek replay store for compact: %w", err))
	}
	newNonces := make(map[NonceKey]time.Time)
	newTransfers := make(map[TransferKey]time.Time)
	newSize := int64(0)
	retentionChanged := false
	reader := bufio.NewReader(activeFile)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return failUnlocked(fmt.Errorf("replay store %s has an incomplete trailing line", path))
			}
			entry, parseErr := parseReplayEntryLine(path, line[:len(line)-1])
			if parseErr != nil {
				return failUnlocked(parseErr)
			}
			keepNonce := entry.retainsNonce() && !entry.Timestamp.Before(before)
			keepTransfer := entry.retainsTransfer() && !entry.TransferTimestamp.Before(before)
			if !keepNonce && !keepTransfer {
				removed++
			} else {
				retentionChanged = retentionChanged || entry.NoncePruned != !keepNonce || entry.TransferPruned != !keepTransfer
				entry.NoncePruned = !keepNonce
				entry.TransferPruned = !keepTransfer
				encoded, marshalErr := json.Marshal(entry)
				if marshalErr != nil {
					return failUnlocked(fmt.Errorf("marshal replay entry: %w", marshalErr))
				}
				encoded = append(encoded, '\n')
				n, writeErr := tmp.Write(encoded)
				if writeErr != nil {
					return failUnlocked(fmt.Errorf("write compacted replay store: %w", writeErr))
				}
				if n != len(encoded) {
					return failUnlocked(fmt.Errorf("write compacted replay store: %w", io.ErrShortWrite))
				}
				if keepNonce {
					newNonces[entry.NonceKey] = entry.Timestamp
				}
				if keepTransfer {
					newTransfers[entry.TransferKey] = entry.TransferTimestamp
				}
				newSize += int64(len(encoded))
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return failUnlocked(fmt.Errorf("read replay store for compact: %w", readErr))
		}
	}
	if removed == 0 && !retentionChanged {
		return removed, nil
	}
	if err := tmp.Sync(); err != nil {
		return failUnlocked(fmt.Errorf("fsync compacted replay store: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return failUnlocked(fmt.Errorf("close compacted replay store: %w", err))
	}
	if err := os.Rename(tmpPath, filepath.Clean(path)); err != nil {
		return failUnlocked(fmt.Errorf("rename compacted replay store: %w", err))
	}
	renamed = true
	fsyncDir(dir)
	newFile, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_APPEND, 0o600) // #nosec G304 -- operator-configured store path
	if err != nil {
		return failUnlocked(fmt.Errorf("reopen compacted replay store: %w", err))
	}
	newRelease, err := acquireReplayStoreLock(newFile)
	if err != nil {
		_ = newFile.Close()
		return failUnlocked(fmt.Errorf("lock compacted replay store: %w", err))
	}
	newLocked := true
	defer func() {
		if newLocked {
			newRelease()
		}
	}()
	if err := verifyStorePathInode(newFile, path); err != nil {
		newRelease()
		newLocked = false
		_ = newFile.Close()
		return failUnlocked(err)
	}
	info, err := newFile.Stat()
	if err != nil {
		newRelease()
		newLocked = false
		_ = newFile.Close()
		return failUnlocked(fmt.Errorf("stat compacted replay store: %w", err))
	}
	if info.Size() != newSize {
		newRelease()
		newLocked = false
		_ = newFile.Close()
		return failUnlocked(fmt.Errorf("compacted replay store changed during replacement: got %d bytes, want %d", info.Size(), newSize))
	}
	s.mu.Lock()
	oldFile := s.file
	s.file = newFile
	s.nonces = newNonces
	s.transfers = newTransfers
	s.readOffset = newSize
	s.mu.Unlock()
	release()
	locked = false
	newRelease()
	newLocked = false
	_ = oldFile.Close()
	return removed, nil
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
	if entry.TransferTimestamp.IsZero() {
		return fmt.Errorf("%w: replay transfer timestamp is required", ErrMalformedBinding)
	}
	if !entry.retainsNonce() && !entry.retainsTransfer() {
		return fmt.Errorf("%w: replay entry retains no keys", ErrMalformedBinding)
	}
	return nil
}

func (entry ReplayEntry) retainsNonce() bool {
	return !entry.NoncePruned
}

func (entry ReplayEntry) retainsTransfer() bool {
	return !entry.TransferPruned
}

// Close releases the underlying file.
func (s *FileReplayStore) Close() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
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
