// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type LocalLog struct {
	Path  string
	LogID string
}

type LocalLogEntry struct {
	Version    int        `json:"version"`
	LogID      string     `json:"log_id"`
	Index      uint64     `json:"index"`
	Timestamp  string     `json:"timestamp"`
	Checkpoint Checkpoint `json:"checkpoint"`
	PrevHash   string     `json:"prev_hash"`
	Hash       string     `json:"hash"`
}

type localLogEntryHashInput struct {
	Version    int        `json:"version"`
	LogID      string     `json:"log_id"`
	Index      uint64     `json:"index"`
	Timestamp  string     `json:"timestamp"`
	Checkpoint Checkpoint `json:"checkpoint"`
	PrevHash   string     `json:"prev_hash"`
}

func (l LocalLog) Submit(checkpoint Checkpoint) (Proof, error) {
	if l.Path == "" {
		return Proof{}, errors.New("local anchor log path required")
	}
	unlock, err := acquireLocalLogLock(l.Path)
	if err != nil {
		return Proof{}, fmt.Errorf("acquire local anchor log lock: %w", err)
	}
	defer unlock()

	logID := l.logID()
	entries, err := ReadLocalLog(l.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Proof{}, err
	}
	for _, entry := range entries {
		if entry.LogID != logID {
			return Proof{}, fmt.Errorf("local anchor log_id mismatch at index %d: got %q, want %q", entry.Index, entry.LogID, logID)
		}
	}
	prevHash := GenesisHash
	if len(entries) > 0 {
		prevHash = entries[len(entries)-1].Hash
	}
	entry := LocalLogEntry{
		Version:    BundleVersion,
		LogID:      logID,
		Index:      uint64(len(entries)),
		Timestamp:  nowString(),
		Checkpoint: checkpoint,
		PrevHash:   prevHash,
	}
	entry.Hash = localEntryHash(entry)

	clean := filepath.Clean(l.Path)
	if err := os.MkdirAll(filepath.Dir(clean), dirPermissions); err != nil {
		return Proof{}, fmt.Errorf("create local anchor log directory: %w", err)
	}
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_WRONLY|os.O_APPEND, filePermissions)
	if err != nil {
		return Proof{}, fmt.Errorf("open local anchor log: %w", err)
	}
	defer func() { _ = f.Close() }()
	line, err := json.Marshal(entry)
	if err != nil {
		return Proof{}, fmt.Errorf("marshal local anchor entry: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Proof{}, fmt.Errorf("write local anchor entry: %w", err)
	}
	return Proof{
		Backend:     LocalBackend,
		LogID:       logID,
		LogIndex:    entry.Index,
		EntryHash:   entry.Hash,
		LogRootHash: entry.Hash,
	}, nil
}

func (l LocalLog) Verify(proof Proof, checkpoint Checkpoint) error {
	if proof.Backend != LocalBackend {
		return fmt.Errorf("anchor proof backend %q is not %q", proof.Backend, LocalBackend)
	}
	if l.Path == "" {
		return errors.New("local anchor log path required")
	}
	logID := l.logID()
	if proof.LogID != logID {
		return fmt.Errorf("anchor proof log_id %q does not match verifier log_id %q", proof.LogID, logID)
	}
	entries, err := ReadLocalLog(l.Path)
	if err != nil {
		return err
	}
	if proof.LogIndex >= uint64(len(entries)) {
		return fmt.Errorf("anchor proof log_index %d outside local log length %d", proof.LogIndex, len(entries))
	}
	entry := entries[proof.LogIndex]
	if entry.LogID != logID {
		return fmt.Errorf("anchor log entry log_id %q does not match %q", entry.LogID, logID)
	}
	if entry.Hash != proof.EntryHash {
		return fmt.Errorf("anchor proof entry_hash does not match local log entry")
	}
	if entry.Hash != proof.LogRootHash {
		return fmt.Errorf("anchor proof log_root_hash does not match local log entry")
	}
	if !checkpointsEqual(entry.Checkpoint, checkpoint) {
		return fmt.Errorf("anchor log checkpoint does not match bundle checkpoint")
	}
	return nil
}

func ReadLocalLog(path string) ([]LocalLogEntry, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 10<<20)
	var entries []LocalLogEntry
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var entry LocalLogEntry
		if err := decodeStrict(raw, &entry); err != nil {
			return nil, fmt.Errorf("parse local anchor log line %d: %w", len(entries)+1, err)
		}
		if err := verifyLocalEntry(entry, entries); err != nil {
			return nil, fmt.Errorf("local anchor log line %d: %w", len(entries)+1, err)
		}
		entries = append(entries, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan local anchor log: %w", err)
	}
	return entries, nil
}

func verifyLocalEntry(entry LocalLogEntry, prior []LocalLogEntry) error {
	if entry.Version != BundleVersion {
		return fmt.Errorf("unsupported version %d", entry.Version)
	}
	if entry.Index != uint64(len(prior)) {
		return fmt.Errorf("index mismatch: got %d, want %d", entry.Index, len(prior))
	}
	wantPrev := GenesisHash
	if len(prior) > 0 {
		wantPrev = prior[len(prior)-1].Hash
	}
	if entry.PrevHash != wantPrev {
		return fmt.Errorf("prev_hash mismatch")
	}
	if got := localEntryHash(entry); got != entry.Hash {
		return fmt.Errorf("hash mismatch: computed %s, stored %s", got, entry.Hash)
	}
	return nil
}

func localEntryHash(entry LocalLogEntry) string {
	data, err := json.Marshal(localLogEntryHashInput{
		Version:    entry.Version,
		LogID:      entry.LogID,
		Index:      entry.Index,
		Timestamp:  entry.Timestamp,
		Checkpoint: entry.Checkpoint,
		PrevHash:   entry.PrevHash,
	})
	if err != nil {
		return ""
	}
	return sha256Hex(data)
}

func (l LocalLog) logID() string {
	if l.LogID != "" {
		return l.LogID
	}
	return DefaultLocalLogID
}

func nowString() string {
	if fixed := os.Getenv("PIPELOCK_ANCHOR_TEST_NOW"); fixed != "" {
		return fixed
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}
