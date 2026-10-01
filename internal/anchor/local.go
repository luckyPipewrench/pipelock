// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
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
	return l.submitWithSync(checkpoint, (*os.File).Sync)
}

func (l LocalLog) submitWithSync(checkpoint Checkpoint, syncFile func(*os.File) error) (Proof, error) {
	if l.Path == "" {
		return Proof{}, errors.New("local anchor log path required")
	}
	unlock, err := acquireLocalLogLock(l.Path)
	if err != nil {
		return Proof{}, fmt.Errorf("acquire local anchor log lock: %w", err)
	}
	defer unlock()

	logID := l.logID()
	entries, appendPath, err := l.readSegments()
	if err != nil {
		return Proof{}, err
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

	clean := filepath.Clean(appendPath)
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
	if err := syncFile(f); err != nil {
		return Proof{}, fmt.Errorf("sync local anchor entry: %w", err)
	}
	// Persist a newly created segment directory entry as well as its contents.
	dir, err := os.Open(filepath.Dir(clean))
	if err != nil {
		return Proof{}, fmt.Errorf("open local anchor log directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil && runtime.GOOS != "windows" {
		return Proof{}, fmt.Errorf("sync local anchor log directory: %w", err)
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
	if err := validateProofBackendConsistency(proof); err != nil {
		return err
	}
	if l.Path == "" {
		return errors.New("local anchor log path required")
	}
	logID := l.logID()
	if proof.LogID != logID {
		return fmt.Errorf("anchor proof log_id %q does not match verifier log_id %q", proof.LogID, logID)
	}
	entries, _, err := l.readSegments()
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

// ReadLocalLog verifies a single file and reports crash-damaged tails without
// claiming the damaged file is healthy. Returned entries cover its complete prefix.
func ReadLocalLog(path string) ([]LocalLogEntry, error) {
	return readLocalLogPrefix(path, nil, "")
}

// readSegments joins verified, newline-complete prefixes. A torn segment is never
// appended to; the next numbered segment continues its last complete hash/index.
// Segment names are storage details and do not change the signed proof format.
func (l LocalLog) readSegments() ([]LocalLogEntry, string, error) {
	base := filepath.Clean(l.Path)
	directory, err := os.ReadDir(filepath.Dir(base))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("find local anchor segments: %w", err)
	}
	paths := []string{base}
	prefix := filepath.Base(base) + ".segment-"
	for _, entry := range directory {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		suffix := strings.TrimPrefix(entry.Name(), prefix)
		if len(suffix) != 20 || strings.IndexFunc(suffix, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			slog.Debug("ignoring unrelated local anchor segment name", "name", entry.Name())
			continue
		}
		segment := filepath.Join(filepath.Dir(base), entry.Name())
		expected := fmt.Sprintf("%s.segment-%020d", base, len(paths))
		if segment != expected {
			return nil, "", fmt.Errorf("local anchor segment sequence mismatch: got %q, want %q", segment, expected)
		}
		paths = append(paths, segment)
	}
	var entries []LocalLogEntry
	for i, path := range paths {
		current, readErr := readLocalLogPrefix(path, entries, l.logID())
		if errors.Is(readErr, os.ErrNotExist) && len(paths) == 1 {
			return entries, base, nil
		}
		if readErr != nil && !errors.Is(readErr, recorder.ErrTornTail) {
			return nil, "", readErr
		}
		entries = current
		if i == len(paths)-1 {
			if readErr == nil {
				return entries, path, nil
			}
			return entries, fmt.Sprintf("%s.segment-%020d", base, len(paths)), nil
		}
	}
	return nil, "", errors.New("local anchor log has no segments")
}

func readLocalLogPrefix(path string, prior []LocalLogEntry, expectedID string) ([]LocalLogEntry, error) {
	validated := append([]LocalLogEntry(nil), prior...)
	tailErr := recorder.InspectJSONLTailWithValidator(path, func(raw []byte) error {
		if len(raw) == 0 {
			return nil
		}
		var entry LocalLogEntry
		if err := decodeStrict(raw, &entry); err != nil {
			return fmt.Errorf("parse local anchor log line %d: %w", len(validated)+1, err)
		}
		if expectedID != "" && entry.LogID != expectedID {
			return fmt.Errorf("local anchor log_id mismatch at index %d: got %q, want %q", entry.Index, entry.LogID, expectedID)
		}
		if err := verifyLocalEntry(entry, validated); err != nil {
			return fmt.Errorf("local anchor log line %d: %w", len(validated)+1, err)
		}
		validated = append(validated, entry)
		return nil
	})
	var torn *recorder.TornTailError
	if tailErr != nil && !errors.As(tailErr, &torn) {
		return nil, tailErr
	}
	if torn != nil {
		// The validator includes a complete final JSON record even without its
		// newline. Keep its index and hash: an issued proof must never be replaced.
		// The torn error still forces Submit to append in a fresh segment.
		return validated, tailErr
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 10<<20)
	entries := append([]LocalLogEntry(nil), prior...)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var entry LocalLogEntry
		if err := decodeStrict(sc.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse local anchor prefix: %w", err)
		}
		if expectedID != "" && entry.LogID != expectedID {
			return nil, fmt.Errorf("local anchor log_id mismatch at index %d: got %q, want %q", entry.Index, entry.LogID, expectedID)
		}
		if err := verifyLocalEntry(entry, entries); err != nil {
			return nil, fmt.Errorf("verify local anchor prefix: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan local anchor prefix: %w", err)
	}
	return entries, tailErr
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
