// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package recorder provides a hash-chained, tamper-evident, DLP-redacted
// evidence log with signed checkpoints and optional encrypted raw escrow.
package recorder

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// EntryVersion is the current schema version. Readers MUST reject unknown versions.
const EntryVersion = 1

// GenesisHash is the PrevHash of the first entry in a chain.
const GenesisHash = "genesis"

// Entry is a single evidence record in the hash chain.
type Entry struct {
	Version   int       `json:"v"`
	Sequence  uint64    `json:"seq"`
	Timestamp time.Time `json:"ts"`
	SessionID string    `json:"session_id"`
	TraceID   string    `json:"trace_id,omitempty"`
	Type      string    `json:"type"`
	Transport string    `json:"transport"`
	Summary   string    `json:"summary"`
	Detail    any       `json:"detail"`
	RawRef    string    `json:"raw_ref,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// CheckpointDetail is the structured payload for checkpoint entries.
type CheckpointDetail struct {
	EntryCount uint64 `json:"entry_count"`
	FirstSeq   uint64 `json:"first_seq"`
	LastSeq    uint64 `json:"last_seq"`
	Signature  string `json:"signature"`
}

// ComputeHash calculates the SHA-256 hash of an entry over all fields except Hash.
// Hash chain: SHA256(v || seq || ts || session_id || trace_id || type || transport
//
//	|| summary || detail_json || raw_ref || prev_hash)
func ComputeHash(e Entry) string {
	detailJSON, err := json.Marshal(e.Detail)
	if err != nil {
		detailJSON = []byte("null")
	}

	h := sha256.New()
	// Each field separated by null byte to prevent field-boundary ambiguity
	fields := []string{
		strconv.Itoa(e.Version),
		strconv.FormatUint(e.Sequence, 10),
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.SessionID,
		e.TraceID,
		e.Type,
		e.Transport,
		e.Summary,
		string(detailJSON),
		e.RawRef,
		e.PrevHash,
	}
	for i, f := range fields {
		if i > 0 {
			_, _ = h.Write([]byte{0}) // null separator
		}
		_, _ = h.Write([]byte(f))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// VerifyChain checks the integrity of a sequence of entries. Returns an error
// describing the first break found, or nil if the chain is intact.
func VerifyChain(entries []Entry) error {
	for i, e := range entries {
		if e.Version != EntryVersion {
			return fmt.Errorf("entry seq %d: unsupported version %d (expected %d)", e.Sequence, e.Version, EntryVersion)
		}
		computed := ComputeHash(e)
		if computed != e.Hash {
			return fmt.Errorf("entry seq %d: hash mismatch: computed %s, stored %s", e.Sequence, computed, e.Hash)
		}
		if i == 0 {
			if e.PrevHash != GenesisHash {
				return fmt.Errorf("entry seq %d: first entry PrevHash should be %q, got %q", e.Sequence, GenesisHash, e.PrevHash)
			}
		} else {
			if e.PrevHash != entries[i-1].Hash {
				return fmt.Errorf("entry seq %d: chain break: PrevHash %s != previous Hash %s", e.Sequence, e.PrevHash, entries[i-1].Hash)
			}
		}
	}
	return nil
}

// ReadEntries reads and parses JSONL evidence entries from a file.
// Rejects entries with unknown versions.
func ReadEntries(path string) ([]Entry, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var entries []Entry
	sc := bufio.NewScanner(f)

	// 1MB max line size for entries with large Detail payloads
	const maxLineSize = 1 << 20
	sc.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("line %d: parsing entry: %w", lineNum, err)
		}
		if e.Version != EntryVersion {
			return nil, fmt.Errorf("line %d: unsupported entry version %d (expected %d)", lineNum, e.Version, EntryVersion)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning evidence file: %w", err)
	}
	return entries, nil
}
