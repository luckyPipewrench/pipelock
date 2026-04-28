// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package recorder provides a hash-chained, tamper-evident, DLP-redacted
// evidence log with signed checkpoints and optional encrypted raw escrow.
package recorder

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// EntryVersion is the current schema version for new writes. Readers MUST
// reject versions outside acceptedEntryVersions; v1 chains continue to
// verify with the v1 hash projection so pre-upgrade audit logs stay valid.
const EntryVersion = 2

// acceptedEntryVersions is the inclusive set of schema versions ReadEntries
// and VerifyChain will load. New writes always use EntryVersion; v1 entries
// keep verifying via computeHashV1 so the chain integrity guarantee survives
// the schema bump.
var acceptedEntryVersions = map[int]bool{1: true, 2: true}

// GenesisHash is the PrevHash of the first entry in a chain.
const GenesisHash = "genesis"

// Entry is a single evidence record in the hash chain.
//
// EventKind is informational at the recorder layer. Empty for envelope
// entries (capture_drop, checkpoint, transcript_root) is acceptable. For
// entries wrapping action receipts it carries the action verb (read, derive,
// write, delegate, authorize, spend, commit, actuate, unclassified). For
// entries wrapping capture summaries it carries the surface (url, response,
// dlp, cee, tool_policy, tool_scan). Downstream consumers (compile,
// classification debt) drive their behavior off this field; the recorder
// itself only stamps it through and binds it into the v2 chain hash.
type Entry struct {
	Version   int       `json:"v"`
	Sequence  uint64    `json:"seq"`
	Timestamp time.Time `json:"ts"`
	SessionID string    `json:"session_id"`
	TraceID   string    `json:"trace_id,omitempty"`
	Type      string    `json:"type"`
	EventKind string    `json:"event_kind,omitempty"`
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

// ComputeHash returns the canonical chain hash for an entry. The canonical
// projection differs by Version: v1 omits EventKind from the digest input
// (preserving pre-upgrade chain verification); v2 inserts EventKind between
// Type and Transport so v2 entries bind the classification to the chain.
//
// Both versions use the same null-byte field separator and field ordering
// for fields they share. Unknown versions return the empty string —
// VerifyChain checks the version fence separately and surfaces a clear
// error.
func ComputeHash(e Entry) string {
	switch e.Version {
	case 1:
		return computeHashV1(e)
	case 2:
		return computeHashV2(e)
	default:
		return ""
	}
}

// computeHashV1 is the frozen v1 canonical projection. Do NOT modify this
// function — pre-upgrade chains depend on byte-for-byte identical output.
// Field order: v, seq, ts, session_id, trace_id, type, transport, summary,
// detail_json, raw_ref, prev_hash. Null byte separators between fields.
func computeHashV1(e Entry) string {
	detailJSON, err := json.Marshal(e.Detail)
	if err != nil {
		detailJSON = []byte("null")
	}

	h := sha256.New()
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
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(f))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// computeHashV2 is the v2 canonical projection. Identical to v1 but inserts
// EventKind between Type and Transport. The version field itself ("1" vs
// "2") differs by definition, so v1 and v2 produce different hashes for the
// same logical entry even when EventKind is empty — this is the v1/v2
// isolation guarantee.
func computeHashV2(e Entry) string {
	detailJSON, err := json.Marshal(e.Detail)
	if err != nil {
		detailJSON = []byte("null")
	}

	h := sha256.New()
	fields := []string{
		strconv.Itoa(e.Version),
		strconv.FormatUint(e.Sequence, 10),
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.SessionID,
		e.TraceID,
		e.Type,
		e.EventKind,
		e.Transport,
		e.Summary,
		string(detailJSON),
		e.RawRef,
		e.PrevHash,
	}
	for i, f := range fields {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(f))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// VerifyChain checks the integrity of a sequence of entries. Returns an error
// describing the first break found, or nil if the chain is intact. Mixed v1
// and v2 entries are accepted; each entry's hash is computed using the
// projection matching its Version field, and PrevHash linkage is enforced
// across the version boundary.
// If pubKey is provided, checkpoint entry signatures are also verified.
func VerifyChain(entries []Entry, pubKey ...ed25519.PublicKey) error {
	for i, e := range entries {
		if !acceptedEntryVersions[e.Version] {
			return fmt.Errorf("entry seq %d: unsupported version %d (accepted: 1, 2)", e.Sequence, e.Version)
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

	// Verify checkpoint signatures if a public key was provided
	if len(pubKey) > 0 && pubKey[0] != nil {
		if err := VerifyCheckpoints(entries, pubKey[0]); err != nil {
			return err
		}
	}

	return nil
}

// VerifyCheckpoints verifies Ed25519 signatures on all checkpoint entries.
// Returns an error if any checkpoint has a missing or invalid signature.
func VerifyCheckpoints(entries []Entry, pubKey ed25519.PublicKey) error {
	for _, e := range entries {
		if e.Type != "checkpoint" {
			continue
		}

		detailJSON, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("entry seq %d: marshaling checkpoint detail: %w", e.Sequence, err)
		}

		var cpDetail CheckpointDetail
		if err := json.Unmarshal(detailJSON, &cpDetail); err != nil {
			return fmt.Errorf("entry seq %d: unmarshaling checkpoint detail: %w", e.Sequence, err)
		}

		if cpDetail.Signature == "" {
			return fmt.Errorf("entry seq %d: checkpoint missing signature", e.Sequence)
		}

		sig, err := hex.DecodeString(cpDetail.Signature)
		if err != nil {
			return fmt.Errorf("entry seq %d: decoding checkpoint signature: %w", e.Sequence, err)
		}

		// The signature is over the PrevHash of the checkpoint entry
		// (which represents the chain state just before the checkpoint)
		if !ed25519.Verify(pubKey, []byte(e.PrevHash), sig) {
			return fmt.Errorf("entry seq %d: checkpoint signature verification failed", e.Sequence)
		}
	}
	return nil
}

// ReadEntries reads and parses JSONL evidence entries from a file.
// Accepts the versions in acceptedEntryVersions; rejects unknown versions.
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
		if !acceptedEntryVersions[e.Version] {
			return nil, fmt.Errorf("line %d: unsupported entry version %d (accepted: 1, 2)", lineNum, e.Version)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning evidence file: %w", err)
	}
	return entries, nil
}
