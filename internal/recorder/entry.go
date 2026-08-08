// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package recorder provides a hash-chained, tamper-evident, DLP-redacted
// evidence log with signed checkpoints and optional encrypted raw escrow.
package recorder

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	// CurrentWriteEntryVersion is the schema version emitted by the recorder.
	// Keep this at v2 during the reader-first rollout.
	CurrentWriteEntryVersion = 2
	// LatestEntryVersion is the newest schema version understood by readers.
	LatestEntryVersion = 3
	// EntryVersion is retained for source compatibility. New code must choose
	// CurrentWriteEntryVersion or LatestEntryVersion according to its role.
	EntryVersion = CurrentWriteEntryVersion

	// ChainKindRecorder identifies the outer recorder hash chain. It is bound
	// into v3 hashes with WriterInstanceID to form the chain namespace.
	ChainKindRecorder = "recorder"
)

// MaxEntryLineBytes is the maximum JSONL line payload accepted by recorder
// entry readers.
const MaxEntryLineBytes = 1 << 20

const maxEntryWireLineBytes = MaxEntryLineBytes + len("\r\n")

type entryReadLimits struct {
	MaxEntries int
	MaxBytes   int64
}

func defaultEntryReadLimits() entryReadLimits {
	return entryReadLimits{
		MaxEntries: MaxEvidenceReadEntries,
		MaxBytes:   MaxEvidenceReadFileBytes,
	}
}

// acceptedEntryVersions is the inclusive set of schema versions ReadEntries
// and VerifyChain will load. New writes always use EntryVersion; v1 entries
// keep verifying via computeHashV1 so the chain integrity guarantee survives
// the schema bump.
var acceptedEntryVersionList = []int{1, 2, 3}

var acceptedEntryVersions = func() map[int]bool {
	versions := make(map[int]bool, len(acceptedEntryVersionList))
	for _, version := range acceptedEntryVersionList {
		versions[version] = true
	}
	return versions
}()

// GenesisHash is the PrevHash of the first entry in a chain.
const GenesisHash = "genesis"

// IsAcceptedEntryVersion reports whether recorder readers accept version.
func IsAcceptedEntryVersion(version int) bool {
	return acceptedEntryVersions[version]
}

// AcceptedEntryVersions returns the recorder schema versions readers accept.
func AcceptedEntryVersions() []int { return append([]int(nil), acceptedEntryVersionList...) }

// EntryVersionHasNamespace reports whether version binds a recorder namespace.
func EntryVersionHasNamespace(version int) bool { return version == 3 }

// ValidateEntryNamespace enforces the namespace fields appropriate to version.
func ValidateEntryNamespace(version int, chainKind, writerInstanceID string) error {
	if EntryVersionHasNamespace(version) {
		if chainKind == "" {
			return errors.New("v3 chain_kind required")
		}
		if writerInstanceID == "" {
			return errors.New("v3 writer_instance_id required")
		}
		if strings.ContainsRune(chainKind, '\x00') {
			return errors.New("v3 chain_kind cannot contain NUL")
		}
		if strings.ContainsRune(writerInstanceID, '\x00') {
			return errors.New("v3 writer_instance_id cannot contain NUL")
		}
		return nil
	}
	if chainKind != "" || writerInstanceID != "" {
		return errors.New("legacy entry cannot carry v3 recorder namespace fields")
	}
	return nil
}

// ValidateEntrySchema rejects fields that the version's hash projection cannot
// bind unambiguously. V3 retains the frozen null-delimited projection, so its
// string fields cannot contain the delimiter.
func ValidateEntrySchema(e Entry) error {
	if err := ValidateEntryNamespace(e.Version, e.ChainKind, e.WriterInstanceID); err != nil {
		return err
	}
	fields := map[string]string{
		"session_id": e.SessionID, "trace_id": e.TraceID,
		"type": e.Type, "transport": e.Transport,
		"summary": e.Summary, "raw_ref": e.RawRef, "prev_hash": e.PrevHash,
	}
	if e.Version >= 2 {
		fields["event_kind"] = e.EventKind
	}
	if EntryVersionHasNamespace(e.Version) {
		fields["chain_kind"] = e.ChainKind
		fields["writer_instance_id"] = e.WriterInstanceID
	}
	for name, value := range fields {
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("v%d %s cannot contain NUL", e.Version, name)
		}
	}
	return nil
}

// ValidateEntryJSONSchema rejects raw JSON representations that typed Go
// decoding would otherwise collapse into the same zero value.
func ValidateEntryJSONSchema(rawJSON []byte, version int) error {
	if version != 3 {
		return nil
	}
	var projected map[string]json.RawMessage
	if err := json.Unmarshal(rawJSON, &projected); err != nil {
		return fmt.Errorf("parse v3 projected fields: %w", err)
	}
	seq, ok := projected["seq"]
	if !ok {
		return errors.New("v3 seq required")
	}
	seqText := string(bytes.TrimSpace(seq))
	if seqText == "" || strings.Trim(seqText, "0123456789") != "" {
		return errors.New("v3 seq must be an unsigned integer")
	}
	if _, err := strconv.ParseUint(seqText, 10, 64); err != nil {
		return errors.New("v3 seq must be an unsigned 64-bit integer")
	}
	required := map[string]bool{"ts": true, "session_id": true, "type": true, "transport": true, "summary": true, "prev_hash": true}
	for _, field := range []string{"ts", "session_id", "chain_kind", "writer_instance_id", "trace_id", "type", "event_kind", "transport", "summary", "raw_ref", "prev_hash"} {
		value, ok := projected[field]
		if !ok && required[field] {
			return fmt.Errorf("v3 %s required", field)
		}
		if ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("v3 %s must be a string", field)
		}
	}
	return nil
}

// EntryVersionsCanShareChain reports whether a writer may resume a tail
// without crossing between legacy and namespaced hash-chain families.
func EntryVersionsCanShareChain(tailVersion, writeVersion int) bool {
	return EntryVersionHasNamespace(tailVersion) == EntryVersionHasNamespace(writeVersion)
}

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
	ChainKind string    `json:"chain_kind,omitempty"`
	// WriterInstanceID is an unauthenticated per-process namespace claim. It
	// prevents cooperating writers from accidentally sharing sequence space;
	// checkpoint and receipt signatures remain the authenticity boundary.
	WriterInstanceID string          `json:"writer_instance_id,omitempty"`
	TraceID          string          `json:"trace_id,omitempty"`
	Type             string          `json:"type"`
	EventKind        string          `json:"event_kind,omitempty"`
	Transport        string          `json:"transport"`
	Summary          string          `json:"summary"`
	Detail           any             `json:"detail"`
	RawDetail        json.RawMessage `json:"-"`
	RawRef           string          `json:"raw_ref,omitempty"`
	PrevHash         string          `json:"prev_hash"`
	Hash             string          `json:"hash"`
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
// for fields they share. Unknown versions return the empty string -
// VerifyChain checks the version fence separately and surfaces a clear
// error.
func ComputeHash(e Entry) string {
	switch e.Version {
	case 1:
		return computeHashV1(e)
	case 2:
		return computeHashV2(e)
	case 3:
		return computeHashV3(e)
	default:
		return ""
	}
}

// computeHashV1 is the frozen v1 canonical projection. Do NOT modify this
// function - pre-upgrade chains depend on byte-for-byte identical output.
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
// same logical entry even when EventKind is empty - this is the v1/v2
// isolation guarantee.
func computeHashV2(e Entry) string {
	detailJSON := detailJSONForHash(e)

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

// computeHashV3 is the frozen v3 canonical projection. It extends v2 by
// inserting ChainKind and WriterInstanceID after SessionID. These fields form
// the per-writer chain namespace and must never be removed or reordered.
func computeHashV3(e Entry) string {
	detailJSON := detailJSONForHash(e)

	h := sha256.New()
	fields := []string{
		strconv.Itoa(e.Version),
		strconv.FormatUint(e.Sequence, 10),
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.SessionID,
		e.ChainKind,
		e.WriterInstanceID,
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

func detailJSONForHash(e Entry) []byte {
	if e.RawDetail != nil {
		return e.RawDetail
	}
	detailJSON, err := json.Marshal(e.Detail)
	if err != nil {
		return []byte("null")
	}
	return detailJSON
}

// VerifyChain checks the integrity of a sequence of entries. Returns an error
// describing the first break found, or nil if the chain is intact. Mixed v1
// and v2 entries are accepted; each entry's hash is computed using the
// projection matching its Version field, and PrevHash linkage is enforced
// across the version boundary.
// If pubKey is provided, checkpoint entry signatures are also verified.
func VerifyChain(entries []Entry, pubKey ...ed25519.PublicKey) error {
	var v3SessionID, v3ChainKind, v3WriterInstanceID string
	for i, e := range entries {
		if !acceptedEntryVersions[e.Version] {
			return fmt.Errorf("entry seq %d: unsupported version %d (accepted: 1, 2, 3)", e.Sequence, e.Version)
		}
		if err := ValidateEntrySchema(e); err != nil {
			return fmt.Errorf("entry seq %d: %w", e.Sequence, err)
		}
		if EntryVersionHasNamespace(e.Version) {
			if i > 0 && !EntryVersionHasNamespace(entries[i-1].Version) {
				return fmt.Errorf("entry seq %d: v3 chain cannot continue a legacy recorder namespace", e.Sequence)
			}
			if v3ChainKind == "" {
				v3SessionID, v3ChainKind, v3WriterInstanceID = e.SessionID, e.ChainKind, e.WriterInstanceID
			} else if e.SessionID != v3SessionID || e.ChainKind != v3ChainKind || e.WriterInstanceID != v3WriterInstanceID {
				return fmt.Errorf("entry seq %d: v3 chain namespace changed", e.Sequence)
			}
		} else {
			if v3ChainKind != "" {
				return fmt.Errorf("entry seq %d: legacy entry cannot continue a v3 recorder namespace", e.Sequence)
			}
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
	entries, truncated, bytesRead, err := readEntries(path, defaultEntryReadLimits())
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, readLimitExceededError(path, defaultEntryReadLimits(), bytesRead)
	}
	return entries, nil
}

func readEntries(path string, limits entryReadLimits) ([]Entry, bool, int64, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, false, 0, fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = f.Close() }()

	entries, truncated, bytesRead, err := readEntriesFromReader(f, limits)
	if err != nil {
		return nil, false, bytesRead, fmt.Errorf("reading evidence file: %w", err)
	}
	return entries, truncated, bytesRead, nil
}

// ReadEntriesFromReader reads and parses JSONL evidence entries from r.
// It applies the same duplicate-key and version fences as ReadEntries.
func ReadEntriesFromReader(r io.Reader) ([]Entry, error) {
	entries, truncated, bytesRead, err := readEntriesFromReader(r, defaultEntryReadLimits())
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, readLimitExceededError("reader", defaultEntryReadLimits(), bytesRead)
	}
	return entries, nil
}

func readEntriesFromReader(r io.Reader, limits entryReadLimits) ([]Entry, bool, int64, error) {
	var entries []Entry
	reader := bufio.NewReader(r)

	var (
		lineNum   int
		bytesRead int64
		line      []byte
	)
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			bytesRead += int64(len(fragment))
			if limits.MaxBytes > 0 && bytesRead > limits.MaxBytes {
				return entries, true, bytesRead, nil
			}
			if len(line)+len(fragment) > maxEntryWireLineBytes {
				return nil, false, bytesRead, fmt.Errorf("line %d: exceeds %d-byte recorder entry limit", lineNum+1, MaxEntryLineBytes)
			}
			line = append(line, fragment...)
		}
		if err == nil {
			// Complete line.
		} else if errors.Is(err, bufio.ErrBufferFull) {
			continue
		} else if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return entries, false, bytesRead, nil
			}
		} else {
			return nil, false, bytesRead, fmt.Errorf("scanning evidence entries: %w", err)
		}
		lineNum++
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
		}
		if len(line) > MaxEntryLineBytes {
			return nil, false, bytesRead, fmt.Errorf("line %d: exceeds %d-byte recorder entry limit", lineNum, MaxEntryLineBytes)
		}
		trimmed := strings.TrimSpace(string(line))
		line = line[:0]
		if trimmed == "" {
			if errors.Is(err, io.EOF) {
				return entries, false, bytesRead, nil
			}
			continue
		}
		if limits.MaxEntries > 0 && len(entries) >= limits.MaxEntries {
			return entries, true, bytesRead, nil
		}

		// Reject duplicate object keys before json.Unmarshal collapses them
		// last-wins (a parser-differential smuggling vector); shared with the
		// receipt verify path via internal/jsonscan.
		if err := jsonscan.RejectDuplicateKeys([]byte(trimmed)); err != nil {
			return nil, false, bytesRead, fmt.Errorf("line %d: parsing entry: %w", lineNum, err)
		}

		var raw struct {
			Version          int             `json:"v"`
			Sequence         uint64          `json:"seq"`
			Timestamp        time.Time       `json:"ts"`
			SessionID        string          `json:"session_id"`
			ChainKind        string          `json:"chain_kind,omitempty"`
			WriterInstanceID string          `json:"writer_instance_id,omitempty"`
			TraceID          string          `json:"trace_id,omitempty"`
			Type             string          `json:"type"`
			EventKind        string          `json:"event_kind,omitempty"`
			Transport        string          `json:"transport"`
			Summary          string          `json:"summary"`
			Detail           json.RawMessage `json:"detail"`
			RawRef           string          `json:"raw_ref,omitempty"`
			PrevHash         string          `json:"prev_hash"`
			Hash             string          `json:"hash"`
		}
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return nil, false, bytesRead, fmt.Errorf("line %d: parsing entry: %w", lineNum, err)
		}
		if err := ValidateEntryJSONSchema([]byte(trimmed), raw.Version); err != nil {
			return nil, false, bytesRead, fmt.Errorf("line %d: %w", lineNum, err)
		}
		e := Entry{
			Version:          raw.Version,
			Sequence:         raw.Sequence,
			Timestamp:        raw.Timestamp,
			SessionID:        raw.SessionID,
			ChainKind:        raw.ChainKind,
			WriterInstanceID: raw.WriterInstanceID,
			TraceID:          raw.TraceID,
			Type:             raw.Type,
			EventKind:        raw.EventKind,
			Transport:        raw.Transport,
			Summary:          raw.Summary,
			RawRef:           raw.RawRef,
			PrevHash:         raw.PrevHash,
			Hash:             raw.Hash,
		}
		if raw.Detail != nil {
			e.RawDetail = append(json.RawMessage(nil), raw.Detail...)
			var detail any
			if err := json.Unmarshal(raw.Detail, &detail); err != nil {
				return nil, false, bytesRead, fmt.Errorf("line %d: parsing entry detail: %w", lineNum, err)
			}
			e.Detail = detail
		}
		if !acceptedEntryVersions[e.Version] {
			return nil, false, bytesRead, fmt.Errorf("line %d: unsupported entry version %d (accepted: 1, 2, 3)", lineNum, e.Version)
		}
		if err := ValidateEntrySchema(e); err != nil {
			return nil, false, bytesRead, fmt.Errorf("line %d: %w", lineNum, err)
		}
		entries = append(entries, e)
		if errors.Is(err, io.EOF) {
			return entries, false, bytesRead, nil
		}
	}
}

func readLimitExceededError(path string, limits entryReadLimits, bytesRead int64) error {
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		name = path
	}
	switch {
	case limits.MaxBytes > 0 && bytesRead > limits.MaxBytes:
		return fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, name, limits.MaxBytes)
	case limits.MaxEntries > 0:
		return fmt.Errorf("%w: evidence file %s exceeds %d entries", ErrEvidenceReadLimitExceeded, name, limits.MaxEntries)
	case limits.MaxBytes > 0:
		return fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, name, limits.MaxBytes)
	default:
		return fmt.Errorf("%w: evidence file %s exceeded bounded read limits", ErrEvidenceReadLimitExceeded, name)
	}
}
