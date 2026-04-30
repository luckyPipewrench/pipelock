// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package ingest streams recorder JSONL into typed inference inputs while
// verifying the recorder hash chain incrementally.
package ingest

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	streamBuffer       = 64
	initialLineBuffer  = 64 * 1024
	maxRecorderLineLen = 16 * 1024 * 1024
)

// ErrHashChainBroken is wrapped by fatal errors when a parsed recorder entry
// fails PrevHash linkage or stored-hash verification.
var ErrHashChainBroken = errors.New("inference ingest: hash chain broken")

// ErrMalformedEntry is wrapped by non-fatal errors when a JSONL line or typed
// capture detail cannot be consumed. The stream drops that line and continues.
var ErrMalformedEntry = errors.New("inference ingest: malformed entry")

// ErrUnsupportedSchemaVersion is wrapped by fatal errors when a parsed recorder
// entry uses a schema version outside StreamOptions.AllowSchemaVersion or a
// version this reader cannot hash.
var ErrUnsupportedSchemaVersion = errors.New("inference ingest: unsupported schema version")

// StreamOptions controls recorder JSONL ingestion.
type StreamOptions struct {
	// EscrowPrivateKey is accepted for the raw-sidecar decryption path. This PR
	// only plumbs the key through; raw escrow decryption is intentionally a no-op.
	EscrowPrivateKey []byte

	// AllowSchemaVersion gates recorder.Entry.Version. The zero value allows
	// recorder v1 and the current recorder.EntryVersion.
	AllowSchemaVersion []int
}

// Entry is the inference ingest wrapper for a verified recorder entry.
type Entry struct {
	// Recorder is the original recorder entry after JSON decoding and hash-chain
	// verification.
	Recorder recorder.Entry

	// Capture is populated for capture.EntryTypeCapture entries after Detail is
	// converted into the typed capture schema. It is nil for non-capture entries.
	Capture *capture.CaptureSummary
}

type streamState struct {
	escrowPrivateKey []byte
	allowedVersions  map[int]bool
}

// Stream reads recorder JSONL from input and returns channels for verified
// entries and ingestion errors. Malformed lines are reported on the error
// channel and skipped; hash-chain and recorder schema errors are fatal and stop
// the stream. Both channels are closed when processing ends.
func Stream(input io.Reader, opts StreamOptions) (<-chan Entry, <-chan error) {
	entries := make(chan Entry, streamBuffer)
	errs := make(chan error, streamBuffer)
	state := newStreamState(opts)

	go func() {
		defer close(entries)
		defer close(errs)
		state.run(input, entries, errs)
	}()

	return entries, errs
}

func newStreamState(opts StreamOptions) streamState {
	state := streamState{
		escrowPrivateKey: append([]byte(nil), opts.EscrowPrivateKey...),
		allowedVersions:  make(map[int]bool),
	}
	if len(opts.AllowSchemaVersion) == 0 {
		state.allowedVersions[1] = true
		state.allowedVersions[recorder.EntryVersion] = true
		return state
	}
	for _, version := range opts.AllowSchemaVersion {
		state.allowedVersions[version] = true
	}
	return state
}

func (s streamState) run(input io.Reader, entries chan<- Entry, errs chan<- error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, initialLineBuffer), maxRecorderLineLen)

	var (
		droppedLines int
		lineNo       int
		previousHash string
		seenEntry    bool
	)

	for scanner.Scan() {
		lineNo++
		rec, err := parseRecorderEntry(scanner.Bytes())
		if err != nil {
			droppedLines++
			errs <- malformedError(lineNo, droppedLines, "decode recorder entry", err)
			continue
		}

		if err := s.verifyRecorderEntry(rec, lineNo, previousHash, seenEntry); err != nil {
			errs <- err
			return
		}
		previousHash = rec.Hash
		seenEntry = true

		entry, err := typedEntry(rec)
		if err != nil {
			droppedLines++
			errs <- malformedError(lineNo, droppedLines, "decode capture detail", err)
			continue
		}
		entries <- entry
	}

	if err := scanner.Err(); err != nil {
		droppedLines++
		errs <- malformedError(lineNo+1, droppedLines, "read recorder line", err)
	}
}

type rawRecorderEntry struct {
	Version   int             `json:"v"`
	Sequence  uint64          `json:"seq"`
	Timestamp time.Time       `json:"ts"`
	SessionID string          `json:"session_id"`
	TraceID   string          `json:"trace_id,omitempty"`
	Type      string          `json:"type"`
	EventKind string          `json:"event_kind,omitempty"`
	Transport string          `json:"transport"`
	Summary   string          `json:"summary"`
	Detail    json.RawMessage `json:"detail"`
	RawRef    string          `json:"raw_ref,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

func parseRecorderEntry(line []byte) (recorder.Entry, error) {
	var raw rawRecorderEntry
	if err := json.Unmarshal(line, &raw); err != nil {
		return recorder.Entry{}, err
	}

	detail := json.RawMessage("null")
	if raw.Detail != nil && string(raw.Detail) != "null" {
		detail = append(json.RawMessage(nil), raw.Detail...)
	}

	return recorder.Entry{
		Version:   raw.Version,
		Sequence:  raw.Sequence,
		Timestamp: raw.Timestamp,
		SessionID: raw.SessionID,
		TraceID:   raw.TraceID,
		Type:      raw.Type,
		EventKind: raw.EventKind,
		Transport: raw.Transport,
		Summary:   raw.Summary,
		Detail:    detail,
		RawRef:    raw.RawRef,
		PrevHash:  raw.PrevHash,
		Hash:      raw.Hash,
	}, nil
}

func (s streamState) verifyRecorderEntry(rec recorder.Entry, lineNo int, previousHash string, seenEntry bool) error {
	if !s.allowedVersions[rec.Version] || !hashSupportedVersion(rec.Version) {
		return fmt.Errorf("%w (line=%d, seq=%d, version=%d)", ErrUnsupportedSchemaVersion, lineNo, rec.Sequence, rec.Version)
	}

	computedHash := recorder.ComputeHash(rec)
	if computedHash != rec.Hash {
		return fmt.Errorf(
			"%w (line=%d, seq=%d): computed hash %s != stored hash %s",
			ErrHashChainBroken,
			lineNo,
			rec.Sequence,
			computedHash,
			rec.Hash,
		)
	}

	if !seenEntry {
		if rec.PrevHash != recorder.GenesisHash {
			return fmt.Errorf(
				"%w (line=%d, seq=%d): first entry PrevHash should be %q, got %q",
				ErrHashChainBroken,
				lineNo,
				rec.Sequence,
				recorder.GenesisHash,
				rec.PrevHash,
			)
		}
		return nil
	}

	if rec.PrevHash != previousHash {
		return fmt.Errorf(
			"%w (line=%d, seq=%d): PrevHash %s != previous Hash %s",
			ErrHashChainBroken,
			lineNo,
			rec.Sequence,
			rec.PrevHash,
			previousHash,
		)
	}
	return nil
}

func hashSupportedVersion(version int) bool {
	return recorder.IsAcceptedEntryVersion(version)
}

func typedEntry(rec recorder.Entry) (Entry, error) {
	entry := Entry{Recorder: rec}
	if rec.Type != capture.EntryTypeCapture {
		return entry, nil
	}

	var summary capture.CaptureSummary
	raw, err := asRawMessage(rec.Detail)
	if err != nil {
		return Entry{}, fmt.Errorf("marshal capture detail: %w", err)
	}
	if err := json.Unmarshal(raw, &summary); err != nil {
		return Entry{}, fmt.Errorf("unmarshal capture detail: %w", err)
	}
	if summary.CaptureSchemaVersion != capture.CaptureSchemaV1 {
		return Entry{}, fmt.Errorf(
			"unsupported capture schema version %d (want %d)",
			summary.CaptureSchemaVersion,
			capture.CaptureSchemaV1,
		)
	}

	entry.Capture = &summary
	return entry, nil
}

func asRawMessage(detail any) (json.RawMessage, error) {
	raw, ok := detail.(json.RawMessage)
	if ok {
		return raw, nil
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func malformedError(lineNo, droppedLines int, context string, err error) error {
	return fmt.Errorf("%w (line=%d, dropped=%d): %s: %w", ErrMalformedEntry, lineNo, droppedLines, context, err)
}
