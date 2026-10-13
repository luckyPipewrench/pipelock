// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/verification"
)

// HistoryObservation binds a torn final shard to its exact bytes and complete
// boundary. It has the same meaning as CaptureTornEvidence's TornSnapshot.
type HistoryObservation struct {
	Shard    string
	Snapshot TornSnapshot
}

// WalkSessionHistoryObserved streams a recovery candidate once. Only a final
// unterminated fragment may be damage; valid JSON in that fragment is validated
// by visit with complete=false, and never delivered as durable history. All
// secured-open, identity and membership guards belong to the authoritative
// history-file walk. Its returned observation is usable only on a successful
// walk, including the final stability checks.
func WalkSessionHistoryObserved(dir, session string, options verification.Options, visit func(Entry, bool) error) (*HistoryObservation, error) {
	location, err := ResolveEvidenceLocation(dir, "")
	if err != nil {
		return nil, err
	}
	var observation *HistoryObservation
	err = WalkSessionHistoryFiles(location, session, func(shard SessionHistoryShard, input io.Reader) error {
		if err := options.Check(); err != nil {
			return err
		}
		h := sha256.New()
		source := &historyProgressReader{Reader: io.TeeReader(input, h), options: options, session: session}
		// CaptureTornEvidence trims the entire NUL suffix before enforcing the
		// record limit. Sparse crash padding must not become an oversized record.
		trimmed := &trailingNULReader{source: source}
		_, offset, torn, err := walkObservedEntries(trimmed, session, visit)
		if err != nil {
			return err
		}
		if torn || trimmed.padding {
			if !shard.Final {
				return errors.New("recovery predecessor has a torn non-final segment")
			}
			observation = &HistoryObservation{Shard: shard.Name, Snapshot: TornSnapshot{Size: source.readBytes, Offset: offset, SHA256: hex.EncodeToString(h.Sum(nil))}}
		}
		return options.Check()
	})
	if err != nil {
		return nil, err
	}
	return observation, options.Check()
}

// trailingNULReader implements inspectJSONLTail's TrimRight(data, "\x00")
// without buffering a sparse tail. Any NUL followed by a non-NUL byte is
// embedded damage, which the existing tail parser rejects.
type trailingNULReader struct {
	source  io.Reader
	padding bool
}

func (r *trailingNULReader) Read(p []byte) (int, error) {
	for {
		n, err := r.source.Read(p)
		if r.padding {
			if len(bytes.Trim(p[:n], "\x00")) > 0 {
				return 0, errors.New("malformed JSONL record: embedded NUL")
			}
			if err != nil || n == 0 {
				return 0, err
			}
			continue
		}
		at := bytes.IndexByte(p[:n], 0)
		if at < 0 {
			return n, err
		}
		r.padding = true
		if len(bytes.Trim(p[at:n], "\x00")) > 0 {
			return 0, errors.New("malformed JSONL record: embedded NUL")
		}
		if at > 0 {
			return at, nil
		}
		if err != nil || n == 0 {
			return 0, err
		}
	}
}

func walkObservedEntries(input io.Reader, session string, visit func(Entry, bool) error) (size, offset int64, torn bool, retErr error) {
	reader := bufio.NewReader(input)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			line = bytes.Clone(line)
			for errors.Is(err, bufio.ErrBufferFull) && len(line) <= maxEntryWireLineBytes {
				chunk, nextErr := reader.ReadSlice('\n')
				line = append(line, chunk...)
				err = nextErr
			}
		}
		size += int64(len(line))
		if len(line) > maxEntryWireLineBytes {
			return size, offset, false, fmt.Errorf("tail line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return size, offset, false, err
		}
		complete := len(line) > 0 && line[len(line)-1] == '\n'
		if !complete && len(line) > 0 {
			torn = true
			line = bytes.TrimRight(line, "\x00")
		}
		payload := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
		if len(payload) > MaxEntryLineBytes {
			return size, offset, false, fmt.Errorf("tail line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
		}
		record := []byte(TrimEntryLine(string(payload)))
		if bytes.IndexByte(record, 0) >= 0 {
			return size, offset, false, errors.New("malformed JSONL record: embedded NUL")
		}
		if len(record) > 0 && (complete || json.Valid(record)) {
			entry, parseErr := ParseEntryLine(record)
			if parseErr != nil {
				return size, offset, false, parseErr
			}
			if !acceptedEntryVersions[entry.Version] {
				return size, offset, false, fmt.Errorf("unsupported entry version %d (accepted: 1, 2, 3)", entry.Version)
			}
			if schemaErr := ValidateEntrySchema(entry); schemaErr != nil {
				return size, offset, false, schemaErr
			}
			if entry.SessionID != session {
				return size, offset, false, entrySessionError(entry, session)
			}
			if visitErr := visit(entry, complete); visitErr != nil {
				return size, offset, false, visitErr
			}
		}
		if complete {
			offset = size
		}
		if errors.Is(err, io.EOF) {
			return size, offset, torn, nil
		}
	}
}
