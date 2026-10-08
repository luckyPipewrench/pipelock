// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrTornTail identifies an incomplete final JSONL write, never a malformed
// complete record. The damaged file must remain untouched.
var ErrTornTail = errors.New("torn JSONL tail")

// TornTailError locates the incomplete write and the end of the complete prefix.
type TornTailError struct {
	Path           string
	Offset         int64
	LastGoodOffset int64
}

func (e *TornTailError) Error() string {
	return fmt.Sprintf("%s: %s at byte %d (last complete boundary %d)", ErrTornTail, e.Path, e.Offset, e.LastGoodOffset)
}

func (e *TornTailError) Unwrap() error { return ErrTornTail }

// InspectJSONLTail checks structural crash damage without changing file bytes.
func InspectJSONLTail(path string) error {
	return InspectJSONLTailWithValidator(path, nil)
}

// InspectJSONLTailWithValidator validates every complete prefix record before
// classifying an incomplete final write. A valid JSON final record missing its
// newline is also validated, so invalid signatures cannot masquerade as damage.
// Healthy files retain a constant-size tail check; normal readers validate them.
func InspectJSONLTailWithValidator(path string, validate func([]byte) error) error {
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return inspectJSONLTail(file, info, path, validate)
}

// InspectEvidenceTail additionally parses evidence records. validate can verify
// signatures and chain state before permitting a torn-tail recovery.
func InspectEvidenceTail(path string, validate func(Entry) error) error {
	return InspectJSONLTailWithValidator(path, evidenceTailValidator(validate))
}

// ValidateEvidenceFile streams a whole shard with bounded per-record memory.
// Reload uses this for its current run: an intact final line cannot hide
// corruption in an earlier complete line. Tail-only legacy queries stay bounded.
func ValidateEvidenceFile(path string, validate func(Entry) error) error {
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	validator := evidenceTailValidator(validate)
	if err := inspectJSONLTail(file, info, path, validator); err != nil {
		return err
	}
	err = inspectJSONLRecords(io.NewSectionReader(file, 0, info.Size()), path, validator, false)
	if changed := ensureEvidenceFileUnchanged(file, info); changed != nil {
		return changed
	}
	return err
}

func inspectJSONLTail(file *os.File, info os.FileInfo, path string, validate func([]byte) error) error {
	size := info.Size()
	if size == 0 {
		return nil
	}
	end := size
	block := make([]byte, 4096)
	for end > 0 {
		n := min(end, int64(len(block)))
		if _, err := file.ReadAt(block[:n], end-n); err != nil {
			return err
		}
		i := int(n) - 1
		for i >= 0 && block[i] == 0 {
			i--
		}
		if i >= 0 {
			end = end - n + int64(i) + 1
			break
		}
		end -= n
	}
	if end == size {
		var last [1]byte
		if _, err := file.ReadAt(last[:], end-1); err != nil {
			return err
		}
		if last[0] == '\n' {
			// A complete snapshot is safe for append classification even when
			// another writer appends an atomic complete line after it. Readers
			// still enforce their own unchanged-file check after parsing.
			return nil
		}
	}
	err := inspectJSONLTornPrefix(io.NewSectionReader(file, 0, end), path, validate)
	if changed := ensureEvidenceFileUnchanged(file, info); changed != nil {
		return changed
	}
	return err
}

// InspectEvidenceTailBytes classifies bytes obtained through a caller's secured
// file-access path. It validates complete prefix records and any valid final JSON
// before deciding whether a writer can treat the final fragment as crash damage.
func InspectEvidenceTailBytes(path string, data []byte, validate func(Entry) error) error {
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return nil
	}
	data = bytes.TrimRight(data, "\x00")
	return inspectJSONLTornPrefix(bytes.NewReader(data), path, evidenceTailValidator(validate))
}

func inspectJSONLTornPrefix(input io.Reader, path string, validate func([]byte) error) error {
	return inspectJSONLRecords(input, path, validate, true)
}

func inspectJSONLRecords(input io.Reader, path string, validate func([]byte) error, torn bool) error {
	reader := bufio.NewReader(input)
	var offset, lastGood int64
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Accumulate at most one bounded record, never an unbounded shard.
			line = bytes.Clone(line)
			for errors.Is(err, bufio.ErrBufferFull) && len(line) <= maxEntryWireLineBytes {
				chunk, nextErr := reader.ReadSlice('\n')
				line = append(line, chunk...)
				err = nextErr
			}
		}
		if len(line) > maxEntryWireLineBytes {
			return fmt.Errorf("tail line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		complete := len(line) > 0 && line[len(line)-1] == '\n'
		payload := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		if len(payload) > MaxEntryLineBytes {
			return fmt.Errorf("tail line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
		}
		record := []byte(TrimEntryLine(string(line)))
		if bytes.IndexByte(record, 0) >= 0 {
			return errors.New("malformed JSONL record: embedded NUL")
		}
		if len(record) > 0 && (complete || json.Valid(record)) {
			if !json.Valid(record) {
				return fmt.Errorf("malformed complete JSONL record at byte %d", offset)
			}
			if validate != nil {
				if err := validate(record); err != nil {
					return err
				}
			}
		}
		if complete {
			offset += int64(len(line))
			lastGood = offset
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if torn {
		return &TornTailError{Path: path, Offset: lastGood, LastGoodOffset: lastGood}
	}
	return nil
}

func evidenceTailValidator(validate func(Entry) error) func([]byte) error {
	var previous *Entry
	return func(line []byte) error {
		entry, err := parseDirectionalEntry(line)
		if err != nil {
			return err
		}
		if entry.Hash == "" || ComputeHash(entry) != entry.Hash {
			return errors.New("evidence tail prefix hash mismatch")
		}
		if previous != nil && (entry.PrevHash != previous.Hash || entry.Sequence == 0 || entry.Sequence-1 != previous.Sequence || entry.SessionID != previous.SessionID) {
			return errors.New("evidence tail prefix chain link mismatch")
		}
		if validate != nil {
			if err := validate(entry); err != nil {
				return err
			}
		}
		previous = &entry
		return nil
	}
}
