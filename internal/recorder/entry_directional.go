// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// ReadHeadEntriesBounded reads a bounded prefix of an evidence shard. Unlike
// ReadEntries, an oversized file is not rejected merely for having more bytes
// after the prefix; Truncated reports that unseen suffix. This is for callers
// that need an earliest entry without treating a legacy shard's total size as
// an availability gate.
func ReadHeadEntriesBounded(path string, maxEntries int, maxBytes int64) ([]Entry, bool, error) {
	limits := directionalEntryReadLimits(maxEntries, maxBytes)
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()

	readLimit := limits.MaxBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	entries, truncated, _, err := readEntriesFromReader(io.LimitReader(file, readLimit), limits)
	if err != nil {
		return nil, false, fmt.Errorf("reading evidence head: %w", err)
	}
	if err := ensureEvidenceFileUnchanged(file, info); err != nil {
		return nil, false, err
	}
	return entries, truncated || info.Size() > limits.MaxBytes, nil
}

// ReadTailEntriesBounded reads complete entries from a bounded suffix of an
// evidence shard and returns them newest-first. It reads at most maxBytes plus
// one maximum-size entry so the suffix can begin at a trusted newline boundary.
// Truncated reports that older bytes or entries were not returned.
func ReadTailEntriesBounded(path string, maxEntries int, maxBytes int64) ([]Entry, bool, error) {
	limits := directionalEntryReadLimits(maxEntries, maxBytes)
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() == 0 {
		return nil, false, nil
	}

	window := limits.MaxBytes
	extra := int64(maxEntryWireLineBytes + 1)
	if window > math.MaxInt64-extra {
		window = math.MaxInt64
	} else {
		window += extra
	}
	readLen := min(info.Size(), window)
	start := info.Size() - readLen
	data := make([]byte, readLen)
	if _, err := io.ReadFull(io.NewSectionReader(file, start, readLen), data); err != nil {
		return nil, false, fmt.Errorf("reading evidence tail: %w", err)
	}
	if err := ensureEvidenceFileUnchanged(file, info); err != nil {
		return nil, false, err
	}

	entries := make([]Entry, 0, min(limits.MaxEntries, 64))
	truncated := start > 0
	var consumed int64
	end := len(data)
	for end > 0 {
		lineEnd := end
		wireBytes := int64(0)
		if data[lineEnd-1] == '\n' {
			lineEnd--
			wireBytes++
		}
		lineStart := bytes.LastIndexByte(data[:lineEnd], '\n') + 1
		line := data[lineStart:lineEnd]
		wireBytes += int64(len(line))
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		consumed += wireBytes
		if consumed > limits.MaxBytes || len(entries) >= limits.MaxEntries {
			truncated = true
			break
		}
		if len(line) > MaxEntryLineBytes {
			return nil, false, fmt.Errorf("tail line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
		}
		if len(bytes.TrimSpace(line)) != 0 {
			if start > 0 && lineStart == 0 {
				truncated = true
				break
			}
			parsed, parseErr := parseDirectionalEntry(line)
			if parseErr != nil {
				return nil, false, parseErr
			}
			entries = append(entries, parsed)
		}
		if lineStart == 0 {
			break
		}
		end = lineStart
	}
	return entries, truncated, nil
}

func directionalEntryReadLimits(maxEntries int, maxBytes int64) entryReadLimits {
	if maxEntries <= 0 {
		maxEntries = MaxEvidenceReadEntries
	}
	if maxBytes <= 0 {
		maxBytes = MaxEvidenceReadFileBytes
	}
	return entryReadLimits{MaxEntries: maxEntries, MaxBytes: maxBytes}
}

func parseDirectionalEntry(line []byte) (Entry, error) {
	entries, truncated, _, err := readEntriesFromReader(bytes.NewReader(line), entryReadLimits{
		MaxEntries: 1,
		MaxBytes:   int64(maxEntryWireLineBytes),
	})
	if err != nil {
		return Entry{}, fmt.Errorf("parsing evidence tail entry: %w", err)
	}
	if truncated || len(entries) != 1 {
		return Entry{}, errors.New("parsing evidence tail entry: expected exactly one complete entry")
	}
	return entries[0], nil
}

func ensureEvidenceFileUnchanged(file *os.File, before os.FileInfo) error {
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return errors.New("evidence file changed during read")
	}
	return nil
}
