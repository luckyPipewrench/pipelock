// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// MaxEvidenceReadFileBytes matches the bounded dashboard evidence
	// verification ceiling: one evidence source may contribute at most 8 MiB
	// to in-memory verifier/resume reads.
	MaxEvidenceReadFileBytes int64 = 8 << 20

	// MaxEvidenceReadDirectoryEntries matches the bounded dashboard evidence
	// directory ceiling.
	MaxEvidenceReadDirectoryEntries = 256

	// MaxEvidenceReadEntries matches the recorder's default shard size. A
	// healthy default shard can be resumed, while appended over-cap records fail
	// closed instead of being silently ignored.
	MaxEvidenceReadEntries = defaultMaxEntriesPerFile
)

// ErrEvidenceReadLimitExceeded marks a fail-closed evidence read cap hit.
var ErrEvidenceReadLimitExceeded = errors.New("evidence read limit exceeded")

func openRegularEvidenceFile(path, label string) (*os.File, os.FileInfo, error) {
	cleanPath := filepath.Clean(path)
	before, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is symlinked or non-regular", label)
	}
	file, err := os.OpenFile(cleanPath, os.O_RDONLY|evidenceReadNoFollowFlag|evidenceReadNonblockFlag, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s changed or is non-regular", label)
	}
	return file, info, nil
}

// readBoundedEvidence opens path as a regular no-follow file and copies at
// most maxBytes into sink. It is the single fail-closed read path shared by
// ReadEvidenceFileBounded and computeEvidenceFileHashBounded: it rejects the
// read if the file exceeds maxBytes (both by pre-read size and by actual bytes
// copied) or if the file changes during the read. A non-positive maxBytes
// falls back to MaxEvidenceReadFileBytes.
func readBoundedEvidence(path string, maxBytes int64, sink io.Writer) error {
	if maxBytes <= 0 {
		maxBytes = MaxEvidenceReadFileBytes
	}
	file, info, err := openRegularEvidenceFile(path, "evidence file")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > maxBytes {
		return fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(path), maxBytes)
	}
	written, err := io.Copy(sink, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(path), maxBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return errors.New("evidence file changed during read")
	}
	return nil
}

// ReadEvidenceFileBounded reads a regular evidence file through a no-follow
// open and returns an error if the file exceeds maxBytes.
func ReadEvidenceFileBounded(path string, maxBytes int64) ([]byte, error) {
	var buf bytes.Buffer
	if err := readBoundedEvidence(path, maxBytes, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func computeEvidenceFileHashBounded(path string, maxBytes int64) (string, error) {
	h := sha256.New()
	if err := readBoundedEvidence(path, maxBytes, h); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
