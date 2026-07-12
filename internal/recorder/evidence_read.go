// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
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

// ReadEvidenceFileBounded reads a regular evidence file through a no-follow
// open and returns an error if the file exceeds maxBytes.
func ReadEvidenceFileBounded(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxEvidenceReadFileBytes
	}
	file, info, err := openRegularEvidenceFile(path, "evidence file")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(path), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(path), maxBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return nil, errors.New("evidence file changed during read")
	}
	return data, nil
}

func computeEvidenceFileHashBounded(path string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = MaxEvidenceReadFileBytes
	}
	file, info, err := openRegularEvidenceFile(path, "evidence file")
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > maxBytes {
		return "", fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(path), maxBytes)
	}
	h := sha256.New()
	written, err := io.Copy(h, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxBytes {
		return "", fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(path), maxBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	if after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return "", errors.New("evidence file changed during read")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
