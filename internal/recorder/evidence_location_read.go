// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

func validateEvidenceLocation(location EvidenceLocation) error {
	root := filepath.Clean(location.Root)
	if location.Root == "" || root == "." {
		return errors.New("evidence location is missing its root")
	}
	id := location.ID
	if id != "" {
		cleanID, err := cleanEvidenceLocationID(filepath.FromSlash(id))
		if err != nil {
			return fmt.Errorf("invalid evidence location ID: %w", err)
		}
		if cleanID != id {
			return errors.New("evidence location ID is not canonical")
		}
	}
	wantDir := root
	if id != "" {
		wantDir = filepath.Join(root, filepath.FromSlash(id))
	}
	if filepath.Clean(location.Dir) != wantDir {
		return errors.New("evidence location directory does not match its root and ID")
	}
	return nil
}

func readEvidenceLocationDirectoryEntries(location EvidenceLocation, maxEntries int) ([]os.DirEntry, bool, error) {
	directory, err := openEvidenceLocationDirectory(location)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = directory.Close() }()
	if maxEntries <= 0 {
		entries, readErr := directory.ReadDir(-1)
		return entries, false, readErr
	}
	readLimit := maxEntries
	if readLimit < math.MaxInt {
		readLimit++
	}
	entries, readErr := directory.ReadDir(readLimit)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, false, readErr
	}
	if len(entries) > maxEntries {
		return entries[:maxEntries], true, nil
	}
	return entries, false, nil
}

// ReadEvidenceLocationEntries securely lists one already-resolved evidence location.
func ReadEvidenceLocationEntries(location EvidenceLocation) ([]os.DirEntry, error) {
	entries, _, err := readEvidenceLocationDirectoryEntries(location, 0)
	return entries, err
}

func readEntriesAtEvidenceLocation(location EvidenceLocation, name string, limits entryReadLimits) ([]Entry, bool, int64, error) {
	file, before, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return nil, false, 0, fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = file.Close() }()
	entries, truncated, bytesRead, err := readEntriesFromReader(file, limits)
	if err != nil {
		return nil, false, bytesRead, fmt.Errorf("reading evidence file: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, false, bytesRead, fmt.Errorf("restat evidence file: %w", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, false, bytesRead, errors.New("evidence file changed during read")
	}
	return entries, truncated, bytesRead, nil
}

// ReadEvidenceLocationFileBounded reads one regular evidence file through its
// resolved location without following a substituted directory or file symlink.
func ReadEvidenceLocationFileBounded(location EvidenceLocation, name string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxEvidenceReadFileBytes
	}
	file, before, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if before.Size() > maxBytes {
		return nil, fmt.Errorf("%w: evidence file exceeds %d bytes", ErrEvidenceReadLimitExceeded, maxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%w: evidence file exceeds %d bytes", ErrEvidenceReadLimitExceeded, maxBytes)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, errors.New("evidence file changed during read")
	}
	return raw, nil
}

// ReadEvidenceLocationFileTail reads at most maxBytes from the end of one
// regular evidence file. The boolean reports that older bytes were omitted.
func ReadEvidenceLocationFileTail(location EvidenceLocation, name string, maxBytes int64) ([]byte, bool, error) {
	if maxBytes <= 0 {
		return nil, false, errors.New("evidence tail limit must be positive")
	}
	file, before, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	readLen := min(before.Size(), maxBytes)
	start := before.Size() - readLen
	raw := make([]byte, readLen)
	if _, err := io.ReadFull(io.NewSectionReader(file, start, readLen), raw); err != nil {
		return nil, false, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, false, errors.New("evidence file changed during read")
	}
	return raw, start > 0, nil
}
