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

// ErrEvidenceFileChanged reports that an evidence file grew, shrank or was
// replaced while it was being read. A live recorder appending to the file is
// the ordinary cause; readers decide whether to retry or treat it as
// inconclusive, never as corruption.
var ErrEvidenceFileChanged = fmt.Errorf("%w: evidence file changed during read", ErrEvidenceChanged)

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

// OpenEvidenceDirectory opens an evidence directory through the platform's
// secure traversal, including its unsupported-platform access check.
func OpenEvidenceDirectory(dir string) (*os.File, error) {
	return openEvidenceLocationDirectory(EvidenceLocation{Root: dir, Dir: dir})
}

// OpenEvidenceFile opens an evidence artifact through the same directory
// traversal and regular-file checks as the session evidence reader.
func OpenEvidenceFile(path string) (*os.File, os.FileInfo, error) {
	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)
	return openEvidenceLocationFile(EvidenceLocation{Root: dir, Dir: dir}, filepath.Base(clean))
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

// ReadEvidenceLocationEntriesBounded lists at most maxEntries and reports
// whether another entry exists without retaining an unbounded directory.
func ReadEvidenceLocationEntriesBounded(location EvidenceLocation, maxEntries int) ([]os.DirEntry, bool, error) {
	return readEvidenceLocationDirectoryEntries(location, maxEntries)
}

func readEntriesAtEvidenceLocation(location EvidenceLocation, name string, limits entryReadLimits) ([]Entry, bool, int64, error) {
	var entries []Entry
	_, truncated, bytesRead, err := walkBoundedEntriesAtEvidenceLocation(location, name, limits, func(e Entry) error {
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return nil, false, bytesRead, err
	}
	return entries, truncated, bytesRead, nil
}

// walkBoundedEntriesAtEvidenceLocation reads one shard through its resolved
// location under limits, delivering each entry to consume. It returns the
// number of entries delivered. A shard that changed while it was read is an
// error even though its entries were already delivered.
func walkBoundedEntriesAtEvidenceLocation(location EvidenceLocation, name string, limits entryReadLimits, consume func(Entry) error) (int, bool, int64, error) {
	file, before, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return 0, false, 0, fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = file.Close() }()
	count := 0
	truncated, bytesRead, err := walkEntriesFromReader(file, limits, func(e Entry) error {
		count++
		return consume(e)
	})
	if err != nil {
		return 0, false, bytesRead, fmt.Errorf("reading evidence file: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return 0, false, bytesRead, fmt.Errorf("restat evidence file: %w", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return 0, false, bytesRead, ErrEvidenceFileChanged
	}
	return count, truncated, bytesRead, nil
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
		return nil, ErrEvidenceFileChanged
	}
	return raw, nil
}

// ReadEvidenceLocationFileForOfflineCompaction reads one immutable source
// shard for a stopped, operator-invoked compaction ceremony. Callers must pass
// their remaining aggregate budget. Online query, view, serve, and doctor
// paths must continue to use ReadEvidenceLocationFileBounded with their normal
// 8 MiB ceiling.
func ReadEvidenceLocationFileForOfflineCompaction(location EvidenceLocation, name string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("offline compaction byte limit must be positive")
	}
	return ReadEvidenceLocationFileBounded(location, name, maxBytes)
}

// StreamEvidenceLocationFileForOfflineCompaction streams one immutable source
// shard for an explicitly offline compaction ceremony.  It deliberately does
// not impose the online whole-file ceiling: callers must process the stream
// with their own bounded buffers.  The callback is invoked while the no-follow
// descriptor is open and the file is re-statted afterwards, so a replacement,
// resize, or timestamp change fails the ceremony rather than producing a
// partially trusted rewrite.  Do not use this API for query, view, serve, or
// doctor paths.
func StreamEvidenceLocationFileForOfflineCompaction(location EvidenceLocation, name string, consume func(io.Reader, os.FileInfo) error) error {
	if consume == nil {
		return errors.New("offline compaction stream consumer is required")
	}
	file, before, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := consume(file, before); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() {
		return fmt.Errorf("%w: evidence file changed during offline compaction read", ErrEvidenceChanged)
	}
	return nil
}

// afterAppendTailRead is a test seam between the read and the restat in
// ReadEvidenceLocationAppendTail. Production leaves it a no-op.
var afterAppendTailRead = func(string) {}

// ReadEvidenceLocationAppendTail reads up to maxBytes ending at the file's
// size when it was opened. It tolerates appends made during the read: the
// bytes it returns lie in a prefix that an append does not change. A file
// that shrank during the read returns ErrEvidenceFileChanged. The read stays
// on the file that was opened: a rename over its path during the read is seen
// by the next read, not this one.
// Use it for a live recorder's own files; use ReadEvidenceLocationFileTail
// where the whole file must be stable.
func ReadEvidenceLocationAppendTail(location EvidenceLocation, name string, maxBytes int64) ([]byte, bool, error) {
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
	afterAppendTailRead(name)
	after, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(before, after) || after.Size() < before.Size() {
		return nil, false, ErrEvidenceFileChanged
	}
	return raw, start > 0, nil
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
		return nil, false, ErrEvidenceFileChanged
	}
	return raw, start > 0, nil
}
