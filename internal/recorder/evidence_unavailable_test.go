// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIsEvidenceUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"changed during read", fmt.Errorf("walk: %w", ErrEvidenceChanged), true},
		{"permission denied", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: os.ErrPermission}, true},
		{"I/O error", &fs.PathError{Op: "read", Path: "evidence-a-0.jsonl", Err: syscall.EIO}, true},
		{"bare errno", fmt.Errorf("sync: %w", syscall.EIO), true},
		{"missing file is a finding", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: os.ErrNotExist}, false},
		{"symlink refused by no-follow open is a finding", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: syscall.ELOOP}, false},
		{"path component not a directory is a finding", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: syscall.ENOTDIR}, false},
		{"directory where a file belongs is a finding", &fs.PathError{Op: "read", Path: "evidence-a-0.jsonl", Err: syscall.EISDIR}, false},
		{"refused evidence is a finding", fmt.Errorf("%w: evidence file is symlinked", ErrEvidenceRefused), false},
		{"refused evidence wrapping permission stays a finding", fmt.Errorf("%w: %w", ErrEvidenceRefused, os.ErrPermission), false},
		{"malformed content is a finding", errors.New("entry 3: invalid character"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsEvidenceUnavailable(tc.err); got != tc.want {
				t.Fatalf("IsEvidenceUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestEnsureEvidenceFileUnchangedReportsSentinel covers the post-read check
// shared by the directional readers: a file that changed after it was opened
// must carry ErrEvidenceChanged, so callers retry or report no verdict instead
// of treating a race with the writer as a finding.
func TestEnsureEvidenceFileUnchangedReportsSentinel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence-a-0.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureEvidenceFileUnchanged(f, before); err != nil {
		t.Fatalf("unchanged file: %v", err)
	}
	if err := os.WriteFile(path, []byte("{}\n{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = ensureEvidenceFileUnchanged(f, before)
	if !errors.Is(err, ErrEvidenceChanged) || !IsEvidenceUnavailable(err) {
		t.Fatalf("changed file: err = %v, want ErrEvidenceChanged classified as unavailable evidence", err)
	}
}

// TestWalkEvidenceLocationReportsSentinelWhenShardChanges covers the location
// walk used by session history: a shard rewritten while its entries are being
// delivered must fail with ErrEvidenceChanged, the error callers retry on.
func TestWalkEvidenceLocationReportsSentinelWhenShardChanges(t *testing.T) {
	source := "../../sdk/conformance/testdata/recovery-seals/valid/evidence/evidence-proxy.run." + "11111111111111111111111111111111-0.jsonl"
	padded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture ends in zero padding, which the reader reports as a torn
	// tail; drop it so the unchanged walk is clean.
	raw := bytes.TrimRight(padded, "\x00")
	dir := t.TempDir()
	const name = "evidence-proxy-0.jsonl"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	location := EvidenceLocation{Root: dir, Dir: dir}

	if _, _, _, err := walkBoundedEntriesAtEvidenceLocation(location, name, defaultEntryReadLimits(), func(Entry) error { return nil }); err != nil {
		t.Fatalf("unchanged shard: %v", err)
	}

	rewritten := false
	_, _, _, err = walkBoundedEntriesAtEvidenceLocation(location, name, defaultEntryReadLimits(), func(Entry) error {
		if rewritten {
			return nil
		}
		rewritten = true
		return os.WriteFile(path, append(append([]byte(nil), raw...), raw...), 0o600)
	})
	if !rewritten {
		t.Fatal("walk delivered no entries")
	}
	if !errors.Is(err, ErrEvidenceChanged) || !IsEvidenceUnavailable(err) {
		t.Fatalf("rewritten shard: err = %v, want ErrEvidenceChanged classified as unavailable evidence", err)
	}
}

// TestOfflineCompactionStreamReportsSentinelWhenShardChanges covers the
// offline-compaction read: a source shard rewritten while it streams must fail
// with ErrEvidenceChanged, so a caller can tell a race from a damaged shard.
func TestOfflineCompactionStreamReportsSentinelWhenShardChanges(t *testing.T) {
	dir := t.TempDir()
	const name = "evidence-proxy-0.jsonl"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	location := EvidenceLocation{Root: dir, Dir: dir}

	if err := StreamEvidenceLocationFileForOfflineCompaction(location, name, func(io.Reader, os.FileInfo) error { return nil }); err != nil {
		t.Fatalf("unchanged shard: %v", err)
	}
	err := StreamEvidenceLocationFileForOfflineCompaction(location, name, func(io.Reader, os.FileInfo) error {
		return os.WriteFile(path, []byte("{}\n{}\n"), 0o600)
	})
	if !errors.Is(err, ErrEvidenceChanged) || !IsEvidenceUnavailable(err) {
		t.Fatalf("rewritten shard: err = %v, want ErrEvidenceChanged classified as unavailable evidence", err)
	}
}
