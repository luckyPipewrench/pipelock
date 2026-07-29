// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadEvidenceFileBounded_HappyPathAndHash(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	content := []byte("bounded evidence body\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := ReadEvidenceFileBounded(path, MaxEvidenceReadFileBytes)
	if err != nil {
		t.Fatalf("ReadEvidenceFileBounded: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content = %q, want %q", got, content)
	}

	hash, err := computeEvidenceFileHashBounded(path, MaxEvidenceReadFileBytes)
	if err != nil {
		t.Fatalf("computeEvidenceFileHashBounded: %v", err)
	}
	sum := sha256.Sum256(content)
	if want := hex.EncodeToString(sum[:]); hash != want {
		t.Fatalf("hash = %s, want %s", hash, want)
	}
}

func TestOpenRegularEvidenceFileRejectsUnsupportedPlatform(t *testing.T) {
	want := errors.New("unsupported evidence access")
	file, info, err := openRegularEvidenceFile("unused", "evidence file", want)
	if file != nil || info != nil {
		t.Fatalf("open result = (%v, %v), want nil handles", file, info)
	}
	if !errors.Is(err, want) {
		t.Fatalf("open error = %v, want %v", err, want)
	}
}

func TestReadEvidenceFileBounded_NonPositiveMaxUsesDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	if err := os.WriteFile(path, []byte("small"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, max := range []int64{0, -1} {
		got, err := ReadEvidenceFileBounded(path, max)
		if err != nil {
			t.Fatalf("ReadEvidenceFileBounded(max=%d): %v", max, err)
		}
		if string(got) != "small" {
			t.Fatalf("max=%d content = %q, want %q", max, got, "small")
		}
	}
}

func TestReadEvidenceFileBounded_ExactCapSucceeds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	content := []byte(strings.Repeat("A", 16))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := ReadEvidenceFileBounded(path, int64(len(content)))
	if err != nil {
		t.Fatalf("ReadEvidenceFileBounded at cap: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content = %q, want %q", got, content)
	}

	hash, err := computeEvidenceFileHashBounded(path, int64(len(content)))
	if err != nil {
		t.Fatalf("computeEvidenceFileHashBounded at cap: %v", err)
	}
	sum := sha256.Sum256(content)
	if want := hex.EncodeToString(sum[:]); hash != want {
		t.Fatalf("hash = %s, want %s", hash, want)
	}
}

func TestReadEvidenceFileBounded_OverCapFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	if err := os.WriteFile(path, []byte(strings.Repeat("A", 64)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := ReadEvidenceFileBounded(path, 16); !errors.Is(err, ErrEvidenceReadLimitExceeded) {
		t.Fatalf("ReadEvidenceFileBounded over cap err = %v, want ErrEvidenceReadLimitExceeded", err)
	}
	if _, err := computeEvidenceFileHashBounded(path, 16); !errors.Is(err, ErrEvidenceReadLimitExceeded) {
		t.Fatalf("computeEvidenceFileHashBounded over cap err = %v, want ErrEvidenceReadLimitExceeded", err)
	}
}

func TestReadEvidenceFileBounded_SymlinkRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	if _, err := ReadEvidenceFileBounded(link, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("ReadEvidenceFileBounded on symlink = nil error, want rejection")
	}
	if _, err := computeEvidenceFileHashBounded(link, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("computeEvidenceFileHashBounded on symlink = nil error, want rejection")
	}
}

func TestReadEvidenceFileBounded_NonRegularRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A directory is non-regular.
	if _, err := ReadEvidenceFileBounded(dir, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("ReadEvidenceFileBounded on directory = nil error, want rejection")
	}
}

func TestReadEvidenceFileBounded_MissingFile(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := ReadEvidenceFileBounded(missing, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("ReadEvidenceFileBounded on missing file = nil error, want error")
	}
	if _, err := computeEvidenceFileHashBounded(missing, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("computeEvidenceFileHashBounded on missing file = nil error, want error")
	}
}

func TestReadEvidenceFileBounded_UnreadableFileRejected(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read chmod 000 files")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("chmod unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if _, err := ReadEvidenceFileBounded(path, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("ReadEvidenceFileBounded on unreadable file = nil error, want error")
	}
	if _, err := computeEvidenceFileHashBounded(path, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("computeEvidenceFileHashBounded on unreadable file = nil error, want error")
	}
}

// TestEvidenceReadBoundsAreNotWidened pins the bounded-resume ceilings.
//
// These caps exist so an oversized evidence directory or shard fails CLOSED on
// the READ paths (query, verification, the dashboard) rather than being
// silently truncated, which would let a partial read masquerade as a verified
// chain. Raising them would make that failure quieter rather than preventing
// it.
//
// The directory ceiling no longer gates recorder RESUME, and reinstating it
// there would reintroduce a proven production outage: resume reads shards
// newest first until one yields a tail entry, under the per-file bounds this
// test also pins, and never verifies the chain. The count ceiling protected
// nothing while permanently ending receipt emission once a directory passed
// 256 shards. Note also that retention does NOT keep a directory under the
// ceiling, because expiry skips .jsonl chain shards by design; growth is
// bounded by nothing today. See sessionResumeCandidates and
// TestRecorder_ResumeSucceedsPastDirectoryCap.
//
// Tightening a bound is allowed and does not fail this test. Widening one does,
// so that it can only happen as a deliberate, reviewed decision. The behavioural
// over-cap tests scale with these constants and therefore cannot detect widening
// on their own.
func TestEvidenceReadBoundsAreNotWidened(t *testing.T) {
	t.Parallel()

	const (
		reviewedMaxDirectoryEntries = 256
		reviewedMaxFileBytes        = int64(8 << 20)
	)

	if MaxEvidenceReadDirectoryEntries > reviewedMaxDirectoryEntries {
		t.Fatalf("MaxEvidenceReadDirectoryEntries widened to %d, reviewed ceiling is %d: "+
			"raising this cap weakens fail-closed chain resume; fix accumulation via retention instead",
			MaxEvidenceReadDirectoryEntries, reviewedMaxDirectoryEntries)
	}
	if MaxEvidenceReadFileBytes > reviewedMaxFileBytes {
		t.Fatalf("MaxEvidenceReadFileBytes widened to %d, reviewed ceiling is %d: "+
			"raising this cap weakens fail-closed chain resume",
			MaxEvidenceReadFileBytes, reviewedMaxFileBytes)
	}
}
