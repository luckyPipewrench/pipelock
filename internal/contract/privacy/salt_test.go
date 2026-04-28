// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package privacy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	testEnvVar      = "PIPELOCK_TEST_SALT"
	testEnvSource   = "${PIPELOCK_TEST_SALT}"
	testSaltLiteral = "salt"
	testSaltFile    = "salt.txt"
)

func TestLoadSalt_EnvVarSet(t *testing.T) {
	t.Setenv(testEnvVar, "from-env")
	got, err := LoadSalt(testEnvSource)
	if err != nil {
		t.Fatalf("LoadSalt: unexpected error: %v", err)
	}
	if string(got) != "from-env" {
		t.Fatalf("LoadSalt: got %q, want %q", string(got), "from-env")
	}
}

func TestLoadSalt_EnvVarUnset(t *testing.T) {
	// Make sure no stale value leaks in from the host environment.
	t.Setenv(testEnvVar, "tmp")
	_ = os.Unsetenv(testEnvVar)
	_, err := LoadSalt(testEnvSource)
	if !errors.Is(err, ErrSaltUnset) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltUnset", err)
	}
}

func TestLoadSalt_EnvVarEmpty(t *testing.T) {
	t.Setenv(testEnvVar, "")
	_, err := LoadSalt(testEnvSource)
	if !errors.Is(err, ErrSaltUnset) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltUnset", err)
	}
}

func TestLoadSalt_FileTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, testSaltFile)
	if err := os.WriteFile(p, []byte("salt\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadSalt("file:" + p)
	if err != nil {
		t.Fatalf("LoadSalt: %v", err)
	}
	if string(got) != testSaltLiteral {
		t.Fatalf("LoadSalt: got %q, want %q", string(got), testSaltLiteral)
	}
}

func TestLoadSalt_FileNoNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, testSaltFile)
	if err := os.WriteFile(p, []byte(testSaltLiteral), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadSalt("file:" + p)
	if err != nil {
		t.Fatalf("LoadSalt: %v", err)
	}
	if string(got) != testSaltLiteral {
		t.Fatalf("LoadSalt: got %q, want %q", string(got), testSaltLiteral)
	}
}

func TestLoadSalt_FileMultipleLinesOnlyTrimsLast(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, testSaltFile)
	if err := os.WriteFile(p, []byte("salt\nmore\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadSalt("file:" + p)
	if err != nil {
		t.Fatalf("LoadSalt: %v", err)
	}
	if string(got) != "salt\nmore" {
		t.Fatalf("LoadSalt: got %q, want %q", string(got), "salt\nmore")
	}
}

func TestLoadSalt_FileRelative(t *testing.T) {
	_, err := LoadSalt("file:relative/path")
	if !errors.Is(err, ErrSaltNotAbsolute) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltNotAbsolute", err)
	}
}

func TestLoadSalt_FileTraversal(t *testing.T) {
	_, err := LoadSalt("file:/path/with/../../escape")
	if !errors.Is(err, ErrSaltNotAbsolute) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltNotAbsolute (canonical form rejection)", err)
	}
}

func TestLoadSalt_FileMissing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "does-not-exist")
	_, err := LoadSalt("file:" + p)
	if !errors.Is(err, ErrSaltMissing) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltMissing", err)
	}
}

func TestLoadSalt_FileStatNonENOENT(t *testing.T) {
	// Routing through a regular file (/etc/passwd is universally present
	// and a regular file) returns ENOTDIR rather than ErrNotExist, exercising
	// the generic stat-error branch.
	_, err := LoadSalt("file:/etc/passwd/notreal")
	if err == nil {
		t.Fatal("expected stat error for ENOTDIR-bearing path")
	}
	if errors.Is(err, ErrSaltMissing) {
		t.Errorf("ENOTDIR misclassified as ErrSaltMissing: %v", err)
	}
}

// Deliberately-permissive modes used to exercise the rejection branch.
// Typed os.FileMode constants keep gosec G302 quiet — these are test
// fixtures, never production write modes.
const (
	looseModeWorld os.FileMode = 0o644
	looseModeOther os.FileMode = 0o604
)

func TestLoadSalt_FileMode0o644(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, testSaltFile)
	if err := os.WriteFile(p, []byte(testSaltLiteral), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(p, looseModeWorld); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := LoadSalt("file:" + p)
	if !errors.Is(err, ErrSaltMode) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltMode", err)
	}
}

func TestLoadSalt_FileMode0o604(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, testSaltFile)
	if err := os.WriteFile(p, []byte(testSaltLiteral), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(p, looseModeOther); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := LoadSalt("file:" + p)
	if !errors.Is(err, ErrSaltMode) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltMode", err)
	}
}

func TestLoadSalt_EmptySource(t *testing.T) {
	_, err := LoadSalt("")
	if !errors.Is(err, ErrSaltUnset) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltUnset", err)
	}
}

func TestLoadSalt_LiteralValue(t *testing.T) {
	got, err := LoadSalt("literal-bytes")
	if err != nil {
		t.Fatalf("LoadSalt: %v", err)
	}
	if string(got) != "literal-bytes" {
		t.Fatalf("LoadSalt: got %q, want %q", string(got), "literal-bytes")
	}
}

func TestLoadSalt_FileEmptyAfterTrim(t *testing.T) {
	// File with only a newline becomes empty after trim → fail closed.
	dir := t.TempDir()
	p := filepath.Join(dir, testSaltFile)
	if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadSalt("file:" + p)
	if !errors.Is(err, ErrSaltUnset) {
		t.Fatalf("LoadSalt: got %v, want ErrSaltUnset for empty-after-trim", err)
	}
}

func TestLoadSalt_FileIsDir(t *testing.T) {
	// Pointing at a directory must reject (regular-file check).
	dir := t.TempDir()
	_, err := LoadSalt("file:" + dir)
	if err == nil {
		t.Fatalf("LoadSalt: want error for directory path")
	}
	// Not one of the named sentinels (caller just sees "not a regular file"),
	// but it MUST NOT be Missing/Mode/NotAbsolute/Unset because the path
	// exists, is canonical, and has 0o700 dir perms.
	if errors.Is(err, ErrSaltMissing) || errors.Is(err, ErrSaltUnset) ||
		errors.Is(err, ErrSaltNotAbsolute) {
		t.Fatalf("LoadSalt: got mismatched sentinel %v", err)
	}
}

func TestLoadSalt_FileOpenFails(t *testing.T) {
	// Lstat passes (regular file, owner-only mode), but OpenFile fails
	// because the file's permission bits are 0 (owner can't read either).
	// Exercises the OpenFile-error fallback after the Lstat checks pass.
	dir := t.TempDir()
	p := filepath.Join(dir, testSaltFile)
	if err := os.WriteFile(p, []byte(testSaltLiteral), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(p, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	// Privileged runners (root in CI containers, some BSD configs) can
	// still read mode-0 files. Skip rather than flap: this case exercises
	// the post-Lstat OpenFile error path, and if the runner can't trigger
	// that path the test has nothing to assert.
	if f, openErr := os.Open(filepath.Clean(p)); openErr == nil {
		_ = f.Close()
		t.Skip("runner can still open mode-0 files; skipping permission-dependent case")
	}
	_, err := LoadSalt("file:" + p)
	if err == nil {
		t.Fatalf("LoadSalt: want error for unreadable file")
	}
	// OpenFile returns EACCES wrapped in os.PathError; the resolver wraps
	// it again. We don't pin a sentinel — just confirm it's neither
	// Missing nor Mode (those are the named branches we route to).
	if errors.Is(err, ErrSaltMissing) || errors.Is(err, ErrSaltMode) ||
		errors.Is(err, ErrSaltUnset) || errors.Is(err, ErrSaltNotAbsolute) {
		t.Fatalf("LoadSalt: got mismatched sentinel %v", err)
	}
}

func TestLoadSalt_FileIsSymlink(t *testing.T) {
	// Symlinks must be rejected at the directory-entry level, regardless of
	// the target's permissions. This closes the TOCTOU window where a path
	// the operator configured as a regular file gets swapped for a symlink
	// to a different file with looser permissions.
	dir := t.TempDir()
	target := filepath.Join(dir, "real-"+testSaltFile)
	if err := os.WriteFile(target, []byte(testSaltLiteral), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link-"+testSaltFile)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := LoadSalt("file:" + link)
	if err == nil {
		t.Fatalf("LoadSalt: want error for symlink path")
	}
	if !errors.Is(err, ErrSaltMode) {
		t.Fatalf("LoadSalt: want ErrSaltMode, got %v", err)
	}
}
