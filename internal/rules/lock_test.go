// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReadLockFile_RoundTrip(t *testing.T) {
	t.Parallel()

	lf := &LockFile{
		InstalledVersion:  "2026.03.1",
		InstalledAt:       "2026-03-15T10:30:00Z",
		Source:            "https://github.com/example/rules/releases/v2026.03.1",
		LastCheck:         "2026-03-15T12:00:00Z",
		BundleSHA256:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SignerFingerprint: "aabbccdd11223344",
		Unsigned:          false,
	}

	dir := t.TempDir()
	path := filepath.Join(dir, lockFilename)

	if err := WriteLockFile(path, lf); err != nil {
		t.Fatalf("WriteLockFile() error: %v", err)
	}

	got, err := ReadLockFile(path)
	if err != nil {
		t.Fatalf("ReadLockFile() error: %v", err)
	}

	if got.InstalledVersion != lf.InstalledVersion {
		t.Errorf("InstalledVersion = %q, want %q", got.InstalledVersion, lf.InstalledVersion)
	}
	if got.InstalledAt != lf.InstalledAt {
		t.Errorf("InstalledAt = %q, want %q", got.InstalledAt, lf.InstalledAt)
	}
	if got.Source != lf.Source {
		t.Errorf("Source = %q, want %q", got.Source, lf.Source)
	}
	if got.LastCheck != lf.LastCheck {
		t.Errorf("LastCheck = %q, want %q", got.LastCheck, lf.LastCheck)
	}
	if got.BundleSHA256 != lf.BundleSHA256 {
		t.Errorf("BundleSHA256 = %q, want %q", got.BundleSHA256, lf.BundleSHA256)
	}
	if got.SignerFingerprint != lf.SignerFingerprint {
		t.Errorf("SignerFingerprint = %q, want %q", got.SignerFingerprint, lf.SignerFingerprint)
	}
	if got.Unsigned != lf.Unsigned {
		t.Errorf("Unsigned = %v, want %v", got.Unsigned, lf.Unsigned)
	}
}

func TestWriteReadLockFile_RoundTripUnsigned(t *testing.T) {
	t.Parallel()

	lf := &LockFile{
		InstalledVersion: "2026.01.0",
		InstalledAt:      "2026-01-01T00:00:00Z",
		Source:           "local",
		BundleSHA256:     "abcdef1234567890",
		Unsigned:         true,
	}

	dir := t.TempDir()
	path := filepath.Join(dir, lockFilename)

	if err := WriteLockFile(path, lf); err != nil {
		t.Fatalf("WriteLockFile() error: %v", err)
	}

	got, err := ReadLockFile(path)
	if err != nil {
		t.Fatalf("ReadLockFile() error: %v", err)
	}

	if got.Unsigned != true {
		t.Errorf("Unsigned = %v, want true", got.Unsigned)
	}
	if got.SignerFingerprint != "" {
		t.Errorf("SignerFingerprint = %q, want empty", got.SignerFingerprint)
	}
}

func TestReadLockFile_MissingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nonexistent", lockFilename)
	_, err := ReadLockFile(path)
	if err == nil {
		t.Fatal("ReadLockFile() expected error for missing file, got nil")
	}
}

func TestWriteLockFile_Permissions(t *testing.T) {
	t.Parallel()

	lf := &LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:30:00Z",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, lockFilename)

	if err := WriteLockFile(path, lf); err != nil {
		t.Fatalf("WriteLockFile() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}

	// File permissions should be 0o600.
	const wantPerm os.FileMode = 0o600
	gotPerm := info.Mode().Perm()
	if gotPerm != wantPerm {
		t.Errorf("file permissions = %o, want %o", gotPerm, wantPerm)
	}
}

func TestWriteLockFile_NonExistentDirectory(t *testing.T) {
	t.Parallel()

	lf := &LockFile{
		InstalledVersion: "2026.03.1",
	}

	path := filepath.Join(t.TempDir(), "no-such-dir", "subdir", lockFilename)
	err := WriteLockFile(path, lf)
	if err == nil {
		t.Fatal("WriteLockFile() expected error for non-existent directory, got nil")
	}
}

func TestWriteLockFile_EmptyLockFile(t *testing.T) {
	t.Parallel()

	lf := &LockFile{}

	dir := t.TempDir()
	path := filepath.Join(dir, lockFilename)

	if err := WriteLockFile(path, lf); err != nil {
		t.Fatalf("WriteLockFile() error for empty LockFile: %v", err)
	}

	// Verify the file was written.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if info.Size() == 0 {
		t.Error("file should not be empty after writing empty LockFile (YAML has field keys)")
	}
}

func TestWriteLockFile_OverwriteExisting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, lockFilename)

	// Write first version.
	lf1 := &LockFile{
		InstalledVersion: "2026.01.0",
		InstalledAt:      "2026-01-01T00:00:00Z",
		Source:           "first",
	}
	if err := WriteLockFile(path, lf1); err != nil {
		t.Fatalf("WriteLockFile() first write error: %v", err)
	}

	// Overwrite with second version.
	lf2 := &LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:30:00Z",
		Source:           "second",
	}
	if err := WriteLockFile(path, lf2); err != nil {
		t.Fatalf("WriteLockFile() overwrite error: %v", err)
	}

	got, err := ReadLockFile(path)
	if err != nil {
		t.Fatalf("ReadLockFile() error: %v", err)
	}

	if got.InstalledVersion != lf2.InstalledVersion {
		t.Errorf("InstalledVersion = %q, want %q (overwrite failed)", got.InstalledVersion, lf2.InstalledVersion)
	}
	if got.Source != lf2.Source {
		t.Errorf("Source = %q, want %q (overwrite failed)", got.Source, lf2.Source)
	}
}
