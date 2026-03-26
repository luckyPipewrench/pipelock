// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// faultFile wraps a real *os.File but can inject errors at each step.
type faultFile struct {
	*os.File
	writeErr error
	chmodErr error
	closeErr error
}

func (f *faultFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.File.Write(p)
}

func (f *faultFile) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.File.Chmod(mode)
}

func (f *faultFile) Close() error {
	if f.closeErr != nil {
		// Still close the underlying file to avoid fd leaks.
		_ = f.File.Close()
		return f.closeErr
	}
	return f.File.Close()
}

// newFaultFile creates a real temp file wrapped in faultFile for testing.
func newFaultFile(t *testing.T, dir string) *faultFile {
	t.Helper()
	tmp, err := os.CreateTemp(dir, ".test-tmp-*")
	if err != nil {
		t.Fatalf("creating temp file for test: %v", err)
	}
	return &faultFile{File: tmp}
}

func TestWrite_Success(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	content := []byte("hello atomic world")

	if err := Write(target, content, 0o600); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("reading target: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q, want %q", got, content)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want %o", info.Mode().Perm(), 0o600)
	}
}

func TestWrite_Permissions(t *testing.T) {
	tests := []struct {
		name string
		perm os.FileMode
	}{
		{name: "restrictive", perm: 0o600},
		{name: "group_read", perm: 0o640},
		{name: "world_read", perm: 0o644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "perm-test.txt")

			if err := Write(target, []byte("data"), tt.perm); err != nil {
				t.Fatalf("Write() error: %v", err)
			}

			info, err := os.Stat(target)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if info.Mode().Perm() != tt.perm {
				t.Errorf("permissions = %o, want %o", info.Mode().Perm(), tt.perm)
			}
		})
	}
}

func TestFinalize_WriteError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	injected := errors.New("disk full")

	ff := newFaultFile(t, dir)
	ff.writeErr = injected
	tmpPath := ff.Name()

	err := finalize(ff, target, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "writing temp file") {
		t.Errorf("error = %q, want it to contain %q", err, "writing temp file")
	}
	if !errors.Is(err, injected) {
		t.Errorf("error should wrap injected error")
	}

	// Temp file must be cleaned up.
	if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file %s still exists after write error", tmpPath)
	}

	// Target must not exist.
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("target %s should not exist after write error", target)
	}
}

func TestFinalize_ChmodError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	injected := errors.New("chmod denied")

	ff := newFaultFile(t, dir)
	ff.chmodErr = injected
	tmpPath := ff.Name()

	err := finalize(ff, target, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "setting permissions") {
		t.Errorf("error = %q, want it to contain %q", err, "setting permissions")
	}
	if !errors.Is(err, injected) {
		t.Errorf("error should wrap injected error")
	}

	// Temp file must be cleaned up.
	if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file %s still exists after chmod error", tmpPath)
	}

	// Target must not exist.
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("target %s should not exist after chmod error", target)
	}
}

func TestFinalize_CloseError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	injected := errors.New("close failed")

	ff := newFaultFile(t, dir)
	ff.closeErr = injected
	tmpPath := ff.Name()

	err := finalize(ff, target, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "closing temp file") {
		t.Errorf("error = %q, want it to contain %q", err, "closing temp file")
	}
	if !errors.Is(err, injected) {
		t.Errorf("error should wrap injected error")
	}

	// Temp file must be cleaned up.
	if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file %s still exists after close error", tmpPath)
	}

	// Target must not exist.
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("target %s should not exist after close error", target)
	}
}

func TestWrite_RenameError(t *testing.T) {
	dir := t.TempDir()
	// Target is a directory, so Rename will fail.
	target := filepath.Join(dir, "subdir")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatalf("creating target dir: %v", err)
	}

	err := Write(target, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "renaming to target") {
		t.Errorf("error = %q, want it to contain %q", err, "renaming to target")
	}

	// Verify no leftover temp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestWrite_BadDirectory(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nonexistent", "file.txt")

	err := Write(target, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "creating temp file") {
		t.Errorf("error = %q, want it to contain %q", err, "creating temp file")
	}
}

func TestWrite_OverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing.txt")

	// Write initial content.
	if err := Write(target, []byte("old"), 0o600); err != nil {
		t.Fatalf("first Write() error: %v", err)
	}

	// Overwrite with new content.
	if err := Write(target, []byte("new"), 0o600); err != nil {
		t.Fatalf("second Write() error: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("reading target: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

func TestWrite_EmptyData(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.txt")

	if err := Write(target, []byte{}, 0o600); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("reading target: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("content length = %d, want 0", len(got))
	}
}
