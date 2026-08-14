// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// faultFile wraps a real *os.File but can inject errors at each step.
type faultFile struct {
	*os.File
	writeErr error
	chmodErr error
	syncErr  error
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

func (f *faultFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
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
	// Windows reports a synthesized 0o666 mode for any user-readable+writable
	// file regardless of the mode passed to OpenFile. Skip the perm assertion
	// there; the content-correctness assertions above still cover the
	// cross-platform behavior of Write.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want %o", info.Mode().Perm(), 0o600)
	}
}

func TestWrite_ReplacingDestSymlinkLeavesTargetUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink replacement semantics differ on Windows")
	}
	dir := t.TempDir()
	protected := filepath.Join(dir, "signing.key")
	original := []byte("protected-key-bytes")
	if err := os.WriteFile(protected, original, 0o600); err != nil {
		t.Fatalf("WriteFile protected: %v", err)
	}
	dest := filepath.Join(dir, "report.json")
	if err := os.Symlink(protected, dest); err != nil {
		t.Fatalf("Symlink dest: %v", err)
	}
	if err := Write(dest, []byte("report-body"), 0o600); err != nil {
		t.Fatalf("Write dest symlink: %v", err)
	}
	got, err := os.ReadFile(filepath.Clean(protected))
	if err != nil {
		t.Fatalf("read protected: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("protected file changed to %q", got)
	}
	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatalf("Lstat dest: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("Write left dest as a symlink; rename should have replaced the directory entry")
	}
	written, err := os.ReadFile(filepath.Clean(dest))
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(written) != "report-body" {
		t.Fatalf("dest content = %q, want report-body", written)
	}
}

func TestWriteNewCreatesAndRefusesReplacement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ceremony.json")
	if err := WriteNew(target, []byte("first"), 0o600); err != nil {
		t.Fatalf("WriteNew first: %v", err)
	}
	assertNoAtomicTemps(t, dir)
	if err := WriteNew(target, []byte("second"), 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("WriteNew existing error = %v, want os.ErrExist", err)
	}
	assertNoAtomicTemps(t, dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile("ceremony.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "first" {
		t.Fatalf("existing target changed: %q", data)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
}

func TestFinalizePublish_PublishError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	injected := errors.New("link failed")
	ff := newFaultFile(t, dir)
	tmpPath := ff.Name()

	err := finalizePublish(
		ff,
		target,
		0o600,
		func(w io.Writer) error {
			_, writeErr := io.WriteString(w, "data")
			return writeErr
		},
		func(_, _ string) error { return injected },
		"publishing new file",
	)
	if !errors.Is(err, injected) || !strings.Contains(err.Error(), "publishing new file") {
		t.Fatalf("error = %v, want wrapped publish failure", err)
	}
	if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file %s still exists after publish error", tmpPath)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target %s should not exist after publish error", target)
	}
}

func assertNoAtomicTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("leaked temp file %q", entry.Name())
		}
	}
}

func TestWriteFuncStreamsAndPreservesTargetOnFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(target, []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("render failed")
	err := WriteFunc(target, 0o600, func(w io.Writer) error {
		if _, writeErr := io.WriteString(w, "partial\n"); writeErr != nil {
			return writeErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WriteFunc error = %v, want render failure", err)
	}
	data, readErr := os.ReadFile(target) // #nosec G304 -- target is inside t.TempDir.
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "previous\n" {
		t.Fatalf("failed callback replaced target with %q", data)
	}

	if err := WriteFunc(target, 0o600, func(w io.Writer) error {
		_, writeErr := io.WriteString(w, "complete\n")
		return writeErr
	}); err != nil {
		t.Fatalf("WriteFunc success: %v", err)
	}
	data, readErr = os.ReadFile(target) // #nosec G304 -- target is inside t.TempDir.
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "complete\n" {
		t.Fatalf("published content = %q", data)
	}
}

func TestWrite_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses NTFS ACLs not Unix mode bits; os.Stat reports a synthesized 0o666 regardless of the mode passed to Write")
	}
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

	err := finalize(ff, target, []byte("data"))
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

	err := finalize(ff, target, []byte("data"))
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

	err := finalize(ff, target, []byte("data"))
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

func TestFinalize_SyncError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	injected := errors.New("fsync failed")

	ff := newFaultFile(t, dir)
	ff.syncErr = injected
	tmpPath := ff.Name()

	err := finalize(ff, target, []byte("data"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "syncing temp file") {
		t.Errorf("error = %q, want it to contain %q", err, "syncing temp file")
	}
	if !errors.Is(err, injected) {
		t.Errorf("error should wrap injected error")
	}

	// Temp file must be cleaned up.
	if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file %s still exists after sync error", tmpPath)
	}

	// Target must not exist: a non-durable write must not become visible.
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("target %s should not exist after sync error", target)
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

func TestWriteNew_BadDirectory(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nonexistent", "file.txt")
	err := WriteNew(target, []byte("data"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "creating temp file") {
		t.Fatalf("WriteNew error = %v, want temp-file creation failure", err)
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

func TestSyncDir_MissingDirectoryIsBestEffort(t *testing.T) {
	syncDir(filepath.Join(t.TempDir(), "missing"))
}
