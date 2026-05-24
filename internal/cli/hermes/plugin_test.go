// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDefaultPluginRoot(t *testing.T) {
	t.Parallel()

	got := ResolveDefaultPluginRoot("/home/agent")
	want := filepath.Join("/home/agent", DefaultPluginSubpath)
	if got != want {
		t.Fatalf("ResolveDefaultPluginRoot mismatch: got %q, want %q", got, want)
	}
}

func TestInstall_RejectsEmptyRoot(t *testing.T) {
	t.Parallel()

	if _, err := Install(PluginTarget{}); err == nil {
		t.Fatal("Install(empty) returned nil; expected validation error")
	}
}

func TestInstall_WritesEmbeddedTree(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	root := filepath.Join(tmp, "hermes-plugins", "pipelock")

	result, err := Install(PluginTarget{Root: root})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if result.FilesWritten == 0 {
		t.Fatal("Install reported zero files written")
	}
	if len(result.BackupsCreated) != 0 {
		t.Fatalf("Install on fresh directory should not rotate files; got %v", result.BackupsCreated)
	}

	for _, name := range []string{"__init__.py", "plugin.py", "README.md"} {
		path := filepath.Join(root, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s after install: %v", name, err)
		}
		if info.IsDir() {
			t.Fatalf("expected %s to be a file, got directory", name)
		}
		if mode := info.Mode().Perm(); mode != pluginFilePerm {
			t.Fatalf("%s perms = %v, want %v", name, mode, pluginFilePerm)
		}
		data, err := os.ReadFile(path) //nolint:gosec // test path is under t.TempDir()
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty after install", name)
		}
	}
}

func TestInstall_RotatesExistingFiles(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if _, err := Install(PluginTarget{Root: tmp}); err != nil {
		t.Fatalf("Install first pass: %v", err)
	}

	// Mutate a file so we can prove rotation preserves prior contents.
	pluginPath := filepath.Join(tmp, "plugin.py")
	const sentinel = "# hand-edited line that must end up in the .bak\n"
	if err := os.WriteFile(pluginPath, []byte(sentinel), pluginFilePerm); err != nil {
		t.Fatalf("seed mutated plugin: %v", err)
	}

	result, err := Install(PluginTarget{Root: tmp})
	if err != nil {
		t.Fatalf("Install second pass: %v", err)
	}
	if len(result.BackupsCreated) == 0 {
		t.Fatal("expected at least one backup on rerun, got none")
	}

	var pluginBackup string
	for _, b := range result.BackupsCreated {
		if strings.HasPrefix(filepath.Base(b), "plugin.py.bak.") {
			pluginBackup = b
			break
		}
	}
	if pluginBackup == "" {
		t.Fatalf("no plugin.py backup recorded in %v", result.BackupsCreated)
	}

	backupBytes, err := os.ReadFile(pluginBackup) //nolint:gosec // path is under t.TempDir() returned by Install
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backupBytes) != sentinel {
		t.Fatalf("backup contents mismatch: got %q, want %q", string(backupBytes), sentinel)
	}

	// And the fresh plugin.py must be the embedded version, not the sentinel.
	currentBytes, err := os.ReadFile(pluginPath) //nolint:gosec // path is under t.TempDir()
	if err != nil {
		t.Fatalf("read current plugin: %v", err)
	}
	if strings.Contains(string(currentBytes), sentinel) {
		t.Fatal("rerun left the hand-edited sentinel in plugin.py instead of restoring the embedded copy")
	}
	if !strings.Contains(string(currentBytes), "register") {
		t.Fatal("restored plugin.py does not contain the expected 'register' symbol from the embedded template")
	}
}

func TestInstall_RejectsDirectoryCollision(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	// Pre-create a directory at one of the destination file paths so the
	// rotation guard refuses to clobber a directory.
	if err := os.MkdirAll(filepath.Join(tmp, "plugin.py"), pluginDirPerm); err != nil {
		t.Fatalf("seed conflicting directory: %v", err)
	}

	_, err := Install(PluginTarget{Root: tmp})
	if err == nil {
		t.Fatal("Install over a directory-named-like-a-file did not fail")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Fatalf("error %q does not mention 'directory'", err.Error())
	}
}

func TestEnsureContained(t *testing.T) {
	t.Parallel()

	root := filepath.Join("/srv", "plugins", "pipelock")
	cases := []struct {
		name    string
		dest    string
		wantErr bool
	}{
		{"direct child", filepath.Join(root, "plugin.py"), false},
		{"nested child", filepath.Join(root, "sub", "x.py"), false},
		{"root itself", root, false},
		{"parent escape", filepath.Join(root, "..", "evil"), true},
		{"deep escape", filepath.Join(root, "..", "..", "etc", "passwd"), true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ensureContained(root, filepath.Clean(tc.dest))
			if (err != nil) != tc.wantErr {
				t.Fatalf("ensureContained(%q) err=%v, wantErr=%v", tc.dest, err, tc.wantErr)
			}
		})
	}
}

func TestRotateExisting_AbsentReturnsEmpty(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	backup, err := rotateExisting(filepath.Join(tmp, "nope"))
	if err != nil {
		t.Fatalf("rotateExisting on missing path: %v", err)
	}
	if backup != "" {
		t.Fatalf("rotateExisting on missing path returned %q, want \"\"", backup)
	}
}

func TestRotateExisting_RegularFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "file")
	if err := os.WriteFile(path, []byte("hi"), pluginFilePerm); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backup, err := rotateExisting(path)
	if err != nil {
		t.Fatalf("rotateExisting: %v", err)
	}
	if backup == "" {
		t.Fatal("rotateExisting on present file returned empty backup path")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("original path still exists after rotation: %v", err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("backup path missing: %v", err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "out")
	if err := writeFileAtomic(path, []byte("payload")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != pluginFilePerm {
		t.Fatalf("mode = %v, want %v", mode, pluginFilePerm)
	}
}

func TestWriteFileAtomic_OpenFailure(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root; cannot exercise permission-denied path")
	}

	tmp := t.TempDir()
	roDir := filepath.Join(tmp, "readonly")
	if err := os.MkdirAll(roDir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, pluginDirPerm) })

	err := writeFileAtomic(filepath.Join(roDir, "f"), []byte("x"))
	if err == nil {
		t.Fatal("writeFileAtomic into read-only dir returned nil err")
	}
	if !strings.Contains(err.Error(), "open") {
		t.Fatalf("error does not name open failure: %v", err)
	}
}

func TestWriteFileAtomic_RenameFailure(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "occupied")
	// Pre-create a directory at the destination so the rename (file ->
	// directory path) fails. The tmp sibling will succeed in being
	// written but rename(tmp, dest) errors EISDIR.
	if err := os.MkdirAll(dest, pluginDirPerm); err != nil {
		t.Fatalf("seed dir: %v", err)
	}

	err := writeFileAtomic(dest, []byte("x"))
	if err == nil {
		t.Fatal("writeFileAtomic over a directory returned nil err")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Fatalf("error does not name rename failure: %v", err)
	}
}

func TestRotateExisting_LstatPermissionDenied(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root; cannot exercise permission-denied path")
	}

	tmp := t.TempDir()
	parent := filepath.Join(tmp, "locked")
	if err := os.MkdirAll(parent, pluginDirPerm); err != nil {
		t.Fatalf("seed parent: %v", err)
	}
	// Drop search permission so Lstat on a child returns EACCES rather
	// than NotExist. The cleanup restores it so t.TempDir() can clean up.
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatalf("chmod 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, pluginDirPerm) })

	_, err := rotateExisting(filepath.Join(parent, "blocked"))
	if err == nil {
		t.Fatal("rotateExisting under unreadable parent returned nil err")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Fatalf("error does not name stat failure: %v", err)
	}
}

func TestInstall_MkdirAllFailure(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	// Create a regular file at a path we'll try to use as a parent dir.
	conflict := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(conflict, []byte("x"), pluginFilePerm); err != nil {
		t.Fatalf("seed conflict file: %v", err)
	}

	_, err := Install(PluginTarget{Root: filepath.Join(conflict, "child")})
	if err == nil {
		t.Fatal("Install under a regular file did not fail")
	}
	if !strings.Contains(err.Error(), "create") {
		t.Fatalf("error does not name MkdirAll failure: %v", err)
	}
}
