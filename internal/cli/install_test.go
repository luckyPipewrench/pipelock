// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstall_RejectsSymlinkDest ensures the install subcommand refuses
// to overwrite a destination path that is already a symlink. Without
// this guard, a pre-populated symlink in a shared volume could redirect
// the copied binary to any path the process can reach. The destination
// handling for install must treat symlinks as an error, not a hint to
// follow.
func TestInstall_RejectsSymlinkDest(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	target := filepath.Join(tmp, "elsewhere")
	link := filepath.Join(tmp, "dest")
	if err := os.WriteFile(target, []byte("real target"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	cmd := installCmd()
	cmd.SetArgs([]string{link})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("install over symlink: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("install over symlink: err = %v, want message mentioning symlink", err)
	}

	// The symlink's target must not have been overwritten.
	contents, readErr := os.ReadFile(filepath.Clean(target))
	if readErr != nil {
		t.Fatalf("read target after refused install: %v", readErr)
	}
	if string(contents) != "real target" {
		t.Errorf("symlink target was overwritten: got %q, want %q", contents, "real target")
	}
}

// TestInstall_RejectsNonRegularDest ensures the install subcommand
// refuses to overwrite a destination that is a directory or other
// non-regular file type. This is a defence-in-depth check: on a well-
// formed sidecar volume the destination either does not exist yet or
// is a regular file from a previous install, never a directory.
func TestInstall_RejectsNonRegularDest(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	destDir := filepath.Join(tmp, "dest-is-a-dir")
	if err := os.Mkdir(destDir, 0o750); err != nil {
		t.Fatalf("create dir: %v", err)
	}

	cmd := installCmd()
	cmd.SetArgs([]string{destDir})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("install over directory: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "non-regular") {
		t.Errorf("install over directory: err = %v, want message mentioning non-regular", err)
	}
}

// TestInstall_StatErrorSurfaces ensures the install subcommand returns
// the Lstat error when a destination path cannot be stat'd for reasons
// other than "does not exist" — for example, when the parent path is a
// regular file so resolving the destination hits ENOTDIR. Without this
// branch, install would silently swallow a meaningful filesystem
// signal.
func TestInstall_StatErrorSurfaces(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	parentAsFile := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(parentAsFile, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	// Destination sits under a path whose parent component is a regular
	// file — Lstat should return ENOTDIR rather than ENOENT.
	dest := filepath.Join(parentAsFile, "pipelock")

	cmd := installCmd()
	cmd.SetArgs([]string{dest})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("install under non-dir parent: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "stat destination") {
		t.Errorf("install under non-dir parent: err = %v, want stat destination message", err)
	}
}

// TestInstall_HappyPath exercises the full copy + atomic-rename flow:
// a fresh destination directory receives the running binary and ends
// up with the executable bit set. Also covers the ReadFile path and
// atomicfile.Write tempfile-rename semantics so any regression in
// either drops coverage loudly.
func TestInstall_HappyPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "nested", "pipelock")

	cmd := installCmd()
	cmd.SetArgs([]string{dest})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install happy path: %v", err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat destination: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("dest mode = %v, want regular file", info.Mode())
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("dest mode = %v, want executable bit set", info.Mode())
	}

	// Source is the test binary itself (os.Executable during tests). It
	// should be a non-empty file, so the copy should be non-empty too.
	if info.Size() == 0 {
		t.Error("dest size = 0, want non-empty copy")
	}

	// Re-running install over the now-existing regular file must
	// succeed (idempotent update flow — an operator upgrading a sidecar
	// expects to overwrite the prior binary without needing to rm it
	// first).
	cmd2 := installCmd()
	cmd2.SetArgs([]string{dest})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("install idempotent re-run: %v", err)
	}
}
