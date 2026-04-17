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
