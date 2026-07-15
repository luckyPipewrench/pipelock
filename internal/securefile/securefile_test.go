// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecurityBoundary(t *testing.T) {
	write := func(dir, name, body string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	opts := Options{MaxBytes: 16, DisallowedPerms: 0o037}

	t.Run("managed symlink", func(t *testing.T) {
		dir := t.TempDir()
		version := filepath.Join(dir, "..2026_07_14")
		if err := os.Mkdir(version, 0o750); err != nil {
			t.Fatal(err)
		}
		write(version, "token", "secret", 0o440)
		link := filepath.Join(dir, "token")
		if err := os.Symlink(filepath.Join(filepath.Base(version), "token"), link); err != nil {
			t.Fatal(err)
		}
		if got, err := Read(link, opts); err != nil || string(got) != "secret" {
			t.Fatalf("read = %q, %v", got, err)
		}
	})
	t.Run("managed symlink rejected when requested", func(t *testing.T) {
		dir := t.TempDir()
		target := write(dir, "target", "secret", 0o600)
		link := filepath.Join(dir, "token")
		if err := os.Symlink(filepath.Base(target), link); err != nil {
			t.Fatal(err)
		}
		strict := opts
		strict.RejectSymlink = true
		if _, err := Read(link, strict); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
			t.Fatalf("error = %v, want symlink rejection", err)
		}
	})
	t.Run("escaping symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := write(t.TempDir(), "token", "secret", 0o600)
		link := filepath.Join(dir, "token")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(link, opts); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("error = %v, want escape rejection", err)
		}
	})
	t.Run("world readable", func(t *testing.T) {
		path := write(t.TempDir(), "token", "secret", 0o644)
		if _, err := Read(path, opts); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("error = %v, want permission rejection", err)
		}
	})
	t.Run("non regular", func(t *testing.T) {
		if _, err := Read(t.TempDir(), opts); err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("error = %v, want regular-file rejection", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := write(t.TempDir(), "token", strings.Repeat("x", 17), 0o600)
		if _, err := Read(path, opts); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error = %v, want size rejection", err)
		}
	})
}
