// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

func TestReadRejectsNonPositiveMaxBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		max  int64
	}{
		{name: "zero", max: 0},
		{name: "negative", max: -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(path, Options{MaxBytes: tt.max, DisallowedPerms: 0o037})
			if err == nil || !strings.Contains(err.Error(), "max bytes must be positive") {
				t.Fatalf("MaxBytes=%d error = %v, want positive-max rejection", tt.max, err)
			}
		})
	}
}

func TestReadMissingFile(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "missing"), Options{MaxBytes: 16, DisallowedPerms: 0o037})
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("error = %v, want missing-file rejection", err)
	}
}

func TestReadBrokenSymlink(t *testing.T) {
	link := filepath.Join(t.TempDir(), "token")
	if err := os.Symlink("no-such-target", link); err != nil {
		t.Fatal(err)
	}
	_, err := Read(link, Options{MaxBytes: 16, DisallowedPerms: 0o037})
	if err == nil || !strings.Contains(err.Error(), "resolve symlink") {
		t.Fatalf("error = %v, want broken-symlink rejection", err)
	}
}

func TestReadSymlinkToDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token")
	if err := os.Symlink("sub", link); err != nil {
		t.Fatal(err)
	}
	_, err := Read(link, Options{MaxBytes: 16, DisallowedPerms: 0o037})
	if err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("error = %v, want regular-file rejection", err)
	}
}

func TestReadOpenPermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix mode 000")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can open mode 000 files")
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	_, err := Read(path, Options{MaxBytes: 16, DisallowedPerms: 0o037})
	if err == nil {
		t.Fatal("expected open failure for mode 000")
	}
	if strings.Contains(err.Error(), "permissions") || strings.Contains(err.Error(), "max bytes") {
		t.Fatalf("error = %v, want open failure not policy rejection", err)
	}
}

// TestOpenRegularNonblockingExported covers the exported wrapper. It exists so
// callers outside this package reuse the platform matrix rather than growing a
// second one, so the export itself is the contract worth pinning: it opens a
// regular file, and it does not follow a final symlink.
func TestOpenRegularNonblockingExported(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	f, err := OpenRegularNonblocking(target)
	if errors.Is(err, ErrUnsupportedSecureOpen) {
		t.Skip("platform cannot provide a nonblocking, no-follow open")
	}
	if err != nil {
		t.Fatalf("OpenRegularNonblocking: %v", err)
	}
	got, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("content = %q, want payload", got)
	}

	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	linked, err := OpenRegularNonblocking(link)
	if err == nil {
		_ = linked.Close()
		t.Fatal("OpenRegularNonblocking followed a symlink, want the no-follow open to refuse it")
	}
}
