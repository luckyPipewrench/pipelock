// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRemoveQuietOnlyIgnoresMissing(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{name: "existing file removed", setup: func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "sig")
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{name: "missing path is not an error", setup: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") }},
		{name: "non-empty directory surfaces error", setup: func(t *testing.T) string {
			d := filepath.Join(t.TempDir(), "dir")
			if err := os.MkdirAll(filepath.Join(d, "child"), 0o750); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.setup(t)
			err := removeQuiet(p)
			if tt.wantErr {
				if err == nil || errors.Is(err, os.ErrNotExist) {
					t.Fatalf("removeQuiet error = %v, want a non-ErrNotExist failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("removeQuiet: %v", err)
			}
			if _, statErr := os.Lstat(p); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("path still present after removeQuiet: %v", statErr)
			}
		})
	}
}

func TestRollbackFailsClosedWithBackupIntact(t *testing.T) {
	backupBytes := []byte("previous-binary")
	tests := []struct {
		name  string
		setup func(t *testing.T) (target string)
		want  string // empty means success expected
		is    func(error) bool
	}{
		{name: "backup restored over target", setup: func(t *testing.T) string {
			dir := t.TempDir()
			target := filepath.Join(dir, "pipelock")
			if err := os.WriteFile(target, []byte("current"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target+backupSuffix, backupBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			return target
		}},
		{name: "target cannot be replaced", setup: func(t *testing.T) string {
			dir := t.TempDir()
			target := filepath.Join(dir, "pipelock")
			if err := os.MkdirAll(filepath.Join(target, "occupied"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target+backupSuffix, backupBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			return target
		}, want: "restoring backup", is: func(err error) bool {
			// Windows refuses removal before Rename; Unix fails replacement.
			if runtime.GOOS == "windows" {
				var pe *os.PathError
				return errors.As(err, &pe)
			}
			var le *os.LinkError
			return errors.As(err, &le)
		}},
		{name: "target directory not writable", setup: func(t *testing.T) string {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("directory write permission is not enforced here")
			}
			dir := filepath.Join(t.TempDir(), "ro")
			if err := os.Mkdir(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "pipelock")
			if err := os.WriteFile(target+backupSuffix, backupBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // test makes the dir read-only on purpose
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore so TempDir cleanup can remove it
			return target
		}, want: "creating temp file", is: func(err error) bool { return errors.Is(err, fs.ErrPermission) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.setup(t)
			backupPath, err := rollback(target)
			if backupPath != target+backupSuffix {
				t.Fatalf("backup path = %q, want %q", backupPath, target+backupSuffix)
			}
			if tt.want == "" {
				if err != nil {
					t.Fatalf("rollback: %v", err)
				}
				got, readErr := os.ReadFile(filepath.Clean(target))
				if readErr != nil || string(got) != string(backupBytes) {
					t.Fatalf("target after rollback = %q (%v), want backup bytes", got, readErr)
				}
				kept, keptErr := os.ReadFile(filepath.Clean(backupPath))
				if keptErr != nil || string(kept) != string(backupBytes) {
					t.Fatalf("backup after successful rollback = %q (%v), want it kept as the recovery path", kept, keptErr)
				}
				assertDirEntries(t, filepath.Dir(target), "pipelock", "pipelock.bak")
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("rollback error = %v, want %q", err, tt.want)
			}
			if got, readErr := os.ReadFile(filepath.Clean(backupPath)); readErr != nil || string(got) != string(backupBytes) {
				t.Fatalf("backup not intact after failed rollback: %q (%v)", got, readErr)
			}
			if !tt.is(err) {
				t.Fatalf("rollback error %v does not carry the expected cause", err)
			}
			want := []string{"pipelock.bak"}
			if tt.want == "restoring backup" {
				want = []string{"pipelock", "pipelock.bak"}
			}
			assertDirEntries(t, filepath.Dir(target), want...)
		})
	}
}

func assertDirEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("entries in %s = %v, want exactly %v", dir, names, want)
	}
}
