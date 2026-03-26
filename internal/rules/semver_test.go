// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSemver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		input           string
		wantMajor       int
		wantMinor       int
		wantPatch       int
		wantErr         bool
		wantErrContains string
	}{
		{"basic version", "1.3.0", 1, 3, 0, false, ""},
		{"large numbers", "10.20.300", 10, 20, 300, false, ""},
		{"zero version", "0.0.0", 0, 0, 0, false, ""},
		{"pre-release stripped", "1.3.0-rc1", 1, 3, 0, false, ""},
		{"pre-release with dots", "2.0.0-beta.1", 2, 0, 0, false, ""},
		{"too few segments", "1.3", 0, 0, 0, true, "expected 3 segments"},
		{"too many segments", "1.3.0.1", 0, 0, 0, true, "expected 3 segments"},
		{"single number", "1", 0, 0, 0, true, "expected 3 segments"},
		{"empty string", "", 0, 0, 0, true, "expected 3 segments"},
		{"non-numeric major", "abc.1.0", 0, 0, 0, true, "invalid major"},
		{"non-numeric minor", "1.abc.0", 0, 0, 0, true, "invalid minor"},
		{"non-numeric patch", "1.0.abc", 0, 0, 0, true, "invalid patch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			major, minor, patch, err := parseSemver(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSemver(%q) expected error, got nil", tt.input)
				}
				if tt.wantErrContains != "" {
					if got := err.Error(); !contains(got, tt.wantErrContains) {
						t.Errorf("error %q should contain %q", got, tt.wantErrContains)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSemver(%q) unexpected error: %v", tt.input, err)
			}
			if major != tt.wantMajor || minor != tt.wantMinor || patch != tt.wantPatch {
				t.Errorf("parseSemver(%q) = (%d, %d, %d), want (%d, %d, %d)",
					tt.input, major, minor, patch, tt.wantMajor, tt.wantMinor, tt.wantPatch)
			}
		})
	}
}

func TestAtomicWriteFile_Success(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	data := []byte("hello world")

	if err := atomicWriteFile(path, data); err != nil {
		t.Fatalf("atomicWriteFile() error: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want %o", perm, 0o600)
	}
}

func TestAtomicWriteFile_NonExistentDir(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "no-such-dir", "testfile")
	err := atomicWriteFile(path, []byte("data"))
	if err == nil {
		t.Fatal("expected error for non-existent directory, got nil")
	}
	if !contains(err.Error(), "creating temp file") {
		t.Errorf("error %q should mention 'creating temp file'", err.Error())
	}
}

func TestAtomicWriteFile_ReadOnlyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("Mkdir() error: %v", err)
	}
	t.Cleanup(func() {
		// Restore write permission so t.TempDir cleanup can remove the directory.
		_ = os.Chmod(roDir, os.FileMode(0o500|0o200)) //nolint:gosec // test cleanup needs write permission
	})

	path := filepath.Join(roDir, "testfile")
	err := atomicWriteFile(path, []byte("data"))
	if err == nil {
		t.Fatal("expected error for read-only directory, got nil")
	}
}

func TestAtomicWriteFile_Overwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")

	// Write initial content.
	if err := atomicWriteFile(path, []byte("first")); err != nil {
		t.Fatalf("first write error: %v", err)
	}

	// Overwrite with new content.
	if err := atomicWriteFile(path, []byte("second")); err != nil {
		t.Fatalf("second write error: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("got %q, want %q", got, "second")
	}
}

// contains is a test helper to check substring presence.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
