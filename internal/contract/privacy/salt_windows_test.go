// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package privacy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsLoadSaltIgnoresMode proves the learn-salt loader's 0o077 mode gate
// is skipped on Windows (issue #695 class). On Unix a 0o644/0o604 salt file is
// rejected (see salt_test.go); on Windows the reported mode is meaningless, so
// the salt must load instead of failing closed on an unenforceable bit.
func TestWindowsLoadSaltIgnoresMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "salt.txt")
	if err := os.WriteFile(p, []byte("super-secret-salt"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = os.Chmod(p, 0o644)

	salt, err := LoadSalt("file:" + p)
	if err != nil {
		t.Fatalf("LoadSalt on Windows must succeed regardless of reported mode: %v", err)
	}
	if string(salt) != "super-secret-salt" {
		t.Fatalf("salt = %q, want %q", salt, "super-secret-salt")
	}
}
