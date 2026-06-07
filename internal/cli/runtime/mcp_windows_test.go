// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsReadHeaderFileIgnoresMode proves the --header-file 0o037 mode gate
// is skipped on Windows (issue #695 class). On Unix a 0o644 header file is
// rejected (it would reveal header values to other users); on Windows the
// reported mode is meaningless, so the file must read instead of failing closed.
func TestWindowsReadHeaderFileIgnoresMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headers.txt")
	if err := os.WriteFile(path, []byte("Authorization: Bearer windows-token\n"), 0o600); err != nil {
		t.Fatalf("write header file: %v", err)
	}
	_ = os.Chmod(path, 0o644)

	lines, err := readHeaderFile(path)
	if err != nil {
		t.Fatalf("readHeaderFile on Windows must succeed regardless of reported mode: %v", err)
	}
	if len(lines) != 1 || lines[0] != "Authorization: Bearer windows-token" {
		t.Fatalf("readHeaderFile lines = %v, want one Authorization header", lines)
	}
}
