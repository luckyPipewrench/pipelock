// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsBaselineNoSymlinkReadsRegularFileAndRejectsSymlink proves the
// Windows no-follow read path reads a normal regular file (the regression: this
// path previously failed every Windows read unconditionally, breaking baseline
// and integrity-state loading) and still rejects a final-component symlink.
func TestWindowsBaselineNoSymlinkReadsRegularFileAndRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "profile.json")
	want := []byte(`{"schema":1}`)
	if err := os.WriteFile(regular, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := readRegularFileNoSymlink(regular, "baseline profile", integrityStateMaxSize)
	if err != nil {
		t.Fatalf("readRegularFileNoSymlink(regular) error = %v, want success", err)
	}
	if string(got) != string(want) {
		t.Fatalf("readRegularFileNoSymlink(regular) = %q, want %q", got, want)
	}

	// Symlink creation needs SeCreateSymbolicLinkPrivilege (developer mode or
	// admin). Where the runner grants it, the read must reject a symlinked
	// final component; where it does not, skip only the symlink assertion.
	link := filepath.Join(dir, "profile-link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Skipf("symlink creation unsupported on this runner (%v); regular-file read verified", err)
	}
	if _, err := readRegularFileNoSymlink(link, "baseline profile", integrityStateMaxSize); err == nil {
		t.Fatal("readRegularFileNoSymlink(symlink) succeeded, want rejection")
	}

	// The read above rejects via the shared, cross-platform Lstat pre-check in
	// readRegularFileNoSymlinkInRootWithOpenHook, which runs before the
	// Windows-specific opener. Call the new opener directly so its own
	// symlink-rejection logic is exercised, not just the outer guard.
	if f, err := openRegularFileNoSymlinkBelowRoot(dir, "profile-link.json", link); err == nil {
		_ = f.Close()
		t.Fatal("openRegularFileNoSymlinkBelowRoot(symlink) succeeded, want rejection")
	}
}
