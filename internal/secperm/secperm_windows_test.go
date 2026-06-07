// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package secperm

import (
	"io/fs"
	"testing"
)

func TestEnforcedOnWindows(t *testing.T) {
	if Enforced {
		t.Fatal("Enforced must be false on Windows: fs.FileMode reflects only the read-only attribute, not the NTFS ACL")
	}
}

// TestTooPermissiveWindows proves the Windows fail-open: no mode bits, including
// the 0666/0444/0777 values Go reports on Windows, may cause a rejection. A key
// at any reported mode must load (issue #695).
func TestTooPermissiveWindows(t *testing.T) {
	perms := []fs.FileMode{0o600, 0o640, 0o644, 0o660, 0o666, 0o444, 0o700, 0o777}
	masks := []fs.FileMode{0o037, 0o077, 0o137, 0o002, 0o177}
	for _, p := range perms {
		for _, m := range masks {
			if TooPermissive(p, m) {
				t.Fatalf("TooPermissive(%04o, %04o) = true on Windows; must always be false", p, m)
			}
		}
	}
}
