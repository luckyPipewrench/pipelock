// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRefuseSymlinkInWalkedRootPath(t *testing.T) {
	base := t.TempDir()
	realEv := filepath.Join(base, "real", "ev")
	other := filepath.Join(base, "other", "sub")
	for _, dir := range []string{realEv, other} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(realEv, filepath.Join(base, "evlink")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(other, filepath.Join(base, "real", "link")); err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	for _, tc := range []struct {
		name    string
		root    string
		refused bool
	}{
		{name: "plain directory", root: realEv},
		{name: "dot-dot through real directories", root: base + sep + "real" + sep + "ev" + sep + ".." + sep + "ev"},
		{name: "symlinked root", root: filepath.Join(base, "evlink"), refused: true},
		// Lexically this is real/ev; the open follows link to other/sub and
		// then climbs to other/ev.
		{name: "symlink hidden by dot-dot", root: base + sep + "real" + sep + "link" + sep + ".." + sep + "ev", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseSymlinkInWalkedRootPath(tc.root)
			if tc.refused != errors.Is(err, ErrEvidenceRefused) {
				t.Fatalf("refuseSymlinkInWalkedRootPath(%q) = %v, want refused=%t", tc.root, err, tc.refused)
			}
			if !tc.refused && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			_, discoverErr := DiscoverEvidenceLocations(tc.root)
			if tc.refused != errors.Is(discoverErr, ErrEvidenceRefused) {
				t.Fatalf("DiscoverEvidenceLocations(%q) = %v, want refused=%t", tc.root, discoverErr, tc.refused)
			}
		})
	}
}

func TestRefuseSymlinkInWalkedRootPathRelative(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "real", "ev"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "other", "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "other", "sub"), filepath.Join(base, "real", "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Chdir(base)
	if err := refuseSymlinkInWalkedRootPath(filepath.Join("real", "ev")); err != nil {
		t.Fatalf("relative plain directory refused: %v", err)
	}
	sep := string(filepath.Separator)
	if err := refuseSymlinkInWalkedRootPath("real" + sep + "link" + sep + ".." + sep + "ev"); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("relative symlink hidden by dot-dot = %v, want refused", err)
	}
}
