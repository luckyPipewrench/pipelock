// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// A shell whose working directory was reached through a symlink reports the
// logical $PWD, but the kernel resolves a relative root from the physical
// directory, so nothing the operator typed is redirected and the root is
// accepted. A symlink inside the relative path itself is still refused.
func TestRefuseSymlinkInWalkedRootPathLogicalWorkingDir(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realEv := filepath.Join(base, "real", "ev")
	if err := os.MkdirAll(realEv, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realEv, "evidence-proxy-0.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cwdLink := filepath.Join(base, "cwdlink")
	if err := os.Symlink(filepath.Join(base, "real"), cwdLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(realEv, filepath.Join(base, "real", "evlink")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwdLink)
	t.Setenv("PWD", cwdLink)
	if wd, err := os.Getwd(); err != nil || wd != cwdLink {
		t.Fatalf("precondition: os.Getwd() = %q, %v; want the logical %q", wd, err, cwdLink)
	}
	if err := refuseSymlinkInWalkedRootPath("ev"); err != nil {
		t.Fatalf("relative root under a logical working directory refused: %v", err)
	}
	location, err := ResolveEvidenceLocation("ev", "")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation(ev) = %v", err)
	}
	if location.Dir != realEv {
		t.Fatalf("location dir = %q, want physical %q", location.Dir, realEv)
	}
	if err := refuseSymlinkInWalkedRootPath("evlink"); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("relative symlinked root = %v, want refused", err)
	}
	if _, err := DiscoverEvidenceLocations("evlink"); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("DiscoverEvidenceLocations(evlink) = %v, want refused", err)
	}
}

// The operating system climbs out of directories only: "file/../ev" fails
// with ENOTDIR, so the walk must fail rather than verify the lexical ev.
func TestRefuseSymlinkInWalkedRootPathFileBeforeDotDot(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "real", "ev"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "real", "afile"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	for name, root := range map[string]string{
		"absolute": base + sep + "real" + sep + "afile" + sep + ".." + sep + "ev",
		"relative": "real" + sep + "afile" + sep + ".." + sep + "ev",
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(base)
			if err := refuseSymlinkInWalkedRootPath(filepath.Join(base, "real", "ev")); err != nil {
				t.Fatalf("positive control refused: %v", err)
			}
			for _, err := range []error{refuseSymlinkInWalkedRootPath(root), func() error {
				_, err := DiscoverEvidenceLocations(root)
				return err
			}()} {
				if err == nil || !strings.Contains(err.Error(), "is not a directory") {
					t.Fatalf("%q = %v, want not-a-directory failure", root, err)
				}
				if errors.Is(err, ErrEvidenceRefused) {
					t.Fatalf("%q = %v, want an open failure, not an evidence refusal", root, err)
				}
			}
		})
	}
}
