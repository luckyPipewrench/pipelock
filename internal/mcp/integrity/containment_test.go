// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

// binaryLocation distinguishes a resolved binary outside the agent's working
// directory from one whose location cannot be resolved.
func TestBinaryLocation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(workDir, "bin"), 0o750); err != nil {
		t.Fatalf("MkdirAll bin: %v", err)
	}
	// A directory whose name begins with two dots but is an ordinary child.
	// A prefix test against ".." misreads this as an escape.
	dotDot := filepath.Join(workDir, "..cache")
	if err := os.MkdirAll(dotDot, 0o750); err != nil {
		t.Fatalf("MkdirAll ..cache: %v", err)
	}
	// A sibling whose name shares workDir's prefix, which a naive string
	// prefix comparison on absolute paths would misread as inside.
	sibling := filepath.Join(root, "workother")
	if err := os.MkdirAll(sibling, 0o750); err != nil {
		t.Fatalf("MkdirAll sibling: %v", err)
	}

	write := func(t *testing.T, path string) string {
		t.Helper()
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		return path
	}

	tests := []struct {
		name string
		path string
		want BinaryLocation
	}{
		{"binary directly in the work dir", write(t, filepath.Join(workDir, "server")), BinaryLocationInside},
		{"binary nested in the work dir", write(t, filepath.Join(workDir, "bin", "server")), BinaryLocationInside},
		{"binary in a child whose name starts with two dots", write(t, filepath.Join(dotDot, "server")), BinaryLocationInside},
		{"the work dir itself", workDir, BinaryLocationInside},
		{"binary in a prefix-sharing sibling", write(t, filepath.Join(sibling, "server")), BinaryLocationOutside},
		{"binary outside the root", write(t, filepath.Join(root, "server")), BinaryLocationOutside},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := binaryLocation(tt.path, workDir)
			if err != nil {
				t.Fatalf("binaryLocation(%q, %q): %v", tt.path, workDir, err)
			}
			if got != tt.want {
				t.Fatalf("binaryLocation(%q, %q) = %q, want %q", tt.path, workDir, got, tt.want)
			}
		})
	}
}

// A symlink is resolved before the comparison, so where the link LIVES does
// not decide the answer; where it POINTS does. Both directions matter: a link
// inside the work dir pointing out is not the agent's own binary, and a link
// outside pointing in is.
func TestBinaryLocationResolvesSymlinksBeforeComparing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{workDir, outside} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("MkdirAll %s: %v", d, err)
		}
	}

	outsideBin := filepath.Join(outside, "server")
	insideBin := filepath.Join(workDir, "real-server")
	for _, f := range []string{outsideBin, insideBin} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", f, err)
		}
	}

	linkInsidePointingOut := filepath.Join(workDir, "link-out")
	if err := os.Symlink(outsideBin, linkInsidePointingOut); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	linkOutsidePointingIn := filepath.Join(outside, "link-in")
	if err := os.Symlink(insideBin, linkOutsidePointingIn); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}

	if got, err := binaryLocation(linkInsidePointingOut, workDir); err != nil || got != BinaryLocationOutside {
		t.Errorf("link inside pointing out = %q, %v; want outside, nil", got, err)
	}
	if got, err := binaryLocation(linkOutsidePointingIn, workDir); err != nil || got != BinaryLocationInside {
		t.Errorf("link outside pointing in = %q, %v; want inside, nil", got, err)
	}
}

func TestBinaryLocationUnresolvablePathsReportUnknown(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Control: a real binary inside resolves and reports inside, so a false
	// below is attributable to the unresolvable path rather than the fixture.
	insideBin := filepath.Join(workDir, "server")
	if err := os.WriteFile(insideBin, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got, err := binaryLocation(insideBin, workDir); err != nil || got != BinaryLocationInside {
		t.Fatalf("control binary = %q, %v; want inside, nil", got, err)
	}

	if got, err := binaryLocation(filepath.Join(workDir, "does-not-exist"), workDir); err == nil || got != BinaryLocationUnknown {
		t.Errorf("nonexistent binary = %q, %v; want unknown with reason", got, err)
	}
	if got, err := binaryLocation(insideBin, filepath.Join(root, "no-such-workdir")); err == nil || got != BinaryLocationUnknown {
		t.Errorf("nonexistent work dir = %q, %v; want unknown with reason", got, err)
	}

	dangling := filepath.Join(workDir, "dangling")
	if err := os.Symlink(filepath.Join(root, "missing-target"), dangling); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	if got, err := binaryLocation(dangling, workDir); err == nil || got != BinaryLocationUnknown {
		t.Errorf("dangling binary = %q, %v; want unknown with reason", got, err)
	}
}
