// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

// isInsideDir answers one containment question: is this resolved binary inside
// the agent's own working directory? Callers set VerifyResult.Suspicious from
// the answer, and false means "not suspicious", so every false is a warning
// the operator does not see. The direction matters more than usual here.
func TestIsInsideDir(t *testing.T) {
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
		want bool
	}{
		{"binary directly in the work dir", write(t, filepath.Join(workDir, "server")), true},
		{"binary nested in the work dir", write(t, filepath.Join(workDir, "bin", "server")), true},
		{"binary in a child whose name starts with two dots", write(t, filepath.Join(dotDot, "server")), true},
		{"the work dir itself", workDir, true},
		{"binary in a prefix-sharing sibling", write(t, filepath.Join(sibling, "server")), false},
		{"binary outside the root", write(t, filepath.Join(root, "server")), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInsideDir(tt.path, workDir); got != tt.want {
				t.Fatalf("isInsideDir(%q, %q) = %v, want %v", tt.path, workDir, got, tt.want)
			}
		})
	}
}

// A symlink is resolved before the comparison, so where the link LIVES does
// not decide the answer; where it POINTS does. Both directions matter: a link
// inside the work dir pointing out is not the agent's own binary, and a link
// outside pointing in is.
func TestIsInsideDirResolvesSymlinksBeforeComparing(t *testing.T) {
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

	if isInsideDir(linkInsidePointingOut, workDir) {
		t.Error("a link inside the work dir pointing outside was reported inside; the target decides, not the link")
	}
	if !isInsideDir(linkOutsidePointingIn, workDir) {
		t.Error("a link outside the work dir pointing inside was reported outside; the target decides, not the link")
	}
}

// Every error path returns false, which means "not suspicious". That is a
// deliberate direction on an advisory signal, and it is worth pinning so a
// later change does not start reporting unresolvable paths as suspicious (a
// warning an operator cannot act on) or, worse, as an error that breaks
// verification.
func TestIsInsideDirUnresolvablePathsReportNotInside(t *testing.T) {
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
	if !isInsideDir(insideBin, workDir) {
		t.Fatal("control failed: a real binary inside the work dir was reported outside")
	}

	if isInsideDir(filepath.Join(workDir, "does-not-exist"), workDir) {
		t.Error("a nonexistent path was reported inside")
	}
	if isInsideDir(insideBin, filepath.Join(root, "no-such-workdir")) {
		t.Error("a nonexistent work dir was reported as containing the binary")
	}

	dangling := filepath.Join(workDir, "dangling")
	if err := os.Symlink(filepath.Join(root, "missing-target"), dangling); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	if isInsideDir(dangling, workDir) {
		t.Error("a dangling symlink was reported inside")
	}
}
