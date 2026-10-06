// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPathEvalAndExistsUseTheFilesystem(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "workspace")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "note")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := filesystemProfileInput{}
	resolved, isDir, err := in.eval(dir)
	if err != nil || !isDir || resolved != dir {
		t.Fatalf("dir eval = %q %v %v", resolved, isDir, err)
	}
	if _, _, err := in.eval(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing path evaluated")
	}

	if os.Geteuid() == 0 {
		// Root bypasses directory search permission, so the stat succeeds.
		return
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	ok, statErr := in.exists(file)
	if ok || statErr == nil {
		t.Fatalf("unsearchable exists = %v %v", ok, statErr)
	}
}
