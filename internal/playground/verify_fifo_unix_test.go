// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package playground

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadRunArtifactRejectsFIFOSwappedAfterLstat(t *testing.T) {
	dir := t.TempDir()
	name := "artifact.json"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	remaining := int64(32)
	_, err = readRunArtifactWithOpen(root, &remaining, name, func(root *os.Root, name string) (*os.File, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		return openRunArtifact(root, name)
	})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO error = %v, want type refusal", err)
	}
	if remaining != 32 {
		t.Fatalf("remaining = %d, want 32", remaining)
	}
}
