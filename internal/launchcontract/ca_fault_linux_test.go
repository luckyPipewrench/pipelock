// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBundleFileCreationFailure(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}
	dir := t.TempDir()
	cache := filepath.Join(dir, "pipelock", "exec-ca")
	if err := os.MkdirAll(cache, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cache, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cache, 0o750) })
	if _, err := WriteBundle(dir, []byte("CA")); err == nil || !strings.Contains(err.Error(), "create combined CA bundle") {
		t.Fatalf("err=%v", err)
	}
}

func TestBundleDiskWriteFailure(t *testing.T) {
	// RLIMIT_FSIZE is process-global; this test must run serially, and restores
	// the original limit before the parallel tests resume.
	dir := t.TempDir()
	data := []byte("positive control certificate bundle")
	if _, err := WriteBundle(dir, data); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	data = []byte("different bundle that must not be written")
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		t.Fatal(err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Errorf("restore file-size limit: %v", err)
		}
	}()
	limited := original
	limited.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBundle(dir, data); err == nil || !strings.Contains(err.Error(), "write combined CA bundle") {
		t.Fatalf("err=%v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "pipelock", "exec-ca"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("partial failed bundle retained: entries=%v err=%v", entries, err)
	}
}
