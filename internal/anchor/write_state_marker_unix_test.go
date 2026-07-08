// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package anchor

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWriteStateMarkerRejectsTempFileWriteFailure(t *testing.T) {
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	t.Cleanup(func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
		signal.Reset(syscall.SIGXFSZ)
	})
	limited := old
	limited.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatalf("Setrlimit: %v", err)
	}

	dir := t.TempDir()
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "write anchor-state temp file") {
		t.Fatalf("WriteStateMarker err = %v, want temp write failure", err)
	}
	matches, globErr := filepath.Glob(filepath.Join(dir, ".anchor-state-*.tmp"))
	if globErr != nil {
		t.Fatalf("Glob temp markers: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary marker files remained after write failure: %v", matches)
	}
}

func TestWriteStateMarkerRejectsUnwritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatalf("Chmod unwritable dir: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(dir, 0o700)
	})
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "create anchor-state temp file") {
		t.Fatalf("WriteStateMarker err = %v, want create temp file failure", err)
	}
}
