// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A file created and then failed mid-write is the case that separates "created"
// from "written". It cannot be reached by passing a bad path, because an
// exclusive create either succeeds or fails outright, so the write is forced to
// fail with a file-size limit instead.
//
// SIGXFSZ has to be ignored first: its default action terminates the process,
// and only once it is ignored does exceeding the limit surface as an EFBIG
// error from write, which is the shape a real disk-full failure takes.
func withTinyFileSizeLimit(t *testing.T, limit uint64) {
	t.Helper()

	signal.Ignore(syscall.SIGXFSZ)
	var saved syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &saved); err != nil {
		t.Skipf("cannot read RLIMIT_FSIZE: %v", err)
	}
	tiny := syscall.Rlimit{Cur: limit, Max: saved.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &tiny); err != nil {
		t.Skipf("cannot lower RLIMIT_FSIZE: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &saved)
		signal.Reset(syscall.SIGXFSZ)
	})
}

// The regression: writeNewArchiveFile reported creation only when the write
// succeeded, so a file it created and then failed to write was never recorded.
// Rollback left that file on disk, and its presence then prevented the kit
// directory from being removed, leaving exactly the half-published artifact set
// the all-or-nothing publish exists to prevent.
func TestPublishArchiveArtifacts_RollsBackAFileCreatedThenFailedMidWrite(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "replay-bundle.tar.gz")
	kitDir := filepath.Join(dir, "kits")
	f := &archiveReplayFlags{output: bundlePath, kitOutputDir: kitDir}

	withTinyFileSizeLimit(t, 1)

	// Larger than the limit, so the exclusive create succeeds and the write then
	// fails.
	bundle := []byte("this payload exceeds the file size limit")
	kits := []archiveKit{{name: "kit.zip", data: []byte("kit")}}

	err := publishArchiveArtifacts(f, bundle, kits)
	if err == nil {
		t.Fatal("a write that exceeded the file size limit was reported as success")
	}
	if !strings.Contains(err.Error(), "write output") && !strings.Contains(err.Error(), "close output") {
		t.Fatalf("error = %v, want a write or close failure", err)
	}
	if _, statErr := os.Stat(bundlePath); !os.IsNotExist(statErr) {
		t.Fatal("a file created and then failed mid-write survived rollback")
	}
	if _, statErr := os.Stat(kitDir); !os.IsNotExist(statErr) {
		t.Fatal("the kit directory survived rollback")
	}
}
