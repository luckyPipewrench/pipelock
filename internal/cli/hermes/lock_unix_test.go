// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package hermes

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A second holder must wait until the first releases the lock.
func TestWithHermesLockSerializes(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	held := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withHermesLock(cfg, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	secondRan := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- withHermesLock(cfg, func() error {
			close(secondRan)
			return nil
		})
	}()
	select {
	case <-secondRan:
		t.Fatal("second holder ran while the first held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-secondRan:
	case <-time.After(10 * time.Second):
		t.Fatal("second holder never acquired the lock after release")
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

// Locking creates nothing in the config directory, and a config whose
// directory path is a regular file is refused before fn runs.
func TestWithHermesLockLeavesNoFileAndRefusesNonDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := withHermesLock(cfg, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("lock left %d entries in the config directory", len(entries))
	}
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := withHermesLock(filepath.Join(blocker, "config.yaml"), func() error { ran = true; return nil }); err == nil || ran {
		t.Fatalf("non-directory accepted: err=%v ran=%v", err, ran)
	}
}
