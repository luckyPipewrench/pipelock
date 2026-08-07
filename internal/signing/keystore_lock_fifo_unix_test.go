// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package signing

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// syscall.Mkfifo does not exist on Windows, so this case lives behind a unix
// build tag. Left in the untagged fault file it made the whole package fail to
// compile for GOOS=windows, which this package supports: it ships a Windows
// locking implementation alongside the unix one.

func TestWithAgentLock_RejectsNonRegularLockFile(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock")
	// A FIFO opens successfully but is not a regular file. Locking it would
	// give no mutual exclusion, so generation must refuse rather than proceed
	// unserialized.
	if err := syscall.Mkfifo(lockPath, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this filesystem: %v", err)
	}

	called := false
	err := withAgentLock(lockPath, func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("withAgentLock accepted a non-regular lock file")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error = %q, want it to name the lock file type", err)
	}
	if called {
		t.Error("the critical section ran without a usable lock")
	}
}
