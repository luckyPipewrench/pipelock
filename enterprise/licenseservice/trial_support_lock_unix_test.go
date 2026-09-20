//go:build enterprise && unix

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAcquireTrialSupportLockSecuresAndRejectsInvalidFiles(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "trial-support.lock")
		if err := os.WriteFile(path, nil, 0o666); err != nil { //nolint:gosec // intentionally permissive fixture; the lock must tighten it
			t.Fatalf("create permissive lock file: %v", err)
		}
		release, err := acquireTrialSupportLock(path)
		if err != nil {
			t.Fatalf("acquire lock: %v", err)
		}
		release()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat lock: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("lock permissions = %o, want 600", got)
		}
	})

	t.Run("missing parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "trial-support.lock")
		if _, err := acquireTrialSupportLock(path); err == nil || !strings.Contains(err.Error(), "open trial support lock") {
			t.Fatalf("missing-parent error = %v", err)
		}
	})

	t.Run("named pipe", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "trial-support.fifo")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("create named pipe: %v", err)
		}
		if _, err := acquireTrialSupportLock(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("named-pipe error = %v", err)
		}
	})
}
