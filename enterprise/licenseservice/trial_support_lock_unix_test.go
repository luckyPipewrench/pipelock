//go:build enterprise && unix

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAcquireTrialSupportLockSecuresAndRejectsInvalidFiles(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "trial-support.lock")
		fd, err := unix.Open(path, unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatalf("create permissive lock file: %v", err)
		}
		if err := unix.Fchmod(fd, 0o666); err != nil {
			_ = unix.Close(fd)
			t.Fatalf("make lock file permissive: %v", err)
		}
		if err := unix.Close(fd); err != nil {
			t.Fatalf("close permissive lock file: %v", err)
		}
		release, err := acquireTrialSupportLock(context.Background(), path)
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
		if _, err := acquireTrialSupportLock(context.Background(), path); err == nil || !strings.Contains(err.Error(), "open trial support lock") {
			t.Fatalf("missing-parent error = %v", err)
		}
	})

	t.Run("named pipe", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "trial-support.fifo")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("create named pipe: %v", err)
		}
		if _, err := acquireTrialSupportLock(context.Background(), path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("named-pipe error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.lock")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatalf("create symlink target: %v", err)
		}
		path := filepath.Join(dir, "trial-support.lock")
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("create lock symlink: %v", err)
		}
		if _, err := acquireTrialSupportLock(context.Background(), path); err == nil || !strings.Contains(err.Error(), "open trial support lock") {
			t.Fatalf("symlink error = %v", err)
		}
	})
}
