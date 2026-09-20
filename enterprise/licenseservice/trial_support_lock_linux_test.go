//go:build enterprise && linux

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAcquireTrialSupportLockSerializesProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trial-support.lock")
	release, err := acquireTrialSupportLock(context.Background(), path)
	if err != nil {
		t.Fatalf("acquire parent lock: %v", err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			release()
		}
	})
	if got := runTrialSupportLockHelper(t, path); got != "blocked" {
		t.Fatalf("helper state with parent lock held = %q, want blocked", got)
	}
	release()
	released = true
	if got := runTrialSupportLockHelper(t, path); got != "acquired" {
		t.Fatalf("helper state after parent release = %q, want acquired", got)
	}
}

func runTrialSupportLockHelper(t *testing.T, path string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "-test.run=^TestTrialSupportLockHelperProcess$")
	cmd.Env = append(os.Environ(),
		"PIPELOCK_TRIAL_LOCK_HELPER=1",
		"PIPELOCK_TRIAL_LOCK_PATH="+path,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run helper process: %v: %s", err, out)
	}
	return strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
}

func TestTrialSupportLockHelperProcess(t *testing.T) {
	if os.Getenv("PIPELOCK_TRIAL_LOCK_HELPER") != "1" {
		return
	}
	fd, err := unix.Open(os.Getenv("PIPELOCK_TRIAL_LOCK_PATH"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatalf("open helper lock: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) {
		_, _ = os.Stdout.WriteString("blocked\n")
		return
	} else if err != nil {
		t.Fatalf("acquire helper lock: %v", err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	_, _ = os.Stdout.WriteString("acquired\n")
}
