// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package llmagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunCommandInvoke_KillsBackgroundedChildOnTimeout proves the process-group
// reaping: a run_command that backgrounds a long-lived child must not leave that
// child alive after the bounded timeout fires. Without the group kill, the
// backgrounded process outlives /bin/sh and keeps running (and, on a real host,
// keeps whatever egress/CPU it grabbed).
func TestRunCommandInvoke_KillsBackgroundedChildOnTimeout(t *testing.T) {
	t.Parallel()

	scratch := t.TempDir()
	pidFile := filepath.Join(scratch, "child.pid")

	// Background a long sleeper (fds redirected so it cannot hold our capture
	// pipe), record its pid, then block past the timeout.
	command := "sleep 60 >/dev/null 2>&1 & echo $! > child.pid; sleep 60"
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}

	_, ev := runCommandInvoke(context.Background(), scratch, 300*time.Millisecond, raw)
	if ev.Note != "timed out" {
		t.Fatalf("expected note %q, got %q", "timed out", ev.Note)
	}

	pid := readChildPID(t, pidFile)

	// After the group kill the backgrounded child must die promptly. Poll so the
	// test does not depend on exact reaping timing. A ticker (not time.Sleep) keeps
	// the poll within the test-stability tripwire's allowed synchronization set.
	deadline := time.Now().Add(3 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !processAlive(pid) {
			return // killed, as required
		}
		if time.Now().After(deadline) {
			// Best-effort cleanup so a leaked sleeper does not linger past the test.
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("backgrounded child pid %d still alive after timeout; process group was not reaped", pid)
		}
		<-ticker.C
	}
}

func readChildPID(t *testing.T, pidFile string) int {
	t.Helper()
	// The pid file is written immediately after backgrounding, well before the
	// timeout, but allow a brief poll in case the scheduler is slow. A ticker (not
	// time.Sleep) keeps the poll within the test-stability tripwire's allowed set.
	deadline := time.Now().Add(2 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(filepath.Clean(pidFile))
		if err == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("child pid file %s never became readable", pidFile)
		}
		<-ticker.C
	}
}

// processAlive reports whether pid is still a live process. signal 0 probes
// existence: nil means alive, ESRCH means gone.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
