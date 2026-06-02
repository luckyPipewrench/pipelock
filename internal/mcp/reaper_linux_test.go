// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReaper_AdoptedZombieDrained_DirectChildPreserved is the regression
// test for the MCP proxy zombie accumulation bug. It enables the same
// PR_SET_CHILD_SUBREAPER bit pipelock sets, spawns a helper whose
// double-forked grandchild exits while the helper stays alive, asserts
// the grandchild is reaped by the live reaper (not left as a zombie),
// then asserts cmd.Wait() still observes the helper's exit normally
// (i.e. the reaper did not steal the direct child's exit status).
func TestReaper_AdoptedZombieDrained_DirectChildPreserved(t *testing.T) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable (need CAP_SYS_RESOURCE in containers): %v", err)
	}

	// Helper script: double-fork a grandchild that sleeps briefly and
	// exits. The intermediate shell exits immediately so the grandchild
	// reparents to whichever ancestor has PR_SET_CHILD_SUBREAPER set -
	// that's this test process. The outer helper then sleeps so the
	// direct child stays alive while the grandchild becomes a zombie.
	helper := `( ( sleep 0.1; exit 0 ) & ) ; sleep 30`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", helper)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting helper: %v", err)
	}
	directPID := cmd.Process.Pid

	// Step 1: WITHOUT the reaper, observe the bug. The double-forked
	// grandchild sleeps 100 ms then exits and becomes a zombie under
	// us (via subreaper adoption). Poll until we see it. This proves
	// the test scenario actually reproduces the leak - without this
	// gate a no-op reaper would also pass.
	if !waitForCondition(t, 2*time.Second, func() bool {
		return countAdoptedZombies(directPID) >= 1
	}) {
		t.Fatal("scenario invalid: no adopted zombie ever appeared (helper didn't double-fork as expected)")
	}

	// Step 2: start the reaper. Initial sweep runs first inside the
	// goroutine (before it blocks on the select), so the existing
	// zombie should be drained within the next scheduling tick.
	// Future grandchildren get drained on SIGCHLD.
	reaperDone := make(chan struct{})
	startAdoptedReaper(directPID, reaperDone)

	if !waitForCondition(t, 2*time.Second, func() bool {
		return countAdoptedZombies(directPID) == 0
	}) {
		dumpZombies(t, directPID)
		t.Fatal("live reaper did not drain adopted-descendant zombie")
	}

	// Direct child must still be running and reapable by cmd.Wait().
	// If the reaper had stolen its exit status, Wait would return
	// ECHILD-derived "wait: no child processes" or hang.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signaling direct child: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case err := <-waitDone:
		// Helper exited via SIGTERM; an *exec.ExitError is expected and
		// proves Wait observed the direct child's exit. The forbidden
		// failure mode is err == nil with a stolen-exit symptom or
		// "no child processes".
		if err == nil {
			// Unlikely but acceptable - the helper happened to exit 0.
			break
		}
		if isReaperStoleExitError(err) {
			t.Fatalf("cmd.Wait() returned a stolen-exit error — reaper consumed the direct child: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cmd.Wait() hung — reaper likely consumed the direct child's exit status")
	}

	close(reaperDone)
}

func TestReaper_ProtectedDirectPIDRegistry(t *testing.T) {
	const pid = 424242

	unregister := registerProtectedDirectPID(pid)
	if !isProtectedDirectPID(pid) {
		t.Fatal("direct PID was not registered as protected")
	}

	unregister()
	if isProtectedDirectPID(pid) {
		t.Fatal("direct PID remained protected after unregister")
	}

	unregister()
	if isProtectedDirectPID(pid) {
		t.Fatal("second unregister call restored protected PID")
	}

	unregisterFirst := registerProtectedDirectPID(pid)
	unregisterSecond := registerProtectedDirectPID(pid)
	unregisterFirst()
	if !isProtectedDirectPID(pid) {
		t.Fatal("first unregister cleared overlapping same-PID registration")
	}
	unregisterSecond()
	if isProtectedDirectPID(pid) {
		t.Fatal("direct PID remained protected after all overlapping registrations were unregistered")
	}
}

// waitForCondition polls cond every 25 ms until it returns true or the
// deadline passes. Returns the final value of cond().
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if cond() {
			return true
		}
		select {
		case <-timer.C:
			return cond()
		case <-ticker.C:
		}
	}
}

// countAdoptedZombies returns the number of zombies under our PID
// excluding the direct child. Mirrors the reaper's filter.
func countAdoptedZombies(directPID int) int {
	selfPID := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	var n int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		childPID, convErr := strconv.Atoi(name)
		if convErr != nil {
			continue
		}
		if childPID == selfPID || childPID == directPID {
			continue
		}
		if isAdoptedZombie(name, selfPID) {
			n++
		}
	}
	return n
}

// dumpZombies logs surviving zombies for diagnostic when the test fails.
func dumpZombies(t *testing.T, directPID int) {
	t.Helper()
	selfPID := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		childPID, convErr := strconv.Atoi(name)
		if convErr != nil {
			continue
		}
		if childPID == selfPID || childPID == directPID {
			continue
		}
		if !isAdoptedZombie(name, selfPID) {
			continue
		}
		statBytes, _ := os.ReadFile(filepath.Clean("/proc/" + name + "/stat"))
		t.Logf("surviving zombie pid=%d stat=%q", childPID, strings.TrimSpace(string(statBytes)))
	}
}

// isReaperStoleExitError detects the symptom of the reaper consuming
// the direct child's exit status: a syscall.ECHILD wrapped somewhere in
// the cmd.Wait error chain. Match through errors.Is so any wrapper
// preserving the chain (exec.Cmd.Wait, os.SyscallError, etc.) resolves
// to the same verdict regardless of the surrounding message text.
func isReaperStoleExitError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECHILD)
}

// TestReaper_DoneChannelStopsGoroutine covers the done-channel teardown
// branch of startAdoptedReaper and verifies the goroutine actually
// exits - not merely that the test completes without deadlock. We
// snapshot runtime.NumGoroutine before and after a batch of
// start/close cycles; if the done branch failed to fire, leaked
// goroutines would accumulate and the post-batch count would exceed
// the pre-batch count by approximately the iteration count.
func TestReaper_DoneChannelStopsGoroutine(t *testing.T) {
	const iterations = 10
	// Warm signal.Notify's package/runtime goroutines before taking the
	// baseline. The assertion below is about startAdoptedReaper teardown, not
	// about one-time SIGCHLD signal machinery initialized on first use.
	warmDone := make(chan struct{})
	startAdoptedReaper(0, warmDone)
	close(warmDone)
	if !waitForCondition(t, time.Second, func() bool {
		return !isProtectedDirectPID(0)
	}) {
		t.Fatal("warm-up reaper did not unregister protected direct PID")
	}
	before := runtime.NumGoroutine()

	for range iterations {
		done := make(chan struct{})
		startAdoptedReaper(0, done) // directPID=0 is impossible - never matches
		// Send a self-SIGCHLD to deterministically exercise the sigCh
		// branch. The reaper sweep is a no-op (no adopted zombies under
		// this test process) but the branch is hit, which is the goal.
		_ = syscall.Kill(os.Getpid(), syscall.SIGCHLD)
		close(done)
		if !waitForCondition(t, time.Second, func() bool {
			return !isProtectedDirectPID(0)
		}) {
			t.Fatal("reaper did not unregister protected direct PID")
		}
	}
	// Give all goroutines a chance to observe close(done) and exit.
	var after int
	if !waitForCondition(t, 2*time.Second, func() bool {
		after = runtime.NumGoroutine()
		return after-before <= 2
	}) {
		after = runtime.NumGoroutine()
	}
	// Allow ±2 goroutines for unrelated test infra noise; iterations=10
	// makes a true leak unmistakable (delta ≥ 10).
	if delta := after - before; delta > 2 {
		t.Fatalf("goroutine leak: %d goroutines before, %d after (delta=%d, iterations=%d)",
			before, after, delta, iterations)
	}
}
