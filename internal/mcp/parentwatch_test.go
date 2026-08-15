// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubPPID returns a getppid func that reports first for the first n calls
// and then reports after, simulating a reparenting event.
func stubPPID(first, after int, n int64) func() int {
	var calls atomic.Int64
	return func() int {
		if calls.Add(1) <= n {
			return first
		}
		return after
	}
}

func TestWatchParentSession_ReparentingIsDetected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		startPPID int
		newPPID   int
	}{
		// The textbook case: no subreaper claimed us, so we land on init.
		{name: "reparented to init", startPPID: 4242, newPPID: orphanedPPID},
		// An intermediate subreaper (systemd --user, a container shim, or
		// another pipelock with PR_SET_CHILD_SUBREAPER set) adopts us
		// instead. The new PPID is neither the original nor 1, so a check
		// written as "PPID == 1" would miss this entirely and the proxy
		// would leak exactly as before.
		{name: "reparented to subreaper", startPPID: 4242, newPPID: 9001},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var logBuf bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			died := watchParentSession(ctx, parentWatchOpts{
				interval:  time.Millisecond,
				startPPID: tc.startPPID,
				getppid:   stubPPID(tc.startPPID, tc.newPPID, 3),
				logW:      &logBuf,
			})

			if !died {
				t.Fatalf("watchParentSession = false, want true after reparent to %d", tc.newPPID)
			}
			if got := logBuf.String(); !strings.Contains(got, "spawning session exited") {
				t.Errorf("missing operator explanation in log, got %q", got)
			}
		})
	}
}

// deadSession reports a reparent immediately, so teardown tests do not
// depend on wall-clock polling.
func deadSession() parentWatchOpts {
	return parentWatchOpts{
		interval:  time.Millisecond,
		startPPID: 4242,
		getppid:   func() int { return orphanedPPID },
	}
}

func TestRunSessionBoundExit_CooperativeServerIsNotKilled(t *testing.T) {
	t.Parallel()

	// The wrapped server takes its stdin close as shutdown and exits, so
	// cmd.Wait returns and waitDone closes. Escalating anyway would kill a
	// server that was already draining cleanly and could discard responses
	// it was still writing.
	waitDone := make(chan struct{})
	var intake, stdinClosed, terminated atomic.Bool

	done := make(chan bool, 1)
	go func() {
		done <- runSessionBoundExit(context.Background(), deadSession(), sessionExitActions{
			stopIntake:       func() { intake.Store(true) },
			closeServerStdin: func() { stdinClosed.Store(true); close(waitDone) },
			terminateTree:    func() { terminated.Store(true) },
			waitDone:         waitDone,
			grace:            10 * time.Second, // must never be waited out
		})
	}()

	select {
	case escalated := <-done:
		if escalated {
			t.Error("escalated to a forced teardown for a server that exited on its own")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("teardown blocked past the cooperative exit; the grace window was waited out")
	}

	if !intake.Load() {
		t.Error("request intake was not stopped")
	}
	if !stdinClosed.Load() {
		t.Error("wrapped server stdin was not closed")
	}
	if terminated.Load() {
		t.Error("process tree was terminated despite a clean drain")
	}
}

func TestRunSessionBoundExit_ServerIgnoringEOFIsTerminated(t *testing.T) {
	t.Parallel()

	// The leak case: the server never reads stdin, so closing it achieves
	// nothing and waitDone never closes. Without the bounded grace the
	// proxy would wait here forever, which is the original bug.
	var terminated atomic.Bool
	escalated := runSessionBoundExit(context.Background(), deadSession(), sessionExitActions{
		stopIntake:       func() {},
		closeServerStdin: func() {}, // server ignores it
		terminateTree:    func() { terminated.Store(true) },
		waitDone:         make(chan struct{}), // never closed
		grace:            10 * time.Millisecond,
	})

	if !escalated {
		t.Error("runSessionBoundExit = false; a server ignoring stdin close was left running")
	}
	if !terminated.Load() {
		t.Error("process tree was not terminated for a server that ignored stdin close")
	}
}

func TestRunSessionBoundExit_LiveSessionRunsNoTeardown(t *testing.T) {
	t.Parallel()

	// Nothing at all may happen while the session is alive - not even
	// stopping intake, which would break a healthy proxy mid-call.
	var touched atomic.Bool
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	escalated := runSessionBoundExit(ctx, parentWatchOpts{
		interval:  time.Millisecond,
		startPPID: 4242,
		getppid:   func() int { return 4242 },
	}, sessionExitActions{
		stopIntake:       func() { touched.Store(true) },
		closeServerStdin: func() { touched.Store(true) },
		terminateTree:    func() { touched.Store(true) },
		waitDone:         make(chan struct{}),
		grace:            time.Millisecond,
	})

	if escalated || touched.Load() {
		t.Fatal("teardown ran against a live session")
	}
}

func TestRunSessionBoundExit_CancelDuringGraceStopsEscalation(t *testing.T) {
	t.Parallel()

	// RunProxy returned while the drain was in flight. The teardown must
	// stand down rather than signal a group the main path already reaped.
	var terminated atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	escalated := runSessionBoundExit(ctx, deadSession(), sessionExitActions{
		stopIntake:       func() {},
		closeServerStdin: func() {},
		terminateTree:    func() { terminated.Store(true) },
		waitDone:         make(chan struct{}),
		grace:            10 * time.Second,
	})

	if escalated || terminated.Load() {
		t.Error("escalated after the proxy had already shut down")
	}
}

func TestRunSessionBoundExit_DefaultGraceApplies(t *testing.T) {
	t.Parallel()

	// A zero grace must fall back to the default rather than escalate
	// instantly, which would give a cooperative server no drain at all.
	start := time.Now()
	waitDone := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		close(waitDone)
	}()

	escalated := runSessionBoundExit(context.Background(), deadSession(), sessionExitActions{
		stopIntake:       func() {},
		closeServerStdin: func() {},
		terminateTree:    func() { t.Error("terminated during the default grace window") },
		waitDone:         waitDone,
	})

	if escalated {
		t.Error("escalated despite the server exiting inside the default grace")
	}
	if elapsed := time.Since(start); elapsed >= defaultParentExitGrace {
		t.Errorf("waited %s, expected to short-circuit well inside the %s default grace", elapsed, defaultParentExitGrace)
	}
}

func TestWatchParentSession_StableParentNeverFires(t *testing.T) {
	t.Parallel()

	// The normal-completion case, and the one that matters most for
	// availability: a live session must never be torn down. The parent
	// never changes, so the watch must block until ctx cancels no matter
	// how long it runs or how many times it polls.
	var polls atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	died := watchParentSession(ctx, parentWatchOpts{
		interval:  time.Millisecond,
		startPPID: 4242,
		getppid: func() int {
			polls.Add(1)
			return 4242
		},
	})

	if died {
		t.Fatal("watchParentSession = true for a live parent; a healthy proxy would be killed mid-call")
	}
	if polls.Load() < 5 {
		t.Fatalf("watcher polled %d times, expected repeated polling", polls.Load())
	}
}

func TestWatchParentSession_AlreadyOrphanedIsInert(t *testing.T) {
	t.Parallel()

	// Started by a supervisor, daemonized, or already reparented before the
	// watch began. There is no session to bind to, so the watcher must stay
	// inert rather than treating "PPID is 1" as death and shutting down a
	// service-managed proxy at startup.
	var polls atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	died := watchParentSession(ctx, parentWatchOpts{
		interval:  time.Millisecond,
		startPPID: orphanedPPID,
		getppid: func() int {
			polls.Add(1)
			return 12345 // would look like a reparent if it were consulted
		},
	})

	if died {
		t.Fatal("watchParentSession = true for an already-orphaned proxy; supervisor-managed proxies would self-terminate")
	}
	if polls.Load() != 0 {
		t.Fatalf("inert watcher polled %d times, want 0", polls.Load())
	}
}

func TestNewSessionBoundContext_AlreadyOrphanedIsInert(t *testing.T) {
	var polls atomic.Int64
	ctx, stop, state := newSessionBoundContext(context.Background(), parentWatchOpts{
		startPPID: orphanedPPID,
		getppid: func() int {
			polls.Add(1)
			return 4242
		},
	}, nil, nil, nil)
	defer stop()

	select {
	case <-ctx.Done():
		t.Fatal("inert session context was cancelled before its caller stopped it")
	default:
	}
	if state.inProgress() {
		t.Fatal("inert session watch recorded an exit")
	}
	if polls.Load() != 0 {
		t.Fatalf("inert session watch polled %d times, want 0", polls.Load())
	}
}

func TestWatchParentSession_ContextCancelWins(t *testing.T) {
	t.Parallel()

	// The proxy finished on its own and stopped the watch. Returning false
	// here is what keeps the teardown path from running twice.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if watchParentSession(ctx, parentWatchOpts{
		interval:  time.Hour,
		startPPID: 4242,
		getppid:   func() int { return orphanedPPID },
	}) {
		t.Fatal("watchParentSession = true on a cancelled context, want false")
	}
}

func TestWatchParentSession_DefaultsAreSane(t *testing.T) {
	t.Parallel()

	// A nil getppid must fall back to the real syscall rather than panic,
	// and the real parent of the test process is stable, so this also
	// re-confirms the no-false-positive direction against live values.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if watchParentSession(ctx, parentWatchOpts{startPPID: os.Getppid(), interval: time.Millisecond}) {
		t.Fatal("watchParentSession fired against the real, live parent PID")
	}
}
