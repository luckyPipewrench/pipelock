// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			died := watchParentSession(ctx, parentWatchOpts{
				interval:  time.Millisecond,
				startPPID: tc.startPPID,
				getppid:   stubPPID(tc.startPPID, tc.newPPID, 3),
			})

			if !died {
				t.Fatalf("watchParentSession = false, want true after reparent to %d", tc.newPPID)
			}
		})
	}
}

type gatedLogWriter struct {
	mu          sync.Mutex
	buf         bytes.Buffer
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

func newGatedLogWriter() *gatedLogWriter {
	return &gatedLogWriter{started: make(chan struct{}), release: make(chan struct{})}
}

func (w *gatedLogWriter) Write(p []byte) (int, error) {
	w.startOnce.Do(func() { close(w.started) })
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *gatedLogWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *gatedLogWriter) Release() {
	w.releaseOnce.Do(func() { close(w.release) })
}

func TestRunSessionBoundExit_BlockedLogDoesNotDelayTeardown(t *testing.T) {
	t.Parallel()

	logW := newGatedLogWriter()
	defer logW.Release()
	var marked, intakeStopped, stdinClosed, terminated atomic.Bool
	done := make(chan bool, 1)
	go func() {
		done <- runSessionBoundExit(context.Background(), deadSession(), sessionExitActions{
			onSessionExit:    func() { marked.Store(true) },
			stopIntake:       func() { intakeStopped.Store(true) },
			closeServerStdin: func() { stdinClosed.Store(true) },
			terminateTree:    func() bool { terminated.Store(true); return true },
			waitDone:         make(chan struct{}),
			grace:            time.Millisecond,
			logW:             logW,
		})
	}()

	select {
	case <-logW.started:
	case <-time.After(5 * time.Second):
		t.Fatal("session-exit log was never attempted")
	}

	select {
	case escalated := <-done:
		if !escalated {
			t.Fatal("session teardown did not escalate while its log writer was blocked")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked log writer delayed session teardown")
	}
	if !marked.Load() || !intakeStopped.Load() || !stdinClosed.Load() || !terminated.Load() {
		t.Fatal("session teardown did not mark, close, and terminate before logging")
	}

	logW.Release()
	testwait.For(t, 5*time.Second, func() bool {
		return strings.Contains(logW.String(), "spawning session exited")
	}, "the deferred session-exit explanation to reach the operator log")
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
			terminateTree:    func() bool { terminated.Store(true); return true },
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
		terminateTree:    func() bool { terminated.Store(true); return true },
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
		terminateTree:    func() bool { touched.Store(true); return true },
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
	draining := make(chan struct{})
	go func() {
		<-draining
		cancel()
	}()

	escalated := runSessionBoundExit(ctx, deadSession(), sessionExitActions{
		stopIntake:       func() {},
		closeServerStdin: func() { close(draining) },
		terminateTree:    func() bool { terminated.Store(true); return true },
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
	draining := make(chan struct{})
	go func() {
		<-draining
		close(waitDone)
	}()

	escalated := runSessionBoundExit(context.Background(), deadSession(), sessionExitActions{
		stopIntake:       func() {},
		closeServerStdin: func() { close(draining) },
		terminateTree: func() bool {
			t.Error("terminated during the default grace window")
			return true
		},
		waitDone: waitDone,
	})

	if escalated {
		t.Error("escalated despite the server exiting inside the default grace")
	}
	if elapsed := time.Since(start); elapsed >= defaultParentExitGrace {
		t.Errorf("waited %s, expected to short-circuit well inside the %s default grace", elapsed, defaultParentExitGrace)
	}
}

func TestProcessExitHandoff_TerminateProceedsWhileReapInFlight(t *testing.T) {
	t.Parallel()

	// The deadlock this guards against: reap is cmd.Wait, and on the path the
	// session-bound exit exists for, cmd.Wait does not return until the tree is
	// terminated. If a reap in flight blocked terminate, the escalation would
	// wait on a reap only that escalation could unblock, and the proxy would
	// hang with the whole tree alive - the exact leak being fixed.
	//
	// A direct-child process handle remains safe here, but a raw process-group
	// signal does not: reap can complete immediately after the handoff releases
	// its lock and before a later goroutine sends that numeric signal.
	handoff := &processExitHandoff{}
	reapEntered := make(chan struct{})
	releaseReap := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseReap) }) }
	waitDone := make(chan error, 1)

	go func() {
		waitDone <- handoff.wait(func() error {
			close(reapEntered)
			<-releaseReap // stands in for a cmd.Wait that never returns on its own
			return nil
		})
	}()

	<-reapEntered
	testwait.For(t, 2*time.Second, handoff.reapStarted, "the reap to be marked in flight")

	var rawGroupSignal, stableDirectKill atomic.Bool
	escalated := make(chan bool, 1)
	go func() {
		escalated <- handoff.terminate(
			func() { rawGroupSignal.Store(true) },
			func() bool {
				stableDirectKill.Store(true)
				release()
				return true
			},
		)
	}()

	select {
	case ok := <-escalated:
		if !ok || !stableDirectKill.Load() {
			t.Error("escalation did not use the stable direct-child handle while reap was in flight")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminate blocked on an in-flight reap; this is the deadlock that hangs the proxy with its tree alive")
	}

	release()
	if rawGroupSignal.Load() {
		t.Error("escalation signalled a raw process group after cmd.Wait started")
	}
	if err := <-waitDone; err != nil {
		t.Fatalf("process reaping returned %v", err)
	}
}

func TestProcessExitHandoff_UsesStableHandleAfterReapingStarts(t *testing.T) {
	t.Parallel()

	// Once cmd.Wait has RETURNED, a late signal could target a PID or process
	// group the kernel already reused.
	handoff := &processExitHandoff{}
	if err := handoff.wait(func() error { return nil }); err != nil {
		t.Fatalf("process reaping returned %v", err)
	}
	var rawGroupSignal, stableDirectKill atomic.Bool

	if !handoff.terminate(
		func() { rawGroupSignal.Store(true) },
		func() bool { stableDirectKill.Store(true); return true },
	) {
		t.Error("session exit did not attempt the stable direct-child handle after reaping started")
	}
	if rawGroupSignal.Load() {
		t.Error("late session exit signalled a raw process identifier after reaping began")
	}
	if !stableDirectKill.Load() {
		t.Error("late session exit did not use the stable direct-child handle")
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
