// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Default cadence and drain window for the session-bound exit. The poll
// interval is deliberately coarse: a leaked proxy that lives two extra
// seconds costs nothing, while a tight loop on a long-lived scanner is
// pure overhead. The grace window is the time a cooperative MCP server
// gets to finish in-flight work and exit on its own after stdin EOF,
// before the tree is torn down for it.
const (
	defaultParentPollInterval = 2 * time.Second
	defaultParentExitGrace    = 5 * time.Second
)

// orphanedPPID is the parent PID a process reports once its original
// parent has died and no ancestor has claimed the subreaper role. A
// process started this way has no session to be bound to.
const orphanedPPID = 1

// parentWatchOpts configures watchParentSession. The function fields
// exist so tests can drive the watcher deterministically without
// spawning real process trees.
type parentWatchOpts struct {
	// interval is how often the parent PID is re-read.
	interval time.Duration
	// getppid returns the current parent PID. Defaults to os.Getppid.
	getppid func() int
	// startPPID is the parent PID recorded before the watch began.
	startPPID int
	// logW receives the single operator-visible line explaining why the
	// proxy is shutting down. Never nil in production; the caller passes
	// the mutex-wrapped writer.
	logW io.Writer
}

// sessionExitTestHooks lets a test drive the session-bound exit in-process.
// The real signal is the kernel reparenting us, which a test process cannot
// arrange for itself without spawning a helper subprocess whose coverage the
// parent cannot observe.
type sessionExitTestHooks struct {
	watch parentWatchOpts
	grace time.Duration
}

// sessionExitState records that Pipelock, rather than the peer, closed a
// session input or output descriptor during intentional session teardown.
// Close errors on that path are expected shutdown, not scanner failures.
type sessionExitState struct {
	exiting atomic.Bool
}

func (s *sessionExitState) begin() {
	if s != nil {
		s.exiting.Store(true)
	}
}

func (s *sessionExitState) inProgress() bool {
	return s != nil && s.exiting.Load()
}

func isSessionExitCloseErr(err error) bool {
	return errors.Is(err, os.ErrClosed)
}

// processExitHandoff gives teardown and reaping one owner for the child
// identifiers. Once cmd.Wait starts, the kernel can reuse the direct child's
// PID or process-group ID as soon as it reaps the child, so a late escalation
// must not signal either value.
type processExitHandoff struct {
	mu     sync.Mutex
	reaped bool
}

func (h *processExitHandoff) wait(reap func() error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := reap()
	h.reaped = true
	return err
}

func (h *processExitHandoff) terminate(fn func()) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reaped {
		return false
	}
	fn()
	return true
}

// sessionExitActions are the teardown steps runSessionBoundExit performs
// once the spawning session is confirmed gone. They are injected so the
// ordering can be tested in-process: the production path runs inside a
// helper subprocess, whose coverage the parent test process cannot see.
type sessionExitActions struct {
	// onSessionExit marks the teardown before it closes any descriptor, so
	// scanner readers can recognize their expected close error.
	onSessionExit func()
	// stopIntake closes the client side so no further requests arrive.
	stopIntake func()
	// closeServerStdin gives a cooperative server its shutdown signal.
	closeServerStdin func()
	// terminateTree tears down the whole process group and the direct
	// child. It returns false when cmd.Wait already owns reaping, so no
	// stale process identifier is ever signalled after that handoff.
	terminateTree func() bool
	// waitDone closes when cmd.Wait has returned, short-circuiting the
	// grace window for a server that exited on its own.
	waitDone <-chan struct{}
	// grace bounds how long a cooperative shutdown is allowed to take.
	grace time.Duration
	// logW receives the escalation notice. May be nil in tests.
	logW io.Writer
}

// runSessionBoundExit waits for the spawning session to die and then runs
// the teardown sequence. It reports whether it escalated to a forced
// process-tree teardown, which is the branch tests assert on.
//
// The sequence is a drain, not a kill: intake stops, the server is given
// its shutdown signal and a bounded window to finish in-flight work, and
// only a server that will not leave on its own is terminated.
func runSessionBoundExit(ctx context.Context, opts parentWatchOpts, act sessionExitActions) bool {
	if !watchParentSession(ctx, opts) {
		return false
	}
	if act.onSessionExit != nil {
		act.onSessionExit()
	}

	// 1. Stop new request intake. The client died with its session, so
	//    anything still arriving cannot be answered anyway.
	if act.stopIntake != nil {
		act.stopIntake()
	}
	// 2. Signal shutdown to the wrapped server. A cooperative server
	//    finishes in-flight work and exits, which lets cmd.Wait return on
	//    its own and keeps pending responses intact.
	if act.closeServerStdin != nil {
		act.closeServerStdin()
	}

	grace := act.grace
	if grace <= 0 {
		grace = defaultParentExitGrace
	}

	// 3. Bound the drain. A server that ignores stdin close never returns
	//    from step 2, so waiting forever here would reproduce the exact
	//    leak this watcher exists to close.
	select {
	case <-act.waitDone:
		return false
	case <-ctx.Done():
		return false
	case <-time.After(grace):
	}

	// The grace timer and waitDone can become ready in the same instant,
	// and a select picks uniformly among ready cases. Re-check before
	// escalating so a server that finished right at the deadline is not
	// signalled after cmd.Wait already reaped its group. terminateTree has
	// the synchronized handoff that closes the remaining check-to-signal
	// race with cmd.Wait.
	select {
	case <-act.waitDone:
		return false
	default:
	}

	// 4. The server outlasted its drain window. The process handoff can
	// decline if cmd.Wait won the race to own reaping.
	terminated := true
	if act.terminateTree != nil {
		terminated = act.terminateTree()
	}
	if !terminated {
		return false
	}
	if act.logW != nil {
		_, _ = fmt.Fprintf(act.logW,
			"pipelock: wrapped MCP server did not exit within %s of session teardown; terminating process tree\n",
			grace)
	}
	return true
}

// newSessionBoundContext cancels a proxy context when the process that
// launched it dies. The caller supplies a PPID captured at function entry so
// startup work cannot turn a real parent death into an inert PID-1 watch.
// Closing a closable input wakes the stdio read that context cancellation alone
// cannot interrupt.
func newSessionBoundContext(
	ctx context.Context,
	watch parentWatchOpts,
	clientIn io.Reader,
	logW io.Writer,
	hooks *sessionExitTestHooks,
) (context.Context, context.CancelFunc, *sessionExitState) {
	sessionCtx, stop := context.WithCancel(ctx)
	state := &sessionExitState{}
	if hooks != nil {
		watch = hooks.watch
	}
	watch.logW = logW

	// An already orphaned launch is intentionally inert. Avoid parking a
	// goroutine for a supervisor-managed proxy that has no session owner.
	if watch.startPPID <= orphanedPPID {
		return sessionCtx, stop, state
	}

	go func() {
		if !watchParentSession(sessionCtx, watch) {
			return
		}
		state.begin()
		if c, ok := clientIn.(io.Closer); ok {
			_ = c.Close()
		}
		stop()
	}()

	return sessionCtx, stop, state
}

// watchParentSession blocks until the spawning session is provably gone,
// then returns true. It returns false when ctx is cancelled first, which
// is the normal path: the proxy finished on its own and stopped the watch.
//
// The only accepted death signal is REPARENTING. A process's parent PID
// can change for exactly one reason - the original parent died and the
// kernel reassigned the child to init or to the nearest subreaper. That
// makes an observed PPID change proof, not a heuristic.
//
// Two signals are deliberately NOT used, because both produce false
// positives that kill a live scanner mid-call:
//
//   - Process age. A legitimate agent session can outlive any threshold
//     an operator would pick, and killing a healthy proxy breaks traffic
//     in flight. An operator who gets burned by that disables the control,
//     which is a worse outcome than the leak it was meant to fix.
//   - stdin EOF alone. A client can close stdin, or a transport can hand
//     us EOF, while the session that owns the wrapped server is very much
//     alive. EOF is a hint about one pipe, not about session lifetime.
//
// A proxy whose recorded parent is already the orphan PID has no session
// to bind to - it was started by a supervisor, daemonized, or re-parented
// before the watch began - so the watch is inert and returns only on ctx.
func watchParentSession(ctx context.Context, opts parentWatchOpts) bool {
	getppid := opts.getppid
	if getppid == nil {
		getppid = os.Getppid
	}
	interval := opts.interval
	if interval <= 0 {
		interval = defaultParentPollInterval
	}

	// No identifiable session owner. Staying inert is the fail-safe
	// direction: a supervisor-managed proxy must not shut itself down
	// merely because it has no interactive parent.
	if opts.startPPID <= orphanedPPID {
		<-ctx.Done()
		return false
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			current := getppid()
			if current == opts.startPPID {
				continue
			}
			// Reparented. The session that spawned this proxy is gone.
			if opts.logW != nil {
				_, _ = fmt.Fprintf(opts.logW,
					"pipelock: spawning session exited (parent pid %d reparented to %d); shutting down MCP proxy\n",
					opts.startPPID, current)
			}
			return true
		}
	}
}
