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
	mu sync.Mutex
	// reaping remains true after reap returns. A numeric PID or PGID is safe
	// to signal only before cmd.Wait begins; after that, the kernel can reap
	// and recycle it before this package observes any later bookkeeping.
	reaping bool
}

// wait runs the blocking reap without holding the lock across it.
//
// Holding the lock for the duration of reap deadlocks: reap is cmd.Wait, and
// on the path this whole mechanism exists for, cmd.Wait does not return until
// the process tree is terminated - which is what terminate does. A terminate
// blocked on the mutex therefore waits on a reap that only that terminate can
// unblock, and the proxy hangs with the tree alive, which is precisely the
// leak being fixed.
//
// Raw numeric signals are safe only before reap begins. Once cmd.Wait starts,
// it may reap the child and recycle its identifiers before this package can
// observe reap's return, so terminate must use a kernel-stable process handle
// instead.
func (h *processExitHandoff) wait(reap func() error) error {
	h.mu.Lock()
	h.reaping = true
	h.mu.Unlock()

	return reap()
}

// reapStarted reports whether cmd.Wait has started. It remains true after
// cmd.Wait returns because that boundary permanently retires numeric process
// identifiers from this handoff.
func (h *processExitHandoff) reapStarted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reaping
}

// terminate runs the raw process-group teardown only while it can exclude a
// concurrent cmd.Wait. Once reaping has begun, it calls stable instead. For a
// Go exec.Cmd, stable is cmd.Process.Kill: Go 1.25 uses its process handle and
// returns os.ErrProcessDone after Wait, rather than signalling a reused PID.
func (h *processExitHandoff) terminate(beforeReap func(), stable func() bool) bool {
	h.mu.Lock()
	if !h.reaping {
		beforeReap()
		h.mu.Unlock()
		return true
	}
	h.mu.Unlock()
	return stable()
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
	// terminateTree tears down the whole process group before reaping
	// starts, or safely targets the direct child through its process
	// handle after that point. It returns false only when no live child
	// remains for the stable handle to terminate.
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
	// Logging is deliberately after the teardown state and descriptors have
	// changed. A blocked stderr copier can hold safeLogW indefinitely; do not
	// let that delay cancellation, descriptor closure, or forced teardown.
	logSessionExitAsync(act.logW)

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
	// signalled after cmd.Wait already reaped its group. terminateTree's
	// handoff allows numeric group signals only before reaping begins.
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
	// Record the escalation whatever the outcome. A false result means no live
	// child remained to signal, because tearing the tree down releases the
	// response reader and the main path can reach cmd.Wait first - not that
	// nothing happened. Returning early there hides the message in exactly the
	// case it matters most: the operator sees their MCP server disappear with
	// no reason recorded, which is indistinguishable from a crash.
	if act.logW != nil {
		logAsync(act.logW,
			"pipelock: wrapped MCP server did not exit within %s of session teardown; terminating process tree\n",
			grace)
	}
	return terminated
}

// newSessionBoundContext cancels a proxy context when the process that
// launched it dies. Capturing a PPID at the caller's first startup step narrows
// the time later setup can hide a parent death. It cannot close the earlier
// launcher-to-first-syscall race; that needs a launcher-owned lifetime
// primitive.
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
		logSessionExitAsync(logW)
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
// Capturing a PPID at process entry narrows but cannot close the earlier
// launcher-to-first-syscall race; closing that requires a launcher-owned
// lifetime primitive such as an owner pipe or cgroup.
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
			// Reparented. The session that spawned this proxy is gone. Logging
			// happens after callers mark and begin teardown, so a blocked writer
			// cannot strand the proxy before it starts shutting down.
			return true
		}
	}
}

func logSessionExitAsync(logW io.Writer) {
	logAsync(logW, "pipelock: spawning session exited; shutting down MCP proxy\n")
}

// logFlushGrace bounds how long an operator message may delay teardown. A
// healthy writer completes far inside it; a wedged one costs at most this.
const logFlushGrace = time.Second

// logAsync emits an operator message without letting a blocked writer stall
// teardown, and without silently dropping the message.
//
// Both failure directions are real. Writing synchronously lets a blocked log
// pipe - including one held by a stalled stderr copy - defer descriptor
// closure, cancellation and process termination indefinitely. But writing
// fire-and-forget loses the line whenever the process finishes first, and that
// line is the only explanation an operator ever gets for why their MCP server
// was killed; a security control that tears down a process tree silently is
// indistinguishable from a crash.
//
// So write from a goroutine, then wait a bounded moment for it. The message
// always lands for a working writer, and a wedged writer delays teardown by at
// most logFlushGrace instead of forever.
func logAsync(logW io.Writer, format string, args ...any) {
	if logW == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = fmt.Fprintf(logW, format, args...)
	}()
	select {
	case <-done:
	case <-time.After(logFlushGrace):
	}
}
