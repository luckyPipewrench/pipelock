// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingReader stands in for a client whose session is alive: it never
// returns data and never returns EOF, so nothing but the session watcher
// can bring the proxy down. Close unblocks it, which is exactly what the
// teardown's stopIntake step must do.
type blockingReader struct {
	once   sync.Once
	closed chan struct{}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type nonClosableBlockingReader struct {
	started      chan struct{}
	returned     chan struct{}
	release      chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
	returnedOnce sync.Once
}

func newNonClosableBlockingReader() *nonClosableBlockingReader {
	return &nonClosableBlockingReader{
		started:  make(chan struct{}),
		returned: make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (b *nonClosableBlockingReader) Read(_ []byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.release
	// A reader can be polled more than once; closing an already-closed
	// channel would panic and mask the behaviour under test.
	b.returnedOnce.Do(func() { close(b.returned) })
	return 0, io.EOF
}

func (b *nonClosableBlockingReader) unblock() {
	b.releaseOnce.Do(func() { close(b.release) })
}

func newBlockingReader() *blockingReader {
	return &blockingReader{closed: make(chan struct{})}
}

func (b *blockingReader) Read(_ []byte) (int, error) {
	<-b.closed
	return 0, io.EOF
}

func (b *blockingReader) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// TestRunProxy_SessionExitTerminatesIgnoringServer drives the real RunProxy
// wiring end to end in-process: a genuine child process that ignores stdin,
// a genuine blocked client reader, and the actual teardown closures. Only
// the parent-death observation is simulated, because a test process cannot
// make its own parent die.
func TestRunProxy_SessionExitTerminatesIgnoringServer(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real child process")
	}

	clientIn := newBlockingReader()
	defer func() { _ = clientIn.Close() }()

	parentDied := make(chan struct{})
	outputForwardStarted := make(chan struct{})
	var stdout bytes.Buffer
	var logBuf lockedBuffer
	opts := MCPProxyOpts{
		sessionExitForTest: &sessionExitTestHooks{
			watch: parentWatchOpts{
				interval:  time.Millisecond,
				startPPID: 4242,
				getppid: func() int {
					select {
					case <-parentDied:
						return orphanedPPID
					default:
						return 4242
					}
				},
			},
			grace: 50 * time.Millisecond,
		},
		outputForwardStartedForTest: func() { close(outputForwardStarted) },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		// `sleep` never reads stdin, so closing it is a no-op and only the
		// forced process-tree teardown can end this call.
		done <- RunProxy(ctx, clientIn, &stdout, &logBuf, []string{"sleep", "120"}, opts)
	}()
	select {
	case <-outputForwardStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("RunProxy never entered the server-output forwarding loop")
	}
	close(parentDied)

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, ErrSubprocessExit) {
			t.Errorf("RunProxy = %v, want no scanner error after session teardown", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("RunProxy never returned after the spawning session died; the proxy leaked")
	}

	log := logBuf.String()
	if !strings.Contains(log, "spawning session exited") {
		t.Errorf("missing session-exit explanation in operator log, got %q", log)
	}
	if !strings.Contains(log, "terminating process tree") {
		t.Errorf("missing forced-teardown notice for a server that ignored stdin close, got %q", log)
	}
}

// TestRunProxy_LiveSessionIsNotTornDown is the availability direction: with
// a parent that never changes, RunProxy must keep running. A watcher that
// fired here would kill healthy scanners mid-call.
func TestRunProxy_LiveSessionIsNotTornDown(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real child process")
	}

	clientIn := newBlockingReader()
	var stdout bytes.Buffer
	var logBuf lockedBuffer

	opts := MCPProxyOpts{
		sessionExitForTest: &sessionExitTestHooks{
			watch: parentWatchOpts{
				interval:  time.Millisecond,
				startPPID: os.Getppid(),
				getppid:   os.Getppid,
			},
			grace: 10 * time.Millisecond,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunProxy(ctx, clientIn, &stdout, &logBuf, []string{"sleep", "120"}, opts)
	}()

	// Well past many poll intervals and grace windows.
	select {
	case <-done:
		t.Fatalf("RunProxy exited while its session was alive; log: %q", logBuf.String())
	case <-time.After(500 * time.Millisecond):
	}

	if got := logBuf.String(); strings.Contains(got, "spawning session exited") {
		t.Errorf("session-exit path ran against a live parent, got %q", got)
	}

	// Shut down cleanly so the child is reaped before the test ends.
	_ = clientIn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("RunProxy did not shut down after context cancellation")
	}
}

func TestRunProxy_SessionExitBoundsNonClosableInputDrain(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real child process")
	}

	clientIn := newNonClosableBlockingReader()
	t.Cleanup(clientIn.unblock)
	parentDied := make(chan struct{})
	var stdout, logBuf bytes.Buffer
	opts := MCPProxyOpts{
		sessionExitForTest: &sessionExitTestHooks{
			watch: parentWatchOpts{
				interval:  time.Millisecond,
				startPPID: 4242,
				getppid: func() int {
					select {
					case <-parentDied:
						return orphanedPPID
					default:
						return 4242
					}
				},
			},
			grace: 20 * time.Millisecond,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunProxy(ctx, clientIn, &stdout, &logBuf, []string{"sleep", "120"}, opts)
	}()

	select {
	case <-clientIn.started:
	case <-time.After(5 * time.Second):
		t.Fatal("RunProxy never started reading the non-closable client input")
	}
	close(parentDied)

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, ErrSubprocessExit) {
			t.Errorf("RunProxy = %v, want clean session-bound shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunProxy waited indefinitely for non-closable input after session exit")
	}

	clientIn.unblock()
	select {
	case <-clientIn.returned:
	case <-time.After(5 * time.Second):
		t.Fatal("non-closable client input did not release after the test")
	}
}

func TestDrainStderr_ReleasesEscapedPipeHolder(t *testing.T) {
	t.Run("timeout closes escaped writer", func(t *testing.T) {
		serverErr, escapedWriter, err := os.Pipe()
		if err != nil {
			t.Fatalf("creating stderr pipe: %v", err)
		}
		defer func() { _ = escapedWriter.Close() }()

		stderrDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, serverErr)
			close(stderrDone)
		}()

		if drained := drainStderr(stderrDone, serverErr, time.Millisecond); drained {
			t.Fatal("drainStderr = true while an escaped stderr writer remained open")
		}
		select {
		case <-stderrDone:
		case <-time.After(5 * time.Second):
			t.Fatal("stderr copier remained blocked after the drain timeout")
		}
	})

	t.Run("normal drain closes reader", func(t *testing.T) {
		serverErr, serverErrW, err := os.Pipe()
		if err != nil {
			t.Fatalf("creating stderr pipe: %v", err)
		}
		if err := serverErrW.Close(); err != nil {
			t.Fatalf("closing stderr writer: %v", err)
		}
		stderrDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, serverErr)
			close(stderrDone)
		}()

		if drained := drainStderr(stderrDone, serverErr, time.Second); !drained {
			t.Fatal("drainStderr = false after normal stderr drain")
		}
		if _, err := serverErr.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("stderr reader error after normal drain = %v, want os.ErrClosed", err)
		}
	})
}
