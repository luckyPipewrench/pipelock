// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
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

	var stdout, logBuf bytes.Buffer
	opts := MCPProxyOpts{
		sessionExitForTest: &sessionExitTestHooks{
			watch: parentWatchOpts{
				interval:  time.Millisecond,
				startPPID: 4242,
				getppid:   func() int { return orphanedPPID },
			},
			grace: 50 * time.Millisecond,
		},
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
	case <-done:
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
	var stdout, logBuf bytes.Buffer

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
