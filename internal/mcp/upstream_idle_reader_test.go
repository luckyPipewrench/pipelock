// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// stallingBody produces one chunk then blocks until released, standing in for an
// upstream that sends headers and then holds the body open.
type stallingBody struct {
	first      []byte
	sent       bool
	eofOnClose bool
	release    chan struct{}
	closedCh   chan struct{}
}

func (b *stallingBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, b.first), nil
	}
	select {
	case <-b.release:
		return 0, io.EOF
	case <-b.closedCh:
		// A ReadCloser is entitled to report EOF once closed. If the wrapper
		// forwards that, a caller reads a truncated stream as a clean end.
		if b.eofOnClose {
			return 0, io.EOF
		}
		return 0, errors.New("read on closed body")
	}
}

func (b *stallingBody) Close() error {
	select {
	case <-b.closedCh:
	default:
		close(b.closedCh)
	}
	return nil
}

// Removing the total client timeout so subscriptions/listen can stream leaves an
// upstream free to send headers and then hold the body open forever, pinning a
// goroutine and both connections. The idle budget has to trip on that.
func TestIdleTimeoutReader_TripsOnStalledUpstream(t *testing.T) {
	body := &stallingBody{first: []byte("data: {}\n\n"), release: make(chan struct{}), closedCh: make(chan struct{})}
	reader := newIdleTimeoutReader(body, 100*time.Millisecond)
	defer func() { _ = reader.Close() }()

	buf := make([]byte, 64)
	if _, err := reader.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}

	start := time.Now()
	_, err := reader.Read(buf)
	if err == nil {
		t.Fatal("stalled upstream read returned no error")
	}
	if !errors.Is(err, ErrUpstreamIdleTimeout) {
		t.Errorf("err = %v, want ErrUpstreamIdleTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to trip a 100ms idle budget", elapsed)
	}
}

// A body that reports io.EOF once closed must not let a stalled stream look
// like a clean end. Returning EOF here would have the caller accept a truncated
// response as complete, which is the failure the idle budget exists to catch.
func TestIdleTimeoutReader_EOFAfterTripStillReportsTimeout(t *testing.T) {
	body := &stallingBody{
		first:      []byte("data: {}\n\n"),
		eofOnClose: true,
		release:    make(chan struct{}),
		closedCh:   make(chan struct{}),
	}
	reader := newIdleTimeoutReader(body, 100*time.Millisecond)
	defer func() { _ = reader.Close() }()

	buf := make([]byte, 64)
	if _, err := reader.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}

	_, err := reader.Read(buf)
	if errors.Is(err, io.EOF) {
		t.Fatal("stalled stream reported io.EOF: the caller would accept a truncated response as complete")
	}
	if !errors.Is(err, ErrUpstreamIdleTimeout) {
		t.Errorf("err = %v, want ErrUpstreamIdleTimeout", err)
	}
}

// Close sets the same closed flag the idle timer does, so a caller closing the
// body mid-read must not be reported as a stall. Misreporting it would have an
// ordinary cancellation surface as an upstream fault, and would make a genuine
// timeout indistinguishable from a caller hanging up.
func TestIdleTimeoutReader_CallerCloseIsNotATimeout(t *testing.T) {
	body := &stallingBody{
		first:    []byte("data: {}\n\n"),
		release:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}
	// A budget long enough that it cannot plausibly fire during this test.
	reader := newIdleTimeoutReader(body, time.Hour)

	buf := make([]byte, 64)
	if _, err := reader.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_ = reader.Close()
	}()
	<-closed

	_, err := reader.Read(buf)
	if errors.Is(err, ErrUpstreamIdleTimeout) {
		t.Error("caller-initiated Close reported as an idle timeout")
	}
}

// The budget must bound the GAP between reads, not the total lifetime, or it
// reintroduces the severed-stream bug the total timeout caused.
func TestIdleTimeoutReader_DoesNotCutASteadyStream(t *testing.T) {
	const chunks = 8
	gap := 40 * time.Millisecond
	chunk := []byte("data: {}\n\n")
	// Close-aware rather than io.NopCloser: a premature close must be
	// detectable, or a total-lifetime timer would pass this test.
	body := &tickingReader{remaining: chunks, gap: gap, chunk: chunk, closedCh: make(chan struct{})}
	reader := newIdleTimeoutReader(body, 150*time.Millisecond)
	defer func() { _ = reader.Close() }()

	buf := make([]byte, 64)
	total := 0
	for {
		n, err := reader.Read(buf)
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("steady stream cut after %d bytes: %v", total, err)
		}
	}
	// Total lifetime is ~320ms, well past the 150ms budget, so a total-timeout
	// implementation would have failed here. Require every chunk: "some bytes
	// arrived" would also accept a stream cut after the first.
	if want := chunks * len(chunk); total != want {
		t.Fatalf("read %d bytes from a steady stream, want %d: the stream was cut short", total, want)
	}
	if body.closedEarly() {
		t.Error("steady stream body was closed by the idle budget")
	}
}

type tickingReader struct {
	remaining int
	gap       time.Duration
	chunk     []byte
	closedCh  chan struct{}
	drained   bool
}

func (r *tickingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		r.drained = true
		return 0, io.EOF
	}
	r.remaining--
	timer := time.NewTimer(r.gap)
	<-timer.C
	timer.Stop()
	return copy(p, r.chunk), nil
}

func (r *tickingReader) Close() error {
	select {
	case <-r.closedCh:
	default:
		close(r.closedCh)
	}
	return nil
}

// closedEarly reports a close that arrived before the stream was drained.
func (r *tickingReader) closedEarly() bool {
	select {
	case <-r.closedCh:
		return !r.drained
	default:
		return false
	}
}

func TestIdleTimeoutReader_ZeroBudgetIsPassthrough(t *testing.T) {
	inner := io.NopCloser(strings.NewReader("hello"))
	if got := newIdleTimeoutReader(inner, 0); got != inner {
		t.Error("zero budget should return the body unchanged")
	}
}
