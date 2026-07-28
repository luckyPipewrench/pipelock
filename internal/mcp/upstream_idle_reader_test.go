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
	first    []byte
	sent     bool
	release  chan struct{}
	closedCh chan struct{}
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

// The budget must bound the GAP between reads, not the total lifetime, or it
// reintroduces the severed-stream bug the total timeout caused.
func TestIdleTimeoutReader_DoesNotCutASteadyStream(t *testing.T) {
	chunks := 8
	gap := 40 * time.Millisecond
	reader := newIdleTimeoutReader(io.NopCloser(&tickingReader{
		remaining: chunks,
		gap:       gap,
		chunk:     []byte("data: {}\n\n"),
	}), 150*time.Millisecond)
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
	// implementation would have failed here.
	if total == 0 {
		t.Fatal("read no bytes from a steady stream")
	}
}

type tickingReader struct {
	remaining int
	gap       time.Duration
	chunk     []byte
}

func (r *tickingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	r.remaining--
	timer := time.NewTimer(r.gap)
	<-timer.C
	timer.Stop()
	return copy(p, r.chunk), nil
}

func TestIdleTimeoutReader_ZeroBudgetIsPassthrough(t *testing.T) {
	inner := io.NopCloser(strings.NewReader("hello"))
	if got := newIdleTimeoutReader(inner, 0); got != inner {
		t.Error("zero budget should return the body unchanged")
	}
}
