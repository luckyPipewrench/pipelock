// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"io"
	"sync"
	"time"
)

// ErrUpstreamIdleTimeout reports that an upstream sent response headers and then
// stopped producing body bytes for longer than the idle budget.
var ErrUpstreamIdleTimeout = errors.New("upstream response stalled")

// idleTimeoutReader bounds the gap BETWEEN reads rather than the total lifetime
// of a response body.
//
// The upstream client deliberately carries no total timeout, because protocol
// revision 2026-07-28 replaces the GET notification endpoint with
// subscriptions/listen: a single long-lived POST response body that a total
// timeout would sever on a fixed schedule no matter how healthy it was. That
// leaves the opposite hazard, which is an upstream that sends headers promptly
// and then holds the body open forever, pinning a goroutine and both
// connections.
//
// An idle budget resolves both: a healthy stream keeps producing events, so the
// timer keeps resetting and the stream is never cut, while a stalled upstream
// trips it. This mirrors the per-read deadline the stdio transport already
// applies to upstream responses, where the same reasoning produced the same
// shape.
//
// It bounds a STALL, not a slow drip: an upstream trickling a byte inside every
// window still proceeds. Total volume is bounded separately by the response
// size limits, so the pair covers both shapes.
type idleTimeoutReader struct {
	inner  io.ReadCloser
	budget time.Duration

	mu    sync.Mutex
	timer *time.Timer
	// closed records that the underlying body has been closed by either party.
	// timedOut records that the IDLE TIMER closed it, which is the only case
	// that should surface as a stall: Close sets closed too, and reporting a
	// caller hang-up as an upstream timeout would misattribute the fault.
	closed   bool
	timedOut bool
}

// newIdleTimeoutReader wraps body so a gap between reads longer than budget
// closes the underlying body and surfaces ErrUpstreamIdleTimeout. A budget of
// zero or less returns body unchanged.
func newIdleTimeoutReader(body io.ReadCloser, budget time.Duration) io.ReadCloser {
	if body == nil || budget <= 0 {
		return body
	}
	r := &idleTimeoutReader{inner: body, budget: budget}
	r.timer = time.AfterFunc(budget, r.trip)
	return r
}

// trip closes the underlying body so a blocked Read returns instead of hanging.
func (r *idleTimeoutReader) trip() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.timedOut = true
	_ = r.inner.Close()
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)

	r.mu.Lock()
	tripped := r.timedOut
	if !r.closed && r.timer != nil {
		// Progress resets the budget, so a steady stream is never severed.
		r.timer.Reset(r.budget)
	}
	r.mu.Unlock()

	if tripped && err != nil {
		// The close came from the idle timer, so report why rather than
		// surfacing a generic use-of-closed-connection error.
		//
		// This deliberately covers io.EOF. A ReadCloser is entitled to report
		// EOF once closed, and forwarding that would present a stalled,
		// truncated response to the caller as a clean end of stream, which is
		// precisely the failure the idle budget exists to catch.
		return n, ErrUpstreamIdleTimeout
	}
	return n, err
}

func (r *idleTimeoutReader) Close() error {
	r.mu.Lock()
	if r.timer != nil {
		r.timer.Stop()
	}
	alreadyClosed := r.closed
	r.closed = true
	r.mu.Unlock()

	if alreadyClosed {
		return nil
	}
	return r.inner.Close()
}
