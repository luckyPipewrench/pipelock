// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"io"
	"time"
)

// ErrResponseTimeout is returned when a TimeoutReader's per-read deadline
// expires before the underlying reader delivers a message. Fail-closed:
// the proxy emits a JSON-RPC error to the client rather than hanging.
var ErrResponseTimeout = errors.New("upstream response timeout")

// ReadResult holds the outcome of a single ReadMessage call. Exported so
// test helpers in other packages can build channel-based message readers.
type ReadResult struct {
	Msg []byte
	Err error
}

// TimeoutReader wraps a MessageReader with a per-read deadline. If the
// underlying reader does not return within the configured timeout, the
// read returns ErrResponseTimeout. A zero or negative timeout disables
// the deadline (passthrough).
//
// Implementation: each ReadMessage call runs the delegate in a goroutine
// when no prior read is outstanding. When a timeout fires, the goroutine
// remains blocked on the inner reader; the next ReadMessage call reuses
// the same channel, so the late result is consumed without spawning a
// second concurrent read.
type TimeoutReader struct {
	inner   MessageReader
	timeout time.Duration

	// inflight is non-nil when a background read goroutine is still waiting
	// on the inner reader from a previous timed-out call.
	inflight chan ReadResult
}

// NewTimeoutReader creates a TimeoutReader. A zero timeout disables the
// deadline (every call delegates directly without a goroutine).
func NewTimeoutReader(inner MessageReader, timeout time.Duration) *TimeoutReader {
	return &TimeoutReader{
		inner:   inner,
		timeout: timeout,
	}
}

// ReadMessage reads the next message, returning ErrResponseTimeout if the
// underlying reader does not respond within the configured deadline.
func (tr *TimeoutReader) ReadMessage() ([]byte, error) {
	if tr.timeout <= 0 {
		return tr.inner.ReadMessage()
	}

	// Reuse the channel from a prior timed-out read if one is still in flight.
	ch := tr.inflight
	if ch == nil {
		ch = make(chan ReadResult, 1)
		go func() {
			msg, err := tr.inner.ReadMessage()
			ch <- ReadResult{Msg: msg, Err: err}
		}()
	}
	tr.inflight = nil // consumed; will be re-set below if we time out again

	timer := time.NewTimer(tr.timeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		return r.Msg, r.Err
	case <-timer.C:
		// The goroutine is still blocked on inner.ReadMessage. Keep the
		// channel so the next call drains its result, or so Close() can
		// release the underlying reader to unblock it.
		tr.inflight = ch
		return nil, ErrResponseTimeout
	}
}

// Close releases the wrapped reader when it implements io.Closer. Callers use
// this after an ErrResponseTimeout to abort the in-flight read: closing the
// underlying body makes the background ReadMessage goroutine's blocked read
// return, so it drains instead of leaking. No-op when the inner reader is not
// a Closer.
func (tr *TimeoutReader) Close() error {
	if c, ok := tr.inner.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
