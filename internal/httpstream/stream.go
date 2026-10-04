// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package httpstream preserves failure semantics after HTTP headers are sent.
package httpstream

import (
	"context"
	"errors"
	"io"
	"net/http"
)

const (
	Incomplete = "incomplete"
	Cancelled  = "stream_cancelled"
)

type clientWriteError struct{ error }

func (e clientWriteError) Unwrap() error { return e.error }

// Writer tags downstream write errors so they cannot be attributed to the
// upstream. It intentionally hides ReaderFrom to keep copy errors distinguishable.
type Writer struct{ io.Writer }

func (w Writer) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		err = clientWriteError{err}
	}
	return n, err
}

// Copy preserves the origin of an error while streaming a response body.
func Copy(w io.Writer, r io.Reader) (int64, error) {
	return io.Copy(Writer{w}, r)
}

// Reason distinguishes a client that went away from an incomplete upstream
// response. Consult the downstream context, not an upstream timeout's error.
func Reason(ctx context.Context, err error) string {
	var writeErr clientWriteError
	if ctx.Err() != nil || errors.As(err, &writeErr) {
		return Cancelled
	}
	return Incomplete
}

// Abort prevents net/http from emitting a clean end of body after a failed
// stream. Callers must record their outcome before calling Abort. Under an HTTP
// server, the sentinel panic closes HTTP/1 connections or resets HTTP/2 streams,
// including a server serving a hijacked CONNECT TLS connection. Without a server
// in the request context, Abort returns err so direct handler callers can stop
// processing without a panic.
func Abort(ctx context.Context, err error) error {
	if err != nil && ctx.Value(http.ServerContextKey) != nil {
		panic(http.ErrAbortHandler)
	}
	return err
}
