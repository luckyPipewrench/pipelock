// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

// upstreamBodyStallTransport bounds how long an upstream response body may go
// without delivering a byte. The reverse listener has no server-wide write
// timeout, and the response-header timeout ends once headers arrive, so an
// upstream that sends headers and then stops would otherwise hold a handler
// and its connection for as long as it likes while the response is buffered
// for scanning. Each read that returns data restarts the window; when it
// expires the request context is canceled, which ends the pending read.
//
// Protocol upgrades and server-sent event streams are exempt: both are
// long-lived by design and may be idle between messages.
type upstreamBodyStallTransport struct {
	base  http.RoundTripper
	stall time.Duration
}

func (t *upstreamBodyStallTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return resp, err
	}
	// Downstream code reads resp.Request.Context() for request-scoped state
	// and runs the response scan under it after closing the upstream body.
	// The derived context exists only to abort the upstream read, so hand back
	// the caller's request, whose context outlives the body.
	resp.Request = req
	if resp.Body == nil {
		cancel()
		return resp, nil
	}
	// A long-lived response owns the context for its lifetime; releasing it
	// here would cut it off. It is released when the body closes. An upgraded
	// body must stay an io.ReadWriteCloser, which the reverse proxy requires
	// to take over the connection.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
			resp.Body = &cancelOnCloseRW{ReadWriteCloser: rw, cancel: cancel}
			return resp, nil
		}
		resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	if isEventStream(resp.Header.Get("Content-Type")) {
		resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	resp.Body = &stallBoundBody{
		ReadCloser: resp.Body,
		cancel:     cancel,
		timer:      time.AfterFunc(t.stall, cancel),
		stall:      t.stall,
	}
	return resp, nil
}

func isEventStream(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "text/event-stream"
}

// cancelOnClose releases the request context when the body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// cancelOnCloseRW is cancelOnClose for an upgraded connection body.
type cancelOnCloseRW struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseRW) Close() error {
	err := b.ReadWriteCloser.Close()
	b.cancel()
	return err
}

// stallBoundBody cancels the upstream request when no byte arrives within
// stall of the previous one.
type stallBoundBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	timer  *time.Timer
	stall  time.Duration
	once   sync.Once
}

func (b *stallBoundBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && err == nil {
		b.timer.Reset(b.stall)
	}
	return n, err
}

func (b *stallBoundBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		b.timer.Stop()
		b.cancel()
	})
	return err
}
