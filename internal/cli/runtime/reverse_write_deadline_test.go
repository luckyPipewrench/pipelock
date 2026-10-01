// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const reverseWriteTestStall = 150 * time.Millisecond

func serveReverseTestHandler(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newReverseProxyServerWithStall(handler, reverseWriteTestStall)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func reverseTestGet(addr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func TestNewReverseProxyServer_HasNoServerWideWriteTimeout(t *testing.T) {
	srv := newReverseProxyServer(http.NotFoundHandler())
	if srv.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %v, want 0: a server-wide value cuts off slow upstream fetches and buffered scans", srv.WriteTimeout)
	}
	if srv.ReadHeaderTimeout != serverReadHeaderTimeout || srv.ReadTimeout != serverReadTimeout || srv.IdleTimeout != serverIdleTimeout {
		t.Fatalf("read/idle timeouts changed: header=%v read=%v idle=%v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.IdleTimeout)
	}
}

// A response that is not ready until well after the stall window must still be
// delivered whole: the window covers writes to the client, not upstream and
// scan time.
func TestReverseProxyServer_ResponseSlowerThanStallWindowIsDelivered(t *testing.T) {
	const size = 3 << 20
	addr := serveReverseTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream/scan latency longer than the stall window, bounded by a timer
		// and abandoned if the client goes away.
		select {
		case <-time.After(4 * reverseWriteTestStall):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("a", size)))
	}))

	resp, err := reverseTestGet(addr)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n != size {
		t.Fatalf("read %d bytes, err=%v; want %d bytes and no error", n, err, size)
	}
}

// A client that stops reading mid-response must not pin the connection past
// the stall window.
func TestReverseProxyServer_StalledReaderIsCutOff(t *testing.T) {
	writeErr := make(chan error, 1)
	addr := serveReverseTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := []byte(strings.Repeat("b", 1<<20))
		for i := 0; i < 512; i++ {
			if _, err := w.Write(chunk); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}))

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("send request: %v", err)
	}
	// Never read: the 512 MiB response cannot fit in the socket buffers.
	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("handler wrote 512 MiB to a client that never read; stalled reader was not cut off")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stalled reader was not cut off within 10s")
	}
}

// httputil.ReverseProxy flushes and upgrades through http.ResponseController,
// so the wrapper must stay transparent to it.
func TestReverseProxyServer_WriterStaysFlushableAndUnwrappable(t *testing.T) {
	got := make(chan [3]bool, 1)
	addr := serveReverseTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, isFlusher := w.(http.Flusher)
		_, hasUnwrap := w.(interface{ Unwrap() http.ResponseWriter })
		rcErr := http.NewResponseController(w).Flush()
		got <- [3]bool{isFlusher, hasUnwrap, rcErr == nil}
		_, _ = io.WriteString(w, "ok")
	}))

	resp, err := reverseTestGet(addr)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if res := <-got; res != [3]bool{true, true, true} {
		t.Fatalf("flusher/unwrap/controller-flush = %v, want all true", res)
	}
}

// Every write here lands well inside the stall window, so the stall re-arms
// forever (a drip reader, or a slow SSE stream, does the same); only the total
// budget can end the response.
func TestReverseProxyServer_DripReaderIsCutOffByTotalBudget(t *testing.T) {
	const budget = 500 * time.Millisecond
	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newReverseProxyServerWithLimits(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		start := time.Now()
		chunk := []byte(strings.Repeat("c", 1<<10))
		for i := 0; i < 200; i++ { // about 6s of drip, 12x the budget
			if _, err := w.Write(chunk); err != nil {
				done <- result{err, time.Since(start)}
				return
			}
			_ = http.NewResponseController(w).Flush()
			pace := time.NewTimer(30 * time.Millisecond) // drip cadence, inside the stall window
			<-pace.C
		}
		done <- result{nil, time.Since(start)}
	}), reverseWriteTestStall, budget)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	resp, err := reverseTestGet(ln.Addr().String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	go func() { _, _ = io.Copy(io.Discard, resp.Body) }()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("handler dripped for %v without being cut off; total budget %v did not apply", r.elapsed, budget)
		}
		if r.elapsed > 3*time.Second {
			t.Fatalf("cut off after %v, want about the %v budget", r.elapsed, budget)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("drip response was not cut off within 15s")
	}
}

type deadlineTestWriter struct {
	http.ResponseWriter
	setErr   error
	maxWrite int // when > 0, accept at most this many bytes per Write, with a nil error
	got      int
}

func (d *deadlineTestWriter) SetWriteDeadline(time.Time) error { return d.setErr }

func (d *deadlineTestWriter) Write(b []byte) (int, error) {
	if d.maxWrite > 0 && len(b) > d.maxWrite {
		b = b[:d.maxWrite]
	}
	d.got += len(b)
	return len(b), nil
}

func TestProgressDeadlineWriter_RefusedDeadlineAbortsWrite(t *testing.T) {
	inner := &deadlineTestWriter{ResponseWriter: httptest.NewRecorder(), setErr: errors.New("no deadlines here")}
	pw := &progressDeadlineWriter{ResponseWriter: inner, rc: http.NewResponseController(inner), stall: time.Second, total: time.Minute}
	if n, err := pw.Write([]byte("data")); err == nil || n != 0 || inner.got != 0 {
		t.Fatalf("Write = (%d, %v), inner got %d; want an error and nothing written", n, err, inner.got)
	}
}

func TestProgressDeadlineWriter_ExhaustedBudgetAbortsWrite(t *testing.T) {
	inner := &deadlineTestWriter{ResponseWriter: httptest.NewRecorder()}
	pw := &progressDeadlineWriter{ResponseWriter: inner, rc: http.NewResponseController(inner), stall: time.Second, total: time.Minute}
	if n, err := pw.Write([]byte("ok")); err != nil || n != 2 {
		t.Fatalf("first Write = (%d, %v), want (2, nil)", n, err)
	}
	pw.end = time.Now().Add(-time.Second)
	if _, err := pw.Write([]byte("late")); !errors.Is(err, errReverseWriteBudget) {
		t.Fatalf("Write past the budget err = %v, want errReverseWriteBudget", err)
	}
	if inner.got != 2 {
		t.Fatalf("inner got %d bytes, want 2", inner.got)
	}
}

func TestProgressDeadlineWriter_AdvancesByBytesWritten(t *testing.T) {
	inner := &deadlineTestWriter{ResponseWriter: httptest.NewRecorder(), maxWrite: 1000}
	pw := &progressDeadlineWriter{ResponseWriter: inner, rc: http.NewResponseController(inner), stall: time.Second, total: time.Minute}
	payload := make([]byte, 2500)
	n, err := pw.Write(payload)
	if err != nil || n != len(payload) || inner.got != len(payload) {
		t.Fatalf("Write = (%d, %v), inner got %d; want all %d bytes exactly once", n, err, inner.got, len(payload))
	}
}

func TestLimitListener_CapsConcurrentConnectionsAndReleasesOnClose(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := newLimitListener(base, 1)
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() {
		c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", base.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	dial()
	first := <-accepted
	dial()
	select {
	case <-accepted:
		t.Fatal("second connection accepted while the cap of 1 was full")
	case <-time.After(200 * time.Millisecond):
	}
	_ = first.Close()
	_ = first.Close() // double close must release once
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("second connection not accepted after the first closed")
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// The stall window must never push a blocked write's deadline past the total
// budget: with a long stall and a short budget, a client that stops reading is
// cut off at the budget.
func TestReverseProxyServer_BlockedWriteDeadlineClampedToBudget(t *testing.T) {
	const budget = 400 * time.Millisecond
	done := make(chan time.Duration, 1)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newReverseProxyServerWithLimits(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		start := time.Now()
		chunk := []byte(strings.Repeat("d", 1<<20))
		for i := 0; i < 512; i++ {
			if _, err := w.Write(chunk); err != nil {
				done <- time.Since(start)
				return
			}
		}
		done <- 0
	}), time.Minute, budget)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("send request: %v", err)
	}
	select {
	case elapsed := <-done:
		if elapsed == 0 || elapsed > 5*time.Second {
			t.Fatalf("blocked write ended after %v, want about the %v budget", elapsed, budget)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("blocked write outlived the total budget: stall window extended past it")
	}
}
