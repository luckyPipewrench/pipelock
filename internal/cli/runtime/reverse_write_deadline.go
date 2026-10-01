// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// reverseProxyWriteStallTimeout is how long the reverse proxy listener
	// waits on a client that stops reading before it gives up on the
	// connection. It applies to each write toward the client, never to the
	// time spent fetching and scanning the upstream response.
	reverseProxyWriteStallTimeout = 30 * time.Second

	// reverseProxyWriteChunk is the largest slice handed to the connection in
	// one write. A buffered response can be tens of MiB; one write that large
	// would have to finish inside a single stall window, so a slow but live
	// client would be cut off. Chunking lets the window restart on progress.
	reverseProxyWriteChunk = 1 << 20

	// reverseProxyWriteTotalBudget is the hard ceiling on how long one response
	// may spend being written to the client, measured from its first write. The
	// stall window restarts on every write, so a client that drains a chunk
	// just inside it could otherwise hold the connection forever. Scan and
	// upstream time happen before the first write and are not counted. Ten
	// minutes lets the documented 64 MiB response ceiling finish at about
	// 110 KiB/s (under 1 Mbit/s), far below what a live client sustains, while
	// bounding a drip reader to a fixed cost.
	reverseProxyWriteTotalBudget = 10 * time.Minute

	// reverseProxyMaxConns caps concurrent connections on the reverse listener
	// so a flood of slow readers cannot exhaust file descriptors. Excess
	// connections wait in the accept backlog until a slot frees.
	reverseProxyMaxConns = 4096
)

var errReverseWriteBudget = errors.New("reverse proxy response exceeded its total write budget")

// newReverseProxyServer builds the reverse proxy listener. http.Server's
// WriteTimeout starts when the request headers are read and covers the whole
// handler, so a fixed 30 second value cut off any response whose upstream
// fetch plus buffered scan took longer than that: a clean 48 MiB response from
// a size-exempt host scanned for about 33 seconds and the client got an empty
// reply. The server-wide timeout is therefore off and the deadline is armed
// per write by withWriteProgressDeadline: a per-chunk stall window plus a hard
// total budget that the stall window can never extend past. Neither bounds how
// long the scan may take; a silent upstream is bounded by the reverse
// transport's response-header timeout. The response size ceiling is enforced
// by the handler and is unchanged.
func newReverseProxyServer(handler http.Handler) *http.Server {
	return newReverseProxyServerWithLimits(handler, reverseProxyWriteStallTimeout, reverseProxyWriteTotalBudget)
}

func newReverseProxyServerWithStall(handler http.Handler, stall time.Duration) *http.Server {
	return newReverseProxyServerWithLimits(handler, stall, reverseProxyWriteTotalBudget)
}

func newReverseProxyServerWithLimits(handler http.Handler, stall, total time.Duration) *http.Server {
	srv := newHTTPServer(withWriteProgressDeadline(handler, stall, total))
	srv.WriteTimeout = 0
	return srv
}

// withWriteProgressDeadline wraps handler so every write toward the client
// must make progress within stall and the whole response must finish within
// total of its first write. No deadline is armed while the handler is still
// working before its first write. net/http clears the connection's write
// deadline after each request, so none carries over to a keep-alive successor.
func withWriteProgressDeadline(handler http.Handler, stall, total time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		pw := &progressDeadlineWriter{ResponseWriter: w, rc: rc, stall: stall, total: total}
		// The server flushes the buffered tail after the handler returns;
		// keep that final flush under the same bounds.
		defer func() { _ = pw.arm() }()
		handler.ServeHTTP(pw, r)
	})
}

type progressDeadlineWriter struct {
	http.ResponseWriter
	rc    *http.ResponseController
	stall time.Duration
	total time.Duration
	end   time.Time // hard end of the response's write budget; zero until the first arm
}

// arm sets the connection write deadline to the earlier of now+stall and the
// total budget end. It fails closed: a refused deadline or an exhausted budget
// returns an error and the caller must not write.
func (w *progressDeadlineWriter) arm() error {
	now := time.Now()
	if w.end.IsZero() {
		w.end = now.Add(w.total)
	}
	deadline := now.Add(w.stall)
	if deadline.After(w.end) {
		deadline = w.end
	}
	// Set even when the budget is spent: a past deadline makes the pending
	// final flush fail instead of running unbounded.
	if err := w.rc.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if !now.Before(w.end) {
		return errReverseWriteBudget
	}
	return nil
}

// Write forwards b in bounded chunks, re-arming the stall deadline before
// each so a large body to a client that keeps reading is not cut off, but
// never past the total budget.
func (w *progressDeadlineWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		if err := w.arm(); err != nil {
			return 0, err
		}
		return w.ResponseWriter.Write(b)
	}
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > reverseProxyWriteChunk {
			chunk = chunk[:reverseProxyWriteChunk]
		}
		if err := w.arm(); err != nil {
			return written, err
		}
		n, err := w.ResponseWriter.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		b = b[n:]
	}
	return written, nil
}

// Flush re-arms the deadline and flushes through the underlying writer. A
// failed arm skips the flush: Flush has no error return, and the next Write
// reports the same failure.
func (w *progressDeadlineWriter) Flush() {
	if err := w.arm(); err != nil {
		return
	}
	_ = w.rc.Flush()
}

// Unwrap lets http.ResponseController (used by httputil.ReverseProxy for
// flushing and protocol upgrades) reach the real connection.
func (w *progressDeadlineWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// limitListener bounds concurrent accepted connections.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

// Close also releases an Accept blocked on a full semaphore, so a graceful
// shutdown is not held up by the cap.
func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
