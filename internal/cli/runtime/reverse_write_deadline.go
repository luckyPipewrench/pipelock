// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/http"
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
)

// newReverseProxyServer builds the reverse proxy listener. http.Server's
// WriteTimeout starts when the request headers are read and covers the whole
// handler, so a fixed 30 second value cut off any response whose upstream
// fetch plus buffered scan took longer than that: a clean 48 MiB response from
// a size-exempt host scanned for about 33 seconds and the client got an empty
// reply. The server-wide timeout is therefore off and the stall deadline is
// armed per write by withWriteProgressDeadline, which keeps slow-reader
// protection without bounding how long the scan may take. The response size
// ceiling is enforced by the handler and is unchanged.
func newReverseProxyServer(handler http.Handler) *http.Server {
	return newReverseProxyServerWithStall(handler, reverseProxyWriteStallTimeout)
}

func newReverseProxyServerWithStall(handler http.Handler, stall time.Duration) *http.Server {
	srv := newHTTPServer(withWriteProgressDeadline(handler, stall))
	srv.WriteTimeout = 0
	return srv
}

// withWriteProgressDeadline wraps handler so every write toward the client
// must make progress within stall. No deadline is armed while the handler is
// still working before its first write. net/http clears the connection's write
// deadline after each request, so none carries over to a keep-alive successor.
func withWriteProgressDeadline(handler http.Handler, stall time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		pw := &progressDeadlineWriter{ResponseWriter: w, rc: rc, stall: stall}
		// The server flushes the buffered tail after the handler returns;
		// keep that final flush under the stall bound as well.
		defer pw.arm()
		handler.ServeHTTP(pw, r)
	})
}

type progressDeadlineWriter struct {
	http.ResponseWriter
	rc    *http.ResponseController
	stall time.Duration
}

func (w *progressDeadlineWriter) arm() {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.stall))
}

// Write forwards b in bounded chunks, re-arming the stall deadline before
// each so a large body to a client that keeps reading is not cut off.
func (w *progressDeadlineWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		w.arm()
		return w.ResponseWriter.Write(b)
	}
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > reverseProxyWriteChunk {
			chunk = chunk[:reverseProxyWriteChunk]
		}
		w.arm()
		n, err := w.ResponseWriter.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		b = b[len(chunk):]
	}
	return written, nil
}

// Flush re-arms the stall deadline and flushes through the underlying writer.
func (w *progressDeadlineWriter) Flush() {
	w.arm()
	_ = w.rc.Flush()
}

// Unwrap lets http.ResponseController (used by httputil.ReverseProxy for
// flushing and protocol upgrades) reach the real connection.
func (w *progressDeadlineWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
