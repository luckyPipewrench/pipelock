// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"io"
	"net"
	"net/http"
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
	addr := serveReverseTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(4 * reverseWriteTestStall)
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
