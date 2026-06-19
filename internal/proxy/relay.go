// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// hopByHopHeaders are RFC 7230 section 6.1 hop-by-hop headers that must be
// removed when forwarding requests/responses through a proxy.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders strips RFC 7230 section 6.1 hop-by-hop headers
// from an http.Header. Per the RFC, the Connection header value lists
// additional header names that are hop-by-hop for this connection and
// must also be removed before forwarding.
func removeHopByHopHeaders(h http.Header) {
	// Parse Connection header for additional hop-by-hop names.
	// e.g., "Connection: X-Foo, close" means X-Foo is also hop-by-hop.
	if connValues := h.Values("Connection"); len(connValues) > 0 {
		for _, v := range connValues {
			for _, name := range strings.Split(v, ",") {
				name = strings.TrimSpace(name)
				if name != "" {
					h.Del(name)
				}
			}
		}
	}

	// Remove the standard hop-by-hop headers.
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}

// tunnelBufSize is the buffer size for tunnel relay reads.
const tunnelBufSize = 32 * 1024

// watchdogPollInterval is how often the tunnel watchdog re-checks the shared
// idle clock, the absolute deadline, and the kill switch. It is capped at the
// idle timeout so very short idle timeouts still reap promptly.
const watchdogPollInterval = 250 * time.Millisecond

// bidirectionalCopy relays data between two connections until the tunnel goes
// idle, an absolute deadline passes, the kill switch activates, or a side
// closes.
//
// Idle is measured across the WHOLE tunnel via a single shared activity clock:
// bytes flowing in EITHER direction keep the tunnel alive. This is the
// liveness contract long-lived streaming responses depend on (an LLM token
// stream keeps the upstream->client direction busy while client->upstream is
// legitimately silent for the whole response). Measuring idle per-direction
// would reap the silent direction at idle_timeout and half-close the upstream,
// killing the active stream.
//
// A single watchdog owns liveness: it force-closes both connections when the
// shared clock expires (or the deadline/kill switch fires), which wakes any
// blocked read. A genuine EOF on one direction still half-closes the peer so
// bidirectional teardown is preserved; only a spurious idle reap is avoided.
//
// When deadline is non-zero it caps total tunnel lifetime. When ks is non-nil
// the kill switch terminates the tunnel mid-stream. Returns the total bytes
// transferred in both directions.
func bidirectionalCopy(client, target net.Conn, idleTimeout time.Duration, deadline time.Time, ks *killswitch.Controller) int64 {
	now := time.Now()
	tr := &tunnelRelay{
		client:      client,
		target:      target,
		idleTimeout: idleTimeout,
		deadline:    deadline,
		ks:          ks,
		clockStart:  now,
	}
	return tr.run()
}

// tunnelRelay carries the shared state for one bidirectional relay: the two
// connections, the liveness bounds, and the shared activity clock that both
// copy directions update and the watchdog reads.
type tunnelRelay struct {
	client, target net.Conn
	idleTimeout    time.Duration
	deadline       time.Time
	ks             *killswitch.Controller

	clockStart   time.Time
	lastActivity atomic.Int64 // monotonic nanoseconds since clockStart of the last byte seen in either direction
	closeOnce    sync.Once
}

// touch records activity on the shared clock. Called on every successful read
// in either direction so the watchdog treats the tunnel as alive while bytes
// move on either side.
func (tr *tunnelRelay) touch() {
	tr.lastActivity.Store(time.Since(tr.clockStart).Nanoseconds())
}

// closeBoth tears the tunnel down exactly once, closing both connections. This
// is what wakes a read blocked on the silent direction.
func (tr *tunnelRelay) closeBoth() {
	tr.closeOnce.Do(func() {
		_ = tr.client.Close()
		_ = tr.target.Close()
	})
}

func (tr *tunnelRelay) run() int64 {
	done := make(chan struct{})
	go tr.watchdog(done)

	var clientToTarget, targetToClient int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientToTarget = tr.copyDir(tr.target, tr.client)
	}()
	targetToClient = tr.copyDir(tr.client, tr.target)

	wg.Wait()
	close(done)    // stop the watchdog
	tr.closeBoth() // ensure both ends are closed (idempotent)
	return clientToTarget + targetToClient
}

// watchdog owns tunnel liveness. It force-closes both connections when the
// shared idle clock expires, the absolute deadline passes, or the kill switch
// activates, and exits when both copy directions have finished.
func (tr *tunnelRelay) watchdog(done <-chan struct{}) {
	interval := watchdogPollInterval
	if tr.idleTimeout > 0 && tr.idleTimeout < interval {
		interval = tr.idleTimeout
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if tr.ks != nil && tr.ks.IsActive() {
				tr.closeBoth()
				return
			}
			if !tr.deadline.IsZero() && time.Now().After(tr.deadline) {
				tr.closeBoth()
				return
			}
			if tr.idleTimeout > 0 {
				idleFor := time.Since(tr.clockStart) - time.Duration(tr.lastActivity.Load())
				if idleFor >= tr.idleTimeout {
					tr.closeBoth()
					return
				}
			}
		}
	}
}

// copyDir copies src->dst until EOF, error, or the watchdog closes the
// connections. It updates the shared activity clock on every read and checks
// the kill switch before and after each read so a chunk read while the switch
// is flipping is not forwarded. A genuine EOF half-closes the peer (preserving
// bidirectional teardown); any other read/write error tears the tunnel down.
func (tr *tunnelRelay) copyDir(dst, src net.Conn) int64 {
	buf := make([]byte, tunnelBufSize)
	var total int64
	for {
		if tr.ks != nil && tr.ks.IsActive() {
			tr.closeBoth()
			return total
		}
		n, err := src.Read(buf)
		if n > 0 {
			tr.touch()
			if tr.ks != nil && tr.ks.IsActive() {
				tr.closeBoth()
				return total
			}
			written, wErr := dst.Write(buf[:n])
			total += int64(written)
			// A conforming io.Writer never returns written < n without an
			// error, but treat a short write as a teardown anyway (matching
			// io.Copy's ErrShortWrite) so a misbehaving conn cannot silently
			// drop the unwritten bytes when the next read overwrites buf.
			if wErr == nil && written < n {
				wErr = io.ErrShortWrite
			}
			if wErr != nil {
				tr.closeBoth()
				return total
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Genuine end of this direction: signal the peer that no more
				// data is coming, but leave the other direction free to drain.
				if tc, ok := dst.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			} else {
				// Read error (watchdog/airlock close, reset, timeout): tear down.
				tr.closeBoth()
			}
			return total
		}
	}
}
