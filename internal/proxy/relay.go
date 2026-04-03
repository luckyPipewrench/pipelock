// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/http"
	"strings"
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

// bidirectionalCopy relays data between two connections with idle timeout.
// The deadline is an absolute time computed once in handleConnect so the total
// tunnel lifetime (including dial) never exceeds max_tunnel_seconds.
// When ks is non-nil, the kill switch is checked after each read so activation
// mid-stream terminates already-open tunnels immediately.
// Returns the total bytes transferred in both directions.
func bidirectionalCopy(client, target net.Conn, idleTimeout time.Duration, deadline time.Time, ks *killswitch.Controller) int64 {
	_ = client.SetDeadline(deadline)
	_ = target.SetDeadline(deadline)

	var clientToTarget, targetToClient int64
	done := make(chan struct{})

	go func() {
		clientToTarget = copyWithIdleTimeout(target, client, idleTimeout, deadline, ks)
		// Half-close: signal target that no more data is coming
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		close(done)
	}()

	targetToClient = copyWithIdleTimeout(client, target, idleTimeout, deadline, ks)
	// Half-close: signal client that no more data is coming
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	<-done
	return clientToTarget + targetToClient
}

// tunnelBufSize is the buffer size for tunnel relay reads.
const tunnelBufSize = 32 * 1024

// copyWithIdleTimeout copies from src to dst, resetting the read deadline
// on src after each successful read. The per-read deadline is capped at the
// absolute deadline so tunnels cannot exceed max_tunnel_seconds while active.
// When ks is non-nil, the kill switch is checked after each successful read
// so activation mid-tunnel terminates the connection immediately.
// Returns total bytes copied.
func copyWithIdleTimeout(dst, src net.Conn, idleTimeout time.Duration, deadline time.Time, ks *killswitch.Controller) int64 {
	buf := make([]byte, tunnelBufSize)
	var total int64
	for {
		// Kill switch: terminate tunnel immediately when activated mid-stream.
		if ks != nil && ks.IsActive() {
			return total
		}

		rd := time.Now().Add(idleTimeout)
		if rd.After(deadline) {
			rd = deadline
		}
		_ = src.SetReadDeadline(rd)
		n, err := src.Read(buf)
		if n > 0 {
			written, wErr := dst.Write(buf[:n])
			total += int64(written)
			if wErr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}
