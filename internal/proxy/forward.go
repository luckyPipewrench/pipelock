package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxConcurrentTunnels = 1024
	tunnelBufSize        = 32 * 1024 // 32KB copy buffer
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

// tunnelSemaphore limits concurrent CONNECT tunnels.
type tunnelSemaphore struct {
	ch chan struct{}
}

func newTunnelSemaphore(capacity int) *tunnelSemaphore {
	return &tunnelSemaphore{ch: make(chan struct{}, capacity)}
}

func (s *tunnelSemaphore) TryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *tunnelSemaphore) Release() {
	<-s.ch
}

// tunnelSem is the global semaphore for concurrent CONNECT tunnels.
// Initialized lazily on first use to avoid allocation when forward proxy is disabled.
var (
	tunnelSem     *tunnelSemaphore
	tunnelSemOnce sync.Once
)

func getTunnelSemaphore() *tunnelSemaphore {
	tunnelSemOnce.Do(func() {
		tunnelSem = newTunnelSemaphore(maxConcurrentTunnels)
	})
	return tunnelSem
}

// handleConnect handles HTTP CONNECT tunnel requests. It scans the target
// hostname through the full scanner pipeline, establishes a TCP connection
// via the SSRF-safe dialer, and relays data bidirectionally.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cfg := p.cfgPtr.Load()
	sc := p.scannerPtr.Load()

	clientIP, requestID := requestMeta(r)

	target := r.Host
	if target == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}

	// Ensure target has a port. CONNECT targets are always host:port.
	// Strip brackets from bare IPv6 literals before JoinHostPort adds them back.
	if _, _, err := net.SplitHostPort(target); err != nil {
		bare := strings.TrimPrefix(strings.TrimSuffix(target, "]"), "[")
		target = net.JoinHostPort(bare, "443")
	}

	// Synthesize a URL for scanner pipeline. The scanner expects a full URL,
	// but CONNECT only gives us host:port. Use https:// as the tunnel is
	// typically used for TLS traffic.
	host, _, _ := net.SplitHostPort(target)
	syntheticHost := host
	if strings.Contains(host, ":") { // IPv6 literal needs brackets in URL
		syntheticHost = "[" + host + "]"
	}
	syntheticURL := "https://" + syntheticHost + "/"

	// Scan through all 9 layers
	result := sc.Scan(syntheticURL)
	if !result.Allowed {
		if cfg.EnforceEnabled() {
			p.logger.LogBlocked(http.MethodConnect, target, result.Scanner, result.Reason, clientIP, requestID)
			p.metrics.RecordTunnelBlocked()
			http.Error(w, "CONNECT blocked: "+result.Reason, http.StatusForbidden)
			return
		}
		// Audit mode: log anomaly but allow through
		p.logger.LogAnomaly(http.MethodConnect, target,
			fmt.Sprintf("[audit] %s: %s", result.Scanner, result.Reason),
			clientIP, requestID, result.Score)
	}

	// Check tunnel capacity
	sem := getTunnelSemaphore()
	if !sem.TryAcquire() {
		http.Error(w, "too many active tunnels", http.StatusServiceUnavailable)
		return
	}
	defer sem.Release()

	// Compute absolute deadline once from start. This covers both dial and
	// relay so the total tunnel lifetime never exceeds max_tunnel_seconds.
	maxDuration := time.Duration(cfg.ForwardProxy.MaxTunnelSeconds) * time.Second
	deadline := start.Add(maxDuration)
	dialCtx, dialCancel := context.WithDeadline(r.Context(), deadline)
	defer dialCancel()

	targetConn, err := p.ssrfSafeDialContext(dialCtx, "tcp", target)
	if err != nil {
		p.logger.LogError(http.MethodConnect, target, clientIP, requestID, err)
		http.Error(w, "tunnel dial failed", http.StatusBadGateway)
		return
	}
	defer targetConn.Close() //nolint:errcheck // best effort

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.LogError(http.MethodConnect, target, clientIP, requestID,
			fmt.Errorf("response writer does not support hijacking"))
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		p.logger.LogError(http.MethodConnect, target, clientIP, requestID, err)
		return
	}
	defer clientConn.Close() //nolint:errcheck // best effort

	// Send 200 Connection Established
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Flush any buffered data from the HTTP parsing layer
	if buf.Reader.Buffered() > 0 {
		buffered := make([]byte, buf.Reader.Buffered())
		_, _ = buf.Read(buffered)
		_, _ = targetConn.Write(buffered)
	}

	p.metrics.IncrActiveTunnels()
	p.logger.LogTunnelOpen(target, clientIP, requestID)

	// Bidirectional relay with idle timeout
	idleTimeout := time.Duration(cfg.ForwardProxy.IdleTimeoutSeconds) * time.Second
	totalBytes := bidirectionalCopy(clientConn, targetConn, idleTimeout, deadline)

	p.metrics.DecrActiveTunnels()
	duration := time.Since(start)
	p.metrics.RecordTunnel(duration, totalBytes)
	p.logger.LogTunnelClose(target, clientIP, requestID, totalBytes, duration)

	// Record data budget for the target domain
	sc.RecordRequest(strings.ToLower(host), int(totalBytes))
}

// bidirectionalCopy relays data between two connections with idle timeout.
// The deadline is an absolute time computed once in handleConnect so the total
// tunnel lifetime (including dial) never exceeds max_tunnel_seconds.
// Returns the total bytes transferred in both directions.
func bidirectionalCopy(client, target net.Conn, idleTimeout time.Duration, deadline time.Time) int64 {
	_ = client.SetDeadline(deadline)
	_ = target.SetDeadline(deadline)

	var clientToTarget, targetToClient int64
	done := make(chan struct{})

	go func() {
		clientToTarget = copyWithIdleTimeout(target, client, idleTimeout, deadline)
		// Half-close: signal target that no more data is coming
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		close(done)
	}()

	targetToClient = copyWithIdleTimeout(client, target, idleTimeout, deadline)
	// Half-close: signal client that no more data is coming
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	<-done
	return clientToTarget + targetToClient
}

// copyWithIdleTimeout copies from src to dst, resetting the read deadline
// on src after each successful read. The per-read deadline is capped at the
// absolute deadline so tunnels cannot exceed max_tunnel_seconds while active.
// Returns total bytes copied.
func copyWithIdleTimeout(dst, src net.Conn, idleTimeout time.Duration, deadline time.Time) int64 {
	buf := make([]byte, tunnelBufSize)
	var total int64
	for {
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

// handleForwardHTTP handles forward proxy requests with absolute URIs
// (e.g., GET http://example.com/path). Scans the URL, forwards the
// request, and streams the raw response back to the client.
func (p *Proxy) handleForwardHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cfg := p.cfgPtr.Load()
	sc := p.scannerPtr.Load()

	clientIP, requestID := requestMeta(r)

	targetURL := r.URL.String()

	// Scan through all 9 layers
	result := sc.Scan(targetURL)
	if !result.Allowed {
		if cfg.EnforceEnabled() {
			p.logger.LogBlocked(r.Method, targetURL, result.Scanner, result.Reason, clientIP, requestID)
			p.metrics.RecordBlocked(r.URL.Hostname(), result.Scanner, time.Since(start))
			http.Error(w, "blocked: "+result.Reason, http.StatusForbidden)
			return
		}
		p.logger.LogAnomaly(r.Method, targetURL,
			fmt.Sprintf("[audit] %s: %s", result.Scanner, result.Reason),
			clientIP, requestID, result.Score)
	}

	// Clone request and strip hop-by-hop headers
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // required for http.Client
	removeHopByHopHeaders(outReq.Header)

	resp, err := p.client.Do(outReq)
	if err != nil {
		p.logger.LogError(r.Method, targetURL, clientIP, requestID, err)
		http.Error(w, "forward proxy fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck // response body

	// Copy response headers, stripping hop-by-hop
	respHeader := w.Header()
	for k, vv := range resp.Header {
		for _, v := range vv {
			respHeader.Add(k, v)
		}
	}
	removeHopByHopHeaders(respHeader)

	// Drop Content-Length: the upstream value may exceed MaxResponseMB. If
	// we forward it and then cap the body with LimitReader, the client sees
	// a Content-Length promising more data than it receives, corrupting
	// HTTP/1.1 persistent connections. Without Content-Length, Go's HTTP
	// server falls back to chunked transfer encoding.
	respHeader.Del("Content-Length")

	w.WriteHeader(resp.StatusCode)

	// Stream body with size limit
	maxBytes := int64(cfg.FetchProxy.MaxResponseMB) * 1024 * 1024
	written, _ := io.Copy(w, io.LimitReader(resp.Body, maxBytes))

	// Record data budget for the target domain
	sc.RecordRequest(strings.ToLower(r.URL.Hostname()), int(written))

	duration := time.Since(start)
	p.metrics.RecordAllowed(duration)
	p.logger.LogForwardHTTP(r.Method, targetURL, clientIP, requestID, resp.StatusCode, int(written), duration)
}

// removeHopByHopHeaders strips RFC 7230 section 6.1 hop-by-hop headers
// from an http.Header. Per the RFC, the Connection header value lists
// additional header names that are hop-by-hop for this connection and
// must also be removed before forwarding.
func removeHopByHopHeaders(h http.Header) {
	// First, parse Connection header for additional hop-by-hop names.
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

	// Then remove the standard hop-by-hop headers.
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}
