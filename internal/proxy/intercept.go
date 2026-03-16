// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// interceptReadHeaderTimeout is the maximum time to read request headers on an
// intercepted TLS connection. 30 seconds is generous for local proxy traffic.
const interceptReadHeaderTimeout = 30 * time.Second

// interceptHandshakeTimeout is the maximum time for the client-side TLS
// handshake during interception. Prevents goroutine/semaphore exhaustion
// from malicious clients that stall during the handshake.
const interceptHandshakeTimeout = 30 * time.Second

// interceptDefaultMaxResp is the fallback maximum response size for scanning.
// Should not be reached since Validate() enforces max_response_bytes > 0,
// but provides a fail-safe for direct callers that bypass validation.
const interceptDefaultMaxResp = 5 * 1024 * 1024 // 5MB

// bufferedConn wraps a net.Conn with a bufio.Reader so that any bytes
// already buffered (e.g. from SNI peeking) are read before falling through
// to the underlying connection. This prevents data loss when passing a
// connection from verifySNI to interceptTunnel.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// wrapBuffered returns a net.Conn that reads from the bufio.Reader first
// (draining any buffered bytes from SNI peeking), then falls through to
// the underlying connection. If nothing is buffered, returns conn as-is.
func wrapBuffered(conn net.Conn, r *bufio.Reader) net.Conn {
	if r.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: r}
	}
	return conn
}

// dialFunc is a function signature for dialing TCP connections.
// The proxy passes its SSRF-safe dialer to prevent DNS rebinding TOCTOU.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// interceptTunnel performs TLS MITM on a hijacked CONNECT tunnel.
// It terminates TLS with the client using a forged cert, creates an
// http.Server to read inner requests, scans them, and forwards to
// upstream via the provided RoundTripper (or a new http.Transport).
// The ctx controls the overall tunnel lifetime including the TLS handshake.
// The safeDial parameter provides SSRF-safe TCP dialing for the upstream
// connection, preventing DNS rebinding between the scanner check and dial.
func interceptTunnel(
	ctx context.Context,
	clientConn net.Conn,
	targetHost, targetPort string,
	cfg *config.Config,
	sc *scanner.Scanner,
	cache *certgen.CertCache,
	logger *audit.Logger,
	m *metrics.Metrics,
	clientIP, requestID, agent string,
	upstreamRT http.RoundTripper,
	safeDial dialFunc,
	et *scanner.EntropyTracker,
	fb *scanner.FragmentBuffer,
	sm *SessionManager,
	p *Proxy, // when non-nil, CEE state resolved per-request (avoids stale pointers after reload)
) error {
	// Client-side TLS config with forged cert from cache.
	tlsCfg := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := cache.Get(targetHost)
			if err == nil {
				m.SetTLSCertCacheSize(float64(cache.Size()))
			}
			return cert, err
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}

	// TLS handshake with client. Set a deadline to prevent goroutine
	// accumulation from clients that stall during the handshake.
	handshakeDeadline := time.Now().Add(interceptHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(handshakeDeadline) {
		handshakeDeadline = ctxDeadline
	}
	if err := clientConn.SetDeadline(handshakeDeadline); err != nil {
		m.RecordTLSIntercept("deadline_error")
		return fmt.Errorf("set handshake deadline: %w", err)
	}

	tlsConn := tls.Server(clientConn, tlsCfg)
	handshakeStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		m.RecordTLSIntercept("handshake_error")
		logger.LogBlocked("CONNECT", targetHost, "tls_handshake_error", err.Error(), clientIP, requestID, agent)
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	m.RecordTLSHandshake("client", time.Since(handshakeStart))

	// Clear the handshake deadline so it doesn't affect request serving.
	_ = clientConn.SetDeadline(time.Time{})
	defer tlsConn.Close() //nolint:errcheck // best effort

	// Create upstream transport if not provided (tests inject mock).
	if upstreamRT == nil {
		upstream := &http.Transport{
			DialTLSContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				addr := net.JoinHostPort(targetHost, targetPort)
				// Use SSRF-safe dialer for the TCP connection to prevent
				// DNS rebinding TOCTOU between the scanner check and dial.
				var rawConn net.Conn
				var dialErr error
				if safeDial != nil {
					rawConn, dialErr = safeDial(dialCtx, network, addr)
				} else {
					// Fallback for tests that don't provide a dialer.
					rawConn, dialErr = (&net.Dialer{}).DialContext(dialCtx, network, addr)
				}
				if dialErr != nil {
					return nil, dialErr
				}
				// Layer TLS on top of the SSRF-validated TCP connection.
				tlsCfg := &tls.Config{
					ServerName: targetHost,
					NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS12,
				}
				start := time.Now()
				tlsUpstream := tls.Client(rawConn, tlsCfg)
				if err := tlsUpstream.HandshakeContext(dialCtx); err != nil {
					_ = rawConn.Close()
					return nil, err
				}
				m.RecordTLSHandshake("upstream", time.Since(start))
				return tlsUpstream, nil
			},
			ForceAttemptHTTP2:  true, // required with custom DialTLSContext for h2
			DisableCompression: true, // force identity encoding for scanning
		}
		defer upstream.CloseIdleConnections()
		upstreamRT = upstream
	}

	// Serve via http.Server on single-connection listener.
	// http.Server handles HTTP/2 when negotiated via ALPN.
	ln := newSingleConnListener(tlsConn)
	handler := newInterceptHandler(targetHost, targetPort, upstreamRT, cfg, sc, logger, m, clientIP, requestID, agent, et, fb, sm, p)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: interceptReadHeaderTimeout,
		ConnState: func(_ net.Conn, state http.ConnState) {
			// Close the listener when the connection finishes so Serve()
			// exits promptly instead of blocking on Accept() forever.
			if state == http.StateClosed {
				_ = ln.Close()
			}
		},
	}

	// Shut down the server when the context expires (tunnel deadline) to
	// prevent goroutine leaks from srv.Serve blocking on Accept forever.
	// The done channel stops this goroutine when Serve returns normally,
	// preventing accumulation under high CONNECT throughput.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
		case <-done:
		}
	}()

	// Serve blocks until the connection closes or the server is shut down.
	// Normal termination returns http.ErrServerClosed (from srv.Close above)
	// or net.ErrClosed (from listener). Both are expected.
	err := srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// newInterceptHandler returns an http.Handler that scans and forwards
// intercepted requests. It enforces authority matching, body/header DLP,
// and response injection scanning.
func newInterceptHandler(
	targetHost, targetPort string,
	upstream http.RoundTripper,
	cfg *config.Config,
	sc *scanner.Scanner,
	logger *audit.Logger,
	m *metrics.Metrics,
	clientIP, requestID, agent string,
	et *scanner.EntropyTracker,
	fb *scanner.FragmentBuffer,
	sm *SessionManager,
	p *Proxy, // when non-nil, CEE state resolved per-request (avoids stale pointers after reload)
) http.Handler {
	target := net.JoinHostPort(targetHost, targetPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authority check: Host must match CONNECT target (host:port).
		// Prevents domain fronting where the agent CONNECTs to allowed.com
		// but sends Host: evil.com inside the encrypted tunnel. Also prevents
		// port mismatch (e.g. Host: example.com:8443 inside tunnel to :443).
		reqHost, reqPort, splitErr := net.SplitHostPort(r.Host)
		if splitErr != nil {
			// No port in Host header: treat as default HTTPS port.
			reqHost = r.Host
			reqPort = "443"
		}
		if !strings.EqualFold(reqHost, targetHost) || reqPort != targetPort {
			mismatch := r.Host + " vs " + target
			logger.LogBlocked(r.Method, r.URL.Path, "tls_authority_mismatch", "authority mismatch: "+mismatch, clientIP, requestID, agent)
			m.RecordTLSRequestBlocked("authority_mismatch")
			http.Error(w, "authority mismatch: blocked", http.StatusForbidden)
			return
		}

		// URL reconstruction: origin-form to absolute.
		r.URL.Scheme = schemeHTTPS
		r.URL.Host = target
		r.RequestURI = "" // required for http.Transport

		// Scan the full URL through the DLP pipeline. The CONNECT handler only
		// scans the synthetic host URL; inside the intercepted tunnel we have
		// the real path and query, which may contain exfiltrated secrets.
		targetURL := r.URL.String()
		urlResult := sc.Scan(r.Context(), targetURL)
		if !urlResult.Allowed {
			if cfg.EnforceEnabled() {
				logger.LogBlocked(r.Method, targetURL, urlResult.Scanner, urlResult.Reason, clientIP, requestID, agent)
				m.RecordTLSRequestBlocked("url_scan")
				if cfg.ExplainBlocksEnabled() && urlResult.Hint != "" {
					w.Header().Set("X-Pipelock-Hint", urlResult.Hint)
				}
				http.Error(w, "blocked: "+urlResult.Reason, http.StatusForbidden)
				return
			}
			// Audit mode: log anomaly but forward the request.
			logger.LogAnomaly(r.Method, targetURL, urlResult.Scanner, urlResult.Reason, clientIP, requestID, agent, urlResult.Score)
		}

		// Strip Accept-Encoding to force identity encoding upstream.
		// This ensures responses arrive uncompressed so we can scan them.
		r.Header.Del("Accept-Encoding")

		// Request body DLP scanning.
		if cfg.RequestBodyScanning.Enabled && r.Body != nil && r.Body != http.NoBody {
			bodyBytes, result := scanRequestBody(
				r.Context(),
				r.Body,
				r.Header.Get("Content-Type"),
				r.Header.Get("Content-Encoding"),
				cfg.RequestBodyScanning.MaxBodyBytes,
				sc,
			)

			if !result.Clean {
				action := result.Action
				if action == "" {
					action = cfg.RequestBodyScanning.Action
				}
				reason := result.Reason
				if reason == "" {
					patternNames := dlpMatchNames(result.DLPMatches)
					reason = fmt.Sprintf("request body contains secret: %s", strings.Join(patternNames, ", "))
				}

				// Fail-closed: nil bodyBytes means body was consumed but couldn't
				// be buffered (oversize, compressed, read error). Always block
				// regardless of enforce mode to prevent forwarding an empty body.
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if bodyBytes == nil || action == config.ActionAsk || (action == config.ActionBlock && cfg.EnforceEnabled()) {
					logger.LogBlocked(r.Method, r.URL.String(), "body_dlp", reason, clientIP, requestID, agent)
					m.RecordTLSRequestBlocked("body_dlp")
					http.Error(w, "blocked: "+reason, http.StatusForbidden)
					return
				}
				// Audit/warn mode: log finding but forward the request.
				logger.LogAnomaly(r.Method, r.URL.String(), "body_dlp", reason, clientIP, requestID, agent, 0.8) // 0.8: high confidence DLP match
			}

			// Re-wrap body so the forwarded request gets the buffered bytes.
			// Always re-wrap after scanning since the original body was consumed.
			if bodyBytes != nil {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				r.ContentLength = int64(len(bodyBytes))
			}
		}

		// Request header DLP scanning.
		if cfg.RequestBodyScanning.Enabled && cfg.RequestBodyScanning.ScanHeaders {
			headerResult := scanRequestHeaders(r.Context(), r.Header, cfg, sc)
			if headerResult != nil && !headerResult.Clean {
				action := cfg.RequestBodyScanning.Action
				// ActionAsk: no HITL terminal in intercepted tunnels, fail closed.
				if action == config.ActionAsk || (action == config.ActionBlock && cfg.EnforceEnabled()) {
					logger.LogBlocked(r.Method, r.URL.String(), "header_dlp", "request header contains secret", clientIP, requestID, agent)
					m.RecordTLSRequestBlocked("header_dlp")
					http.Error(w, "blocked: request header contains secret", http.StatusForbidden)
					return
				}
				// Audit mode: log but forward.
				logger.LogAnomaly(r.Method, r.URL.String(), "header_dlp", "request header contains secret", clientIP, requestID, agent, 0.8) // 0.8: high confidence DLP match
			}
		}

		// CEE pre-forward admission for intercepted requests. The intercepted
		// request has full body, headers, and URL available for entropy and
		// fragment analysis. When p is non-nil, resolve CEE objects per-request
		// so hot-reloads during long-lived CONNECT tunnels use fresh state.
		ceeCfg := ceeEffectiveConfig(cfg.CrossRequestDetection, cfg.EnforceEnabled())
		if ceeCfg.Enabled {
			ceeET, ceeFB, ceeSM := et, fb, sm
			if p != nil {
				ceeET = p.entropyTrackerPtr.Load()
				ceeFB = p.fragmentBufferPtr.Load()
				ceeSM = p.sessionMgrPtr.Load()
			}

			sessionKey := ceeSessionKey(agent, clientIP)
			outbound := extractOutboundPayload(r)
			keys := queryParamKeys(r.URL)

			ceeRes := ceeAdmit(r.Context(), sessionKey, outbound, keys, r.URL.String(), agent, clientIP, requestID,
				ceeCfg, ceeET, ceeFB, sc, logger, m)

			if ceeSM != nil && cfg.AdaptiveEnforcement.Enabled {
				ceeRecordSignals(ceeRes, ceeSM, sessionKey, cfg.AdaptiveEnforcement.EscalationThreshold, logger, m, clientIP, requestID)
			}

			if ceeRes.Blocked {
				m.RecordTLSRequestBlocked("cross_request")
				http.Error(w, "blocked: "+ceeRes.Reason, http.StatusForbidden)
				return
			}
		}

		// Remove hop-by-hop headers before forwarding.
		removeHopByHopHeaders(r.Header)

		// Forward to upstream.
		resp, err := upstream.RoundTrip(r)
		if err != nil {
			logger.LogError(r.Method, r.URL.String(), clientIP, requestID, agent, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // response body

		// Fail-closed on compressed responses: DLP regex can't match
		// compressed content. Block rather than forward unscanned data.
		if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
			logger.LogBlocked(r.Method, r.URL.String(), "tls_response_blocked", "compressed response cannot be scanned", clientIP, requestID, agent)
			m.RecordTLSResponseBlocked("compressed")
			http.Error(w, "blocked: compressed response cannot be scanned", http.StatusForbidden)
			return
		}

		// Buffer response for scanning (scan-then-send, fail-closed).
		maxResp := cfg.TLSInterception.MaxResponseBytes
		if maxResp <= 0 {
			maxResp = interceptDefaultMaxResp
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
		if readErr != nil {
			logger.LogError(r.Method, r.URL.String(), clientIP, requestID, agent, readErr)
			m.RecordTLSResponseBlocked("read_error")
			http.Error(w, "blocked: response read error", http.StatusForbidden)
			return
		}
		if int64(len(respBody)) > maxResp {
			logger.LogBlocked(r.Method, r.URL.String(), "tls_response_blocked", "response too large for scanning", clientIP, requestID, agent)
			m.RecordTLSResponseBlocked("oversized")
			http.Error(w, "blocked: response too large for scanning", http.StatusForbidden)
			return
		}

		// Response injection scanning.
		if sc.ResponseScanningEnabled() {
			scanResult := sc.ScanResponse(r.Context(), string(respBody))
			if !scanResult.Clean {
				action := sc.ResponseAction()
				patternNames := make([]string, len(scanResult.Matches))
				for i, match := range scanResult.Matches {
					patternNames[i] = match.PatternName
				}
				bundleRules := responseBundleRules(scanResult.Matches)
				reason := fmt.Sprintf("response injection: %s", strings.Join(patternNames, ", "))

				switch action {
				case config.ActionBlock, config.ActionAsk:
					// ActionAsk: no HITL terminal available inside intercepted tunnels,
					// so fail-closed to block (consistent with HITL non-terminal default).
					logger.LogBlocked(r.Method, r.URL.String(), "response_scan", reason, clientIP, requestID, agent)
					m.RecordTLSResponseBlocked("injection")
					http.Error(w, "blocked: response contains injection", http.StatusForbidden)
					return
				case config.ActionStrip:
					respBody = []byte(scanResult.TransformedContent)
					// Update Content-Length to match stripped body; prevents HTTP/1.1
					// framing errors from a stale upstream Content-Length header.
					resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
					logger.LogResponseScan(r.URL.String(), clientIP, requestID, agent, config.ActionStrip, len(scanResult.Matches), patternNames, bundleRules)
				default:
					// warn/forward: log and forward unmodified.
					logger.LogResponseScan(r.URL.String(), clientIP, requestID, agent, action, len(scanResult.Matches), patternNames, bundleRules)
				}
			}
		}

		// Record response size for per-domain data budget tracking.
		sc.RecordRequest(strings.ToLower(targetHost), len(respBody))

		// Forward response to client.
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		removeHopByHopHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	})
}

// isPassthrough checks if a hostname matches the passthrough domain list.
// Supports exact match and wildcard prefix (*.example.com matches any subdomain depth).
func isPassthrough(host string, domains []string) bool {
	host = strings.ToLower(host)
	for _, pattern := range domains {
		pattern = strings.ToLower(pattern)
		if pattern == host {
			return true
		}
		// Wildcard: *.example.com matches sub.example.com and deep.sub.example.com.
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // .example.com
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// singleConnListener yields one connection then blocks until closed.
// Used to serve a single hijacked TLS connection via http.Server.
// The channel is NOT closed in the constructor because http.Server.Serve
// must not exit until the handler goroutine completes. Instead, call
// Close() (typically via srv.Close/Shutdown) to unblock the accept loop.
type singleConnListener struct {
	ch        chan net.Conn
	addr      net.Addr
	closeOnce sync.Once
}

func newSingleConnListener(conn net.Conn) net.Listener {
	ln := &singleConnListener{
		ch:   make(chan net.Conn, 1),
		addr: conn.LocalAddr(),
	}
	ln.ch <- conn
	return ln
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.ch) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}
