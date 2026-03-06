package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// interceptReadHeaderTimeout is the maximum time to read request headers on an
// intercepted TLS connection. 30 seconds is generous for local proxy traffic.
const interceptReadHeaderTimeout = 30 * time.Second

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

// interceptTunnel performs TLS MITM on a hijacked CONNECT tunnel.
// It terminates TLS with the client using a forged cert, creates an
// http.Server to read inner requests, scans them, and forwards to
// upstream via the provided RoundTripper (or a new http.Transport).
func interceptTunnel(
	clientConn net.Conn,
	targetHost, targetPort string,
	cfg *config.Config,
	sc *scanner.Scanner,
	cache *certgen.CertCache,
	upstreamRT http.RoundTripper,
) error {
	// Client-side TLS config with forged cert from cache.
	tlsCfg := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cache.Get(targetHost)
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}

	// TLS handshake with client.
	tlsConn := tls.Server(clientConn, tlsCfg)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	defer tlsConn.Close() //nolint:errcheck // best effort

	// Create upstream transport if not provided (tests inject mock).
	if upstreamRT == nil {
		upstream := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				dialer := &tls.Dialer{Config: &tls.Config{
					ServerName: targetHost,
					NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS12,
				}}
				return dialer.DialContext(ctx, network, net.JoinHostPort(targetHost, targetPort))
			},
			DisableCompression: true, // force identity encoding for scanning
		}
		defer upstream.CloseIdleConnections()
		upstreamRT = upstream
	}

	// Serve via http.Server on single-connection listener.
	ln := newSingleConnListener(tlsConn)
	handler := newInterceptHandler(targetHost, targetPort, upstreamRT, cfg, sc)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: interceptReadHeaderTimeout,
	}
	// Serve blocks until connection closes.
	return srv.Serve(ln)
}

// newInterceptHandler returns an http.Handler that scans and forwards
// intercepted requests. It enforces authority matching, body/header DLP,
// and response injection scanning.
func newInterceptHandler(
	targetHost, targetPort string,
	upstream http.RoundTripper,
	cfg *config.Config,
	sc *scanner.Scanner,
) http.Handler {
	target := net.JoinHostPort(targetHost, targetPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authority check: Host must match CONNECT target.
		// Prevents domain fronting where the agent CONNECTs to allowed.com
		// but sends Host: evil.com inside the encrypted tunnel.
		reqHost := r.Host
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		if !strings.EqualFold(reqHost, targetHost) {
			http.Error(w, "authority mismatch: blocked", http.StatusForbidden)
			return
		}

		// URL reconstruction: origin-form to absolute.
		r.URL.Scheme = schemeHTTPS
		r.URL.Host = target
		r.RequestURI = "" // required for http.Transport

		// Strip Accept-Encoding to force identity encoding upstream.
		// This ensures responses arrive uncompressed so we can scan them.
		r.Header.Del("Accept-Encoding")

		// Request body DLP scanning.
		if cfg.RequestBodyScanning.Enabled && r.Body != nil && r.Body != http.NoBody {
			bodyBytes, result := scanRequestBody(
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
				// Fail-closed: nil bodyBytes means body was consumed but couldn't
				// be buffered (oversize, compressed, read error).
				if bodyBytes == nil || (action == config.ActionBlock && cfg.EnforceEnabled()) {
					reason := result.Reason
					if reason == "" {
						patternNames := dlpMatchNames(result.DLPMatches)
						reason = fmt.Sprintf("request body contains secret: %s", strings.Join(patternNames, ", "))
					}
					http.Error(w, "blocked: "+reason, http.StatusForbidden)
					return
				}
			}

			// Re-wrap body so the forwarded request gets the buffered bytes.
			if bodyBytes != nil {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				r.ContentLength = int64(len(bodyBytes))
			}
		}

		// Request header DLP scanning.
		if cfg.RequestBodyScanning.Enabled && cfg.RequestBodyScanning.ScanHeaders {
			headerResult := scanRequestHeaders(r.Header, cfg, sc)
			if headerResult != nil && !headerResult.Clean {
				action := cfg.RequestBodyScanning.Action
				if action == config.ActionBlock && cfg.EnforceEnabled() {
					http.Error(w, "blocked: request header contains secret", http.StatusForbidden)
					return
				}
			}
		}

		// Remove hop-by-hop headers before forwarding.
		removeHopByHopHeaders(r.Header)

		// Forward to upstream.
		resp, err := upstream.RoundTrip(r)
		if err != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // response body

		// Fail-closed on compressed responses: DLP regex can't match
		// compressed content. Block rather than forward unscanned data.
		if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
			http.Error(w, "blocked: compressed response cannot be scanned", http.StatusForbidden)
			return
		}

		// Buffer response for scanning (scan-then-send, fail-closed).
		maxResp := cfg.TLSInterception.MaxResponseBytes
		if maxResp <= 0 {
			maxResp = 5 * 1024 * 1024 // 5MB default
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
		if readErr != nil {
			http.Error(w, "blocked: response read error", http.StatusForbidden)
			return
		}
		if int64(len(respBody)) > maxResp {
			http.Error(w, "blocked: response too large for scanning", http.StatusForbidden)
			return
		}

		// Response injection scanning.
		if sc.ResponseScanningEnabled() {
			scanResult := sc.ScanResponse(string(respBody))
			if !scanResult.Clean {
				action := sc.ResponseAction()
				if action == config.ActionBlock {
					http.Error(w, "blocked: response contains injection", http.StatusForbidden)
					return
				}
				// warn/strip: log but forward (no logger in this handler, caller logs)
			}
		}

		// Forward clean response to client.
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
// Supports exact match and wildcard prefix (*.example.com).
func isPassthrough(host string, domains []string) bool {
	host = strings.ToLower(host)
	for _, pattern := range domains {
		pattern = strings.ToLower(pattern)
		if pattern == host {
			return true
		}
		// Wildcard: *.example.com matches sub.example.com
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
