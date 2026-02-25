package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// setupForwardProxy creates a running pipelock proxy with forward_proxy enabled
// and returns the proxy address and a cleanup function.
func setupForwardProxy(t *testing.T, cfgMod func(*config.Config)) (string, func()) {
	t.Helper()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.FetchProxy.TimeoutSeconds = 5

	if cfgMod != nil {
		cfgMod(cfg)
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p := New(cfg, logger, sc, m)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/fetch", p.handleFetch)
		mux.HandleFunc("/health", p.handleHealth)

		handler := p.buildHandler(mux)

		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			BaseContext: func(_ net.Listener) context.Context {
				return ctx
			},
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
		}()

		_ = srv.Serve(ln)
	}()

	proxyAddr := ln.Addr().String()
	return proxyAddr, cancel
}

// dialProxy connects to the proxy via TCP.
func dialProxy(t *testing.T, proxyAddr string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	return conn
}

// listenEcho creates a TCP listener that echoes back received data.
func listenEcho(t *testing.T) net.Listener {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				_, _ = conn.Write(buf[:n])
			}()
		}
	}()
	return ln
}

// listenHold creates a TCP listener that holds connections open without sending.
func listenHold(t *testing.T) net.Listener {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				time.Sleep(10 * time.Second)
			}()
		}
	}()
	return ln
}

// doGet issues a GET request via the given client with a proper context.
func doGet(t *testing.T, client *http.Client, targetURL string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to %s: %v", targetURL, err)
	}
	return resp
}

// proxyClient creates an http.Client that uses the given proxy address.
func proxyClient(proxyAddr string) *http.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr) //nolint:errcheck // test helper
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
}

func TestConnectAllowed(t *testing.T) {
	echoLn := listenEcho(t)
	defer func() { _ = echoLn.Close() }()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoLn.Addr().String(), echoLn.Addr().String())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	testMsg := "hello through tunnel"
	_, err = conn.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}

	reply := make([]byte, len(testMsg))
	_, err = io.ReadFull(br, reply)
	if err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}

	if string(reply) != testMsg {
		t.Errorf("expected %q, got %q", testMsg, string(reply))
	}
}

func TestConnectDisabled(t *testing.T) {
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.Enabled = false
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestConnectBlockedDomain(t *testing.T) {
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.FetchProxy.Monitoring.Blocklist = []string{"*.pastebin.com"}
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.pastebin.com:443 HTTP/1.1\r\nHost: evil.pastebin.com:443\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d (body: %s)", resp.StatusCode, body)
	}
}

func TestConnectAuditMode(t *testing.T) {
	echoLn := listenEcho(t)
	defer func() { _ = echoLn.Close() }()

	enforce := false
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.Enforce = &enforce
		// Blocklist 127.0.0.1 so the scanner rejects the target, but audit
		// mode (enforce=false) logs the anomaly and lets traffic through.
		cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	target := echoLn.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	// Audit mode: scanner blocks 127.0.0.1 but enforce=false, so the
	// tunnel is established anyway (covers lines 109-111 audit anomaly path).
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 in audit mode, got %d", resp.StatusCode)
	}

	// Verify tunnel actually works by sending data through
	_, _ = conn.Write([]byte("audit-test"))
	buf := make([]byte, 32)
	n, readErr := br.Read(buf)
	if readErr != nil {
		t.Fatalf("read through audit tunnel: %v", readErr)
	}
	if string(buf[:n]) != "audit-test" {
		t.Errorf("expected echo 'audit-test', got %q", string(buf[:n]))
	}
}

func TestConnectMaxTunnels(t *testing.T) {
	sem := newTunnelSemaphore(1)

	if !sem.TryAcquire() {
		t.Fatal("first acquire should succeed")
	}

	if sem.TryAcquire() {
		t.Fatal("second acquire should fail with capacity 1")
	}

	sem.Release()

	if !sem.TryAcquire() {
		t.Fatal("acquire after release should succeed")
	}
	sem.Release()
}

func TestConnectIdleTimeout(t *testing.T) {
	holdLn := listenHold(t)
	defer func() { _ = holdLn.Close() }()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.IdleTimeoutSeconds = 1
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	target := holdLn.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)

	if err == nil {
		t.Error("expected error from idle timeout, got nil")
	}
}

func TestForwardHTTPAllowed(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Custom", "test-value")
		_, _ = fmt.Fprintf(w, "method=%s path=%s", r.Method, r.URL.Path)
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/test")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "method=GET") {
		t.Errorf("expected body to contain method=GET, got: %s", body)
	}
	if !strings.Contains(string(body), "path=/test") {
		t.Errorf("expected body to contain path=/test, got: %s", body)
	}
	if resp.Header.Get("X-Custom") != "test-value" {
		t.Errorf("expected X-Custom header, got: %s", resp.Header.Get("X-Custom"))
	}
}

func TestForwardHTTPDisabled(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.Enabled = false
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/test")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestForwardHTTPBlockedDomain(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "should not reach here")
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/test")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403, got %d (body: %s)", resp.StatusCode, body)
	}
}

func TestForwardHTTPPost(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "method=%s body=%s", r.Method, body)
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backend.URL+"/submit", strings.NewReader("test-data"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward HTTP POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "method=POST") {
		t.Errorf("expected POST method, got: %s", body)
	}
	if !strings.Contains(string(body), "body=test-data") {
		t.Errorf("expected body=test-data, got: %s", body)
	}
}

func TestForwardHTTPHopByHop(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, "Proxy-Authorization should be stripped")
			return
		}
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Custom-Response", "should-pass")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	fakeAuth := base64.StdEncoding.EncodeToString([]byte("test" + ":" + "test")) //nolint:goconst // test value
	reqStr := fmt.Sprintf("GET %s/hoptest HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nConnection: keep-alive\r\n\r\n",
		backend.URL, backend.Listener.Addr().String(), fakeAuth)
	_, _ = conn.Write([]byte(reqStr))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	if resp.Header.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive header should be stripped from response")
	}
	if resp.Header.Get("X-Custom-Response") != "should-pass" {
		t.Error("X-Custom-Response header should pass through")
	}
}

func TestForwardHTTPContentLengthStripped(t *testing.T) {
	// Verify the proxy strips upstream Content-Length before writing the
	// response. Go's ResponseWriter may re-add a correct Content-Length for
	// small bodies, so we use a raw TCP backend to control the exact wire
	// format and verify the proxy handles it correctly.
	lc := net.ListenConfig{}
	rawLn, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rawLn.Close() }()

	go func() {
		for {
			conn, acceptErr := rawLn.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				// Read request (discard)
				buf := make([]byte, 4096)
				_, _ = conn.Read(buf)
				// Send response with mismatched Content-Length
				resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 999999\r\n\r\nactual body"
				_, _ = conn.Write([]byte(resp))
			}()
		}
	}()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, "http://"+rawLn.Addr().String()+"/cl-test")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "actual body" {
		t.Errorf("expected 'actual body', got %q", string(body))
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic abc")
	h.Set("Te", "trailers")
	h.Set("Trailer", "X-Checksum")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "websocket")
	h.Set("Content-Type", "text/plain")
	h.Set("X-Custom", "value")

	removeHopByHopHeaders(h)

	for _, header := range hopByHopHeaders {
		if h.Get(header) != "" {
			t.Errorf("hop-by-hop header %q should be removed", header)
		}
	}
	if h.Get("Content-Type") != "text/plain" {
		t.Error("Content-Type should not be removed")
	}
	if h.Get("X-Custom") != "value" {
		t.Error("X-Custom should not be removed")
	}
}

func TestTunnelSemaphore(t *testing.T) {
	sem := newTunnelSemaphore(2)

	if !sem.TryAcquire() {
		t.Error("first acquire should succeed")
	}
	if !sem.TryAcquire() {
		t.Error("second acquire should succeed")
	}
	if sem.TryAcquire() {
		t.Error("third acquire should fail (capacity 2)")
	}

	sem.Release()
	if !sem.TryAcquire() {
		t.Error("acquire after release should succeed")
	}
}

func TestConnectSSRFBlocked(t *testing.T) {
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.Internal = []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		}
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	// Scanner catches the private IP before the dial attempt, returning 403.
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for SSRF blocked, got %d", resp.StatusCode)
	}
}

func TestConnectViaHTTPProxy(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/via-proxy")
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from backend" {
		t.Errorf("expected 'hello from backend', got: %s", body)
	}
}

func TestHealthIncludesForwardProxy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = true

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc, metrics.New())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	p.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"forward_proxy_enabled":true`) {
		t.Errorf("expected forward_proxy_enabled:true in health response, got: %s", body)
	}
}

// startProxyOnFreePort starts the proxy via Start() on a random port and returns
// the listening address. Uses the production code path (mux wrapper, WriteTimeout).
func startProxyOnFreePort(t *testing.T, cfg *config.Config) (string, func()) {
	t.Helper()

	// Find a free port
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg.FetchProxy.Listen = addr
	cfg.FetchProxy.TimeoutSeconds = 5

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p := New(cfg, logger, sc, m)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Start(ctx)
	}()

	// Wait for server to be ready, draining errCh to detect startup failures.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case startErr := <-errCh:
			t.Fatalf("proxy Start() failed: %v", startErr)
		default:
		}
		d := net.Dialer{Timeout: 100 * time.Millisecond}
		conn, dialErr := d.DialContext(context.Background(), "tcp", addr)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cleanup := func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
		}
		sc.Close()
	}
	return addr, cleanup
}

func TestStartConnectViaProduction(t *testing.T) {
	echoLn := listenEcho(t)
	defer func() { _ = echoLn.Close() }()
	echoAddr := echoLn.Addr().String()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2

	proxyAddr, cleanup := startProxyOnFreePort(t, cfg)
	defer cleanup()

	// CONNECT through the production Start() code path
	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	_, _ = conn.Write([]byte("hello"))
	buf := make([]byte, 32)
	n, _ := br.Read(buf)
	if string(buf[:n]) != "hello" { //nolint:goconst // test value
		t.Errorf("expected echo 'hello', got %q", string(buf[:n]))
	}
}

func TestStartConnectDisabledViaProduction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = false

	proxyAddr, cleanup := startProxyOnFreePort(t, cfg)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 when forward proxy disabled, got %d", resp.StatusCode)
	}
}

func TestStartForwardHTTPViaProduction(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "backend-ok")
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true

	proxyAddr, cleanup := startProxyOnFreePort(t, cfg)
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/test")
	defer resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-ok" {
		t.Errorf("expected 'backend-ok', got %q", string(body))
	}
}

func TestStartForwardHTTPDisabledViaProduction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = false

	proxyAddr, cleanup := startProxyOnFreePort(t, cfg)
	defer cleanup()

	client := proxyClient(proxyAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/test", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 when forward proxy disabled, got %d", resp.StatusCode)
	}
}

func TestStartFetchStillWorksWithForwardProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><body>hello fetch</body></html>")
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true

	proxyAddr, cleanup := startProxyOnFreePort(t, cfg)
	defer cleanup()

	// /fetch endpoint should still work alongside forward proxy
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	fetchURL := fmt.Sprintf("http://%s/fetch?url=%s", proxyAddr, url.QueryEscape(backend.URL))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from /fetch, got %d", resp.StatusCode)
	}
}

func TestConnectMissingHost(t *testing.T) {
	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	// CONNECT with empty host (missing Host header and no authority)
	_, _ = conn.Write([]byte("CONNECT HTTP/1.1\r\n\r\n"))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing host, got %d", resp.StatusCode)
	}
}

func TestForwardHTTPAuditMode(t *testing.T) {
	// Backend to target
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "audit-ok")
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.Mode = config.ModeAudit
		v := false
		cfg.Enforce = &v
		// Add a blocklist to trigger scan failure
		cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/test")
	defer resp.Body.Close() //nolint:errcheck // test

	// Audit mode: should still succeed (log only, no block)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 in audit mode, got %d", resp.StatusCode)
	}
}

func TestForwardHTTPDialFailure(t *testing.T) {
	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)

	// Target a port that nothing is listening on
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:1/unreachable", nil)
	resp, err := client.Do(req)
	if err != nil {
		// Connection refused errors may propagate as client errors
		return
	}
	defer resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 for unreachable target, got %d", resp.StatusCode)
	}
}

func TestConnectDialFailure(t *testing.T) {
	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	// CONNECT to a port that nothing is listening on
	_, _ = fmt.Fprintf(conn, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 for dial failure, got %d", resp.StatusCode)
	}
}

func TestCopyWithIdleTimeoutRespectsDeadline(t *testing.T) {
	// Verify that copyWithIdleTimeout caps per-read deadlines at the absolute
	// deadline. A 10s idle timeout should be capped by a near-immediate deadline.
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Set deadline to 50ms from now, idle timeout much longer (10s)
	deadline := time.Now().Add(50 * time.Millisecond)
	var dst strings.Builder
	dstConn := &writerConn{Writer: &dst, Conn: client}

	start := time.Now()
	// Server never sends data, so copyWithIdleTimeout blocks on Read.
	// With deadline capping, it should return after ~50ms (the deadline),
	// not after 10s (the idle timeout).
	_ = copyWithIdleTimeout(dstConn, server, 10*time.Second, deadline)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("copyWithIdleTimeout took %v; expected it to respect the ~50ms deadline", elapsed)
	}
}

// writerConn wraps an io.Writer into a net.Conn for testing copyWithIdleTimeout's
// write path. Only Write is used; all net.Conn methods delegate to the embedded Conn.
type writerConn struct {
	io.Writer
	net.Conn
}

func (w *writerConn) Write(p []byte) (int, error) {
	return w.Writer.Write(p)
}

func TestConnectDefaultPort(t *testing.T) {
	// CONNECT with host but no port should default to :443
	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	// CONNECT to just "127.0.0.1" (no port) - should try :443 and fail since nothing listens there
	_, _ = fmt.Fprintf(conn, "CONNECT 127.0.0.1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	// Will get 502 (dial failure to port 443) which proves the default port logic ran
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 (default port 443 unreachable), got %d", resp.StatusCode)
	}
}

func TestSSRFSafeDialContext_DirectIP(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc, metrics.New())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Direct IP in internal range should be blocked
	_, err := p.ssrfSafeDialContext(ctx, "tcp", "10.0.0.1:443")
	if err == nil {
		t.Fatal("expected SSRF block for internal IP, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF blocked") {
		t.Errorf("expected SSRF blocked error, got: %v", err)
	}
}

func TestSSRFSafeDialContext_InvalidAddr(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"10.0.0.0/8"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc, metrics.New())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Address without port should fail SplitHostPort
	_, err := p.ssrfSafeDialContext(ctx, "tcp", "no-port")
	if err == nil {
		t.Fatal("expected error for address without port")
	}
}

func TestSSRFSafeDialContext_LoopbackBlocked(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"127.0.0.0/8"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc, metrics.New())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 127.0.0.1 is in the internal range 127.0.0.0/8.
	_, err := p.ssrfSafeDialContext(ctx, "tcp", "127.0.0.1:443")
	if err == nil {
		t.Fatal("expected SSRF block for loopback IP")
	}
	if !strings.Contains(err.Error(), "SSRF blocked") {
		t.Errorf("expected SSRF blocked error, got: %v", err)
	}
}

func TestSSRFSafeDialContext_DNSResolvesToInternal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"127.0.0.0/8"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc, metrics.New())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// "localhost" resolves to 127.0.0.1 via /etc/hosts on all CI and dev
	// machines. This exercises the DNS LookupHost + IP validation path in
	// ssrfSafeDialContext (lines 194-215), which is not covered by direct-IP
	// tests.
	_, err := p.ssrfSafeDialContext(ctx, "tcp", "localhost:443")
	if err == nil {
		t.Fatal("expected SSRF block for localhost resolving to 127.0.0.1")
	}
	if !strings.Contains(err.Error(), "SSRF blocked") {
		t.Errorf("expected SSRF blocked error, got: %v", err)
	}
}

func TestSSRFSafeDialContext_AllowedIP(t *testing.T) {
	// Start a local listener to accept the connection
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_ = conn.Close()
	}()

	cfg := config.Defaults()
	cfg.Internal = nil // No SSRF checks

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc, metrics.New())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Direct IP with no internal ranges should succeed
	conn, dialErr := p.ssrfSafeDialContext(ctx, "tcp", ln.Addr().String())
	if dialErr != nil {
		t.Fatalf("expected successful dial, got: %v", dialErr)
	}
	_ = conn.Close()
}

func TestConnectBlockedByEnforce(t *testing.T) {
	// Test the enforce=true path with a blocklisted target
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	// CONNECT to a blocklisted IP
	_, _ = fmt.Fprintf(conn, "CONNECT 127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for blocklisted target, got %d", resp.StatusCode)
	}
}

func TestGetTunnelSemaphore(t *testing.T) {
	// Verify the lazy initialization returns the same instance
	s1 := getTunnelSemaphore()
	s2 := getTunnelSemaphore()
	if s1 != s2 {
		t.Error("getTunnelSemaphore should return the same instance")
	}
}

func TestConnectIPv6BareNoPort(t *testing.T) {
	// CONNECT with bare IPv6 literal "[::1]" (no port) should default to :443
	// and correctly normalize to [::1]:443 (not [[::1]]:443).
	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT [::1] HTTP/1.1\r\nHost: [::1]\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	// Expect 502 (dial failure to [::1]:443), not a parse error.
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 for bare IPv6 dial failure, got %d", resp.StatusCode)
	}
}

func TestConnectIPv6Brackets(t *testing.T) {
	// Verify that CONNECT to an IPv6 literal produces a valid synthetic URL.
	// net.SplitHostPort("[::1]:443") strips brackets, so the proxy must
	// re-bracket before building "https://[::1]/" for the scanner.
	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	// CONNECT to IPv6 loopback - will fail the dial (nothing listening on [::1]:443)
	// but exercises the URL construction path.
	_, _ = fmt.Fprintf(conn, "CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	// Expect 502 (dial failure) not 403 (scanner misparse) or 400 (bad URL).
	// This proves the synthetic URL was valid and the scanner processed it correctly.
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 for IPv6 dial failure, got %d", resp.StatusCode)
	}
}

func TestConnectSessionBlocked(t *testing.T) {
	// Session profiling should block CONNECT when anomaly_action=block.
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.SessionProfiling.Enabled = true
		cfg.SessionProfiling.DomainBurst = 2
		cfg.SessionProfiling.WindowMinutes = 5
		cfg.SessionProfiling.AnomalyAction = "block" //nolint:goconst // test value
		cfg.SessionProfiling.MaxSessions = 100
		cfg.SessionProfiling.SessionTTLMinutes = 30
		cfg.SessionProfiling.CleanupIntervalSeconds = 60
	})
	defer cleanup()

	// Send CONNECT requests to enough different domains to trigger domain burst.
	domains := []string{"a.com:443", "b.com:443", "c.com:443"}
	for _, d := range domains {
		conn := dialProxy(t, proxyAddr)
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", d, d)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err == nil {
			_ = resp.Body.Close()
		}
		_ = conn.Close()
	}

	// After exceeding domain burst threshold (2), next request should be blocked.
	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT final.com:443 HTTP/1.1\r\nHost: final.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when session anomaly blocks, got %d", resp.StatusCode)
	}
}

func TestConnectWSRedirectHint(t *testing.T) {
	// Exercise the WebSocket redirect hint path (forward.go lines 130-136).
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.WebSocketProxy.Enabled = true
		cfg.ForwardProxy.RedirectWebSocketHosts = []string{"stream.example.com"}
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()

	// CONNECT to a host that's in the redirect-websocket list.
	_, _ = fmt.Fprintf(conn, "CONNECT stream.example.com:443 HTTP/1.1\r\nHost: stream.example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	// The hint is a log-only anomaly; CONNECT still proceeds (and fails at dial).
	// Status 502 means the scanner passed and the dial failed, proving the hint code ran.
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 (dial failed after hint), got %d", resp.StatusCode)
	}
}

func TestForwardHTTPSessionBlocked(t *testing.T) {
	// Session profiling should block forward HTTP when anomaly_action=block.
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.SessionProfiling.Enabled = true
		cfg.SessionProfiling.DomainBurst = 2
		cfg.SessionProfiling.WindowMinutes = 5
		cfg.SessionProfiling.AnomalyAction = "block" //nolint:goconst // test value
		cfg.SessionProfiling.MaxSessions = 100
		cfg.SessionProfiling.SessionTTLMinutes = 30
		cfg.SessionProfiling.CleanupIntervalSeconds = 60
	})
	defer cleanup()

	client := proxyClient(proxyAddr)

	// Trigger domain burst by hitting many different hosts via forward proxy.
	for i := 0; i < 4; i++ {
		reqURL := fmt.Sprintf("http://domain%d.com/path", i)
		req, _ := http.NewRequest(http.MethodGet, reqURL, nil) //nolint:noctx // test
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}

	// After exceeding domain burst, the next forward HTTP should be blocked.
	resp := doGet(t, client, "http://final-domain.com/test")
	defer resp.Body.Close() //nolint:errcheck // test

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when session anomaly blocks forward HTTP, got %d", resp.StatusCode)
	}
}

func TestBidirectionalCopy(t *testing.T) {
	// Test bidirectional copy with a near-immediate deadline
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	deadline := time.Now().Add(100 * time.Millisecond)
	start := time.Now()
	total := bidirectionalCopy(client, server, 50*time.Millisecond, deadline)
	elapsed := time.Since(start)

	// Should return quickly (within deadline) with zero bytes
	if total != 0 {
		t.Errorf("expected 0 bytes, got %d", total)
	}
	if elapsed > 2*time.Second {
		t.Errorf("bidirectionalCopy took %v, expected ~100ms", elapsed)
	}
}
