// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// SSE streaming on the forward and intercept proxies must be activated by
// the response Content-Type alone, not by response_scanning.enabled. The
// buffered scan path was previously gated by an OR-condition over response
// scanning, browser shield, and media policy; media policy defaults to ON,
// which silently forced every text/event-stream response into io.ReadAll
// regardless of scanning state. The egress benchmark surfaced this as a
// 90 ms TTFB regression. The tests in this file are the
// in-repo regression coverage for the decoupling fix.

const (
	sseDecoupledFirst  = "epsilon-event"
	sseDecoupledSecond = "zeta-event"
)

func sseDecoupledFakeAWSKey() string {
	// gosec G101: synthesized at runtime, never a real credential.
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

// emitTwoEventSSE returns an http.HandlerFunc that writes one SSE event,
// then blocks on releaseSecond before writing a second. If the proxy
// buffers the whole body, the client cannot read event 1 until event 2 is
// written, and the test deadline fires. Streaming proxies deliver event 1
// immediately and the client's close(releaseSecond) unblocks event 2.
func emitTwoEventSSE(t *testing.T, releaseSecond <-chan struct{}) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)

		if _, err := fmt.Fprintf(w, "data: %s\n\n", sseDecoupledFirst); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}

		select {
		case <-releaseSecond:
		case <-time.After(3 * time.Second):
			return
		}

		if _, err := fmt.Fprintf(w, "data: %s\n\n", sseDecoupledSecond); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// assertTwoEventSSEStreams drives the proxied client, releases the second
// event after reading the first, and asserts both arrive in order.
func assertTwoEventSSEStreams(t *testing.T, resp *http.Response, releaseSecond chan<- struct{}) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream prefix", resp.Header.Get("Content-Type"))
	}

	scanner := bufio.NewScanner(resp.Body)
	first := readNextSSEData(t, scanner)
	if first != sseDecoupledFirst {
		t.Fatalf("first event = %q, want %q", first, sseDecoupledFirst)
	}

	close(releaseSecond)

	second := readNextSSEData(t, scanner)
	if second != sseDecoupledSecond {
		t.Fatalf("second event = %q, want %q", second, sseDecoupledSecond)
	}
}

// TestForwardProxy_SSE_StreamsWhenScanningDisabled asserts the v2.3.0
// CHANGELOG promise: when response_scanning.enabled is false, an SSE
// response still flows through pipelock chunk-by-chunk and is not
// silently downgraded to io.ReadAll by the MediaPolicy/BrowserShield
// arms of the buffered-gate OR condition.
func TestForwardProxy_SSE_StreamsWhenScanningDisabled(t *testing.T) {
	releaseSecond := make(chan struct{})
	backend := newIPv4Server(t, emitTwoEventSSE(t, releaseSecond))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertTwoEventSSEStreams(t, resp, releaseSecond)
}

// TestForwardProxy_SSE_StreamsWithMediaPolicyDefault asserts SSE
// streaming activates even when MediaPolicy.IsEnabled() is true (the
// default). MediaPolicy targets image/audio/video; it has no work on
// text/event-stream, so SSE must skip the buffered scan path entirely.
func TestForwardProxy_SSE_StreamsWithMediaPolicyDefault(t *testing.T) {
	releaseSecond := make(chan struct{})
	backend := newIPv4Server(t, emitTwoEventSSE(t, releaseSecond))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		// Explicitly leave MediaPolicy at default (Enabled=nil => true)
		// AND disable response scanning. Pre-fix this combination forced
		// the buffered path. Post-fix the streaming branch wins on
		// Content-Type alone.
		cfg.ResponseScanning.Enabled = false
		enabledTrue := true
		cfg.MediaPolicy.Enabled = &enabledTrue
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertTwoEventSSEStreams(t, resp, releaseSecond)
}

// TestForwardProxy_SSE_StreamsWhenChildSSEStreamingDisabled asserts the
// finer-grained switch: response_scanning.enabled = true but
// response_scanning.sse_streaming.enabled = false. The streaming branch
// must still activate (Content-Type-driven) and the dispatcher's
// passthroughSSE must run instead of per-event scanning.
func TestForwardProxy_SSE_StreamsWhenChildSSEStreamingDisabled(t *testing.T) {
	releaseSecond := make(chan struct{})
	backend := newIPv4Server(t, emitTwoEventSSE(t, releaseSecond))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.SSEStreaming.Enabled = false
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertTwoEventSSEStreams(t, resp, releaseSecond)
}

// TestForwardProxy_SSE_StreamsAndScansWhenEnabled asserts the per-event
// scanning path still flushes clean events promptly. Same release-channel
// proof: client must read event 1 before upstream writes event 2.
func TestForwardProxy_SSE_StreamsAndScansWhenEnabled(t *testing.T) {
	releaseSecond := make(chan struct{})
	backend := newIPv4Server(t, emitTwoEventSSE(t, releaseSecond))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.SSEStreaming.Enabled = true
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertTwoEventSSEStreams(t, resp, releaseSecond)
}

// TestForwardProxy_SSE_BlocksDLPWhenParentResponseScanningDisabled proves
// the decoupled activation gate does not turn parent response-scanner opt-out
// into a DLP bypass. The child SSE scanner defaults on, so disabling
// response_scanning.enabled still streams promptly and still blocks a leaking
// event unless response_scanning.sse_streaming.enabled is explicitly false.
func TestForwardProxy_SSE_BlocksDLPWhenParentResponseScanningDisabled(t *testing.T) {
	leakToken := sseDecoupledFakeAWSKey()
	releaseSecond := make(chan struct{})

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", sseDecoupledFirst)
		if flusher != nil {
			flusher.Flush()
		}
		<-releaseSecond
		_, _ = fmt.Fprintf(w, "data: leaking %s\n\n", leakToken)
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/leak", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	sc := bufio.NewScanner(resp.Body)
	first := readNextSSEData(t, sc)
	if first != sseDecoupledFirst {
		t.Fatalf("first event = %q, want %q", first, sseDecoupledFirst)
	}

	close(releaseSecond)

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), leakToken) {
		t.Fatalf("leak token reached client with parent response scanner disabled: %q", body)
	}
}

// TestForwardProxy_SSE_BlocksDLPInEventWhenScanningOn asserts the
// streaming path does not bypass DLP. The clean first event flushes
// through, but a second event carrying a fake AWS access key terminates
// the stream. This is the security baseline that prevents the
// streaming-mode fix from being usable as a leak channel.
func TestForwardProxy_SSE_BlocksDLPInEventWhenScanningOn(t *testing.T) {
	leakToken := sseDecoupledFakeAWSKey()
	releaseSecond := make(chan struct{})

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", sseDecoupledFirst)
		if flusher != nil {
			flusher.Flush()
		}
		<-releaseSecond
		_, _ = fmt.Fprintf(w, "data: leaking %s\n\n", leakToken)
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.SSEStreaming.Enabled = true
		cfg.ResponseScanning.SSEStreaming.Action = config.ActionBlock
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/leak", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	sc := bufio.NewScanner(resp.Body)
	first := readNextSSEData(t, sc)
	if first != sseDecoupledFirst {
		t.Fatalf("first event = %q, want %q", first, sseDecoupledFirst)
	}

	close(releaseSecond)

	// The streaming scanner terminates on detection. The client may see
	// the connection close before the leaking second event arrives, or it
	// may see a truncated/empty body. Either way the leak token must NOT
	// be in any bytes the client received.
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), leakToken) {
		t.Fatalf("leak token reached client through streaming path: %q", body)
	}
}

// TestInterceptTunnel_SSE_StreamsWhenScanningDisabled is the TLS-MITM
// parity test for the forward-proxy regression above. Same release-
// channel proof, same fix surface.
func TestInterceptTunnel_SSE_StreamsWhenScanningDisabled(t *testing.T) {
	releaseSecond := make(chan struct{})
	upstream := httptest.NewTLSServer(emitTwoEventSSE(t, releaseSecond))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.ResponseScanning.Enabled = false
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })

	host := upstream.Listener.Addr().(*net.TCPAddr).IP.String()
	port := fmt.Sprintf("%d", upstream.Listener.Addr().(*net.TCPAddr).Port)

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: host,
			TargetPort: port,
			Config:     cfg,
			Scanner:    sc,
			CertCache:  cache,
			Logger:     logger,
			Metrics:    m,
			ClientIP:   "10.0.0.1",
			RequestID:  "test-sse-streams",
			UpstreamRT: upstream.Client().Transport,
		})
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+":"+port+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	assertTwoEventSSEStreams(t, resp, releaseSecond)
}

// TestInterceptTunnel_SSE_StreamsWithMediaPolicyDefault is the second
// half of TLS-MITM parity: MediaPolicy default true must not buffer
// text/event-stream responses.
func TestInterceptTunnel_SSE_StreamsWithMediaPolicyDefault(t *testing.T) {
	releaseSecond := make(chan struct{})
	upstream := httptest.NewTLSServer(emitTwoEventSSE(t, releaseSecond))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.ResponseScanning.Enabled = false
	enabledTrue := true
	cfg.MediaPolicy.Enabled = &enabledTrue
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })

	host := upstream.Listener.Addr().(*net.TCPAddr).IP.String()
	port := fmt.Sprintf("%d", upstream.Listener.Addr().(*net.TCPAddr).Port)

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: host,
			TargetPort: port,
			Config:     cfg,
			Scanner:    sc,
			CertCache:  cache,
			Logger:     logger,
			Metrics:    m,
			ClientIP:   "10.0.0.1",
			RequestID:  "test-sse-media",
			UpstreamRT: upstream.Client().Transport,
		})
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+":"+port+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	assertTwoEventSSEStreams(t, resp, releaseSecond)
}

// buildExifJPEGFixture builds a minimal valid JPEG (SOI, a strippable APP1/EXIF
// segment of payloadLen bytes, SOS + scan, EOI). Media policy would strip the
// APP1; the total size lets a test set MaxResponseBytes below it.
func buildExifJPEGFixture(payloadLen int) []byte {
	b := []byte{0xFF, 0xD8} // SOI
	payload := append([]byte("Exif\x00\x00"), make([]byte, payloadLen)...)
	segLen := len(payload) + 2 // length field includes its own 2 bytes
	// Panic (not t.Fatal) so gosec's SSA value-range analysis narrows segLen
	// to a uint16-safe interval before the byte casts below (G115).
	if segLen < 0 || segLen > 0xFFFF {
		panic("buildExifJPEGFixture: segment length exceeds JPEG 16-bit limit")
	}
	b = append(b, 0xFF, 0xE1, byte(segLen>>8), byte(segLen&0xFF))
	b = append(b, payload...)
	b = append(b, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x3F, 0x00) // SOS
	b = append(b, 0x11, 0x22, 0xFF, 0x00, 0x33)                               // scan
	b = append(b, 0xFF, 0xD9)                                                 // EOI
	return b
}

// TestInterceptTunnel_ExemptDomain_StreamsBodyIntact asserts that a response
// from a host in response_scanning.exempt_domains streams through byte-intact:
// no media-policy metadata strip and no response-size block, even though the
// body exceeds MaxResponseBytes and carries strippable EXIF. This is the
// trusted-destination file-transfer path (e.g. signed download URLs).
func TestInterceptTunnel_ExemptDomain_StreamsBodyIntact(t *testing.T) {
	jpeg := buildExifJPEGFixture(256)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(jpeg)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	host := upstream.Listener.Addr().(*net.TCPAddr).IP.String()
	port := fmt.Sprintf("%d", upstream.Listener.Addr().(*net.TCPAddr).Port)
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.ExemptDomains = []string{host}
	enabledTrue := true
	cfg.MediaPolicy.Enabled = &enabledTrue
	cfg.MediaPolicy.StripImageMetadata = &enabledTrue
	cfg.TLSInterception.MaxResponseBytes = 64 // below the image size: non-exempt would size-block
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: host, TargetPort: port, Config: cfg, Scanner: sc,
			CertCache: cache, Logger: logger, Metrics: m,
			ClientIP: "10.0.0.1", RequestID: "test-exempt-passthrough",
			UpstreamRT: upstream.Client().Transport,
		})
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { _ = tlsConn.Close() })

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+":"+port+"/photo.jpg", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (exempt host must not be size-blocked)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != string(jpeg) {
		t.Errorf("body altered: got %d bytes, want %d (exempt host must stream intact)", len(body), len(jpeg))
	}
	if !strings.Contains(string(body), "Exif") {
		t.Error("EXIF APP1 stripped; media policy ran on an exempt host")
	}
}

// TestInterceptTunnel_ExemptDomain_MediaPolicyRunsWhenResponseScanDisabled
// asserts the exempt passthrough is gated on response scanning being enabled.
// With response_scanning disabled, an exempt host's image must still go through
// media policy (EXIF stripped), preserving the "media policy runs even when
// response scanning is disabled" invariant and matching the validator warning
// that exempt_domains only takes effect when response scanning is enabled.
func TestInterceptTunnel_ExemptDomain_MediaPolicyRunsWhenResponseScanDisabled(t *testing.T) {
	jpeg := buildExifJPEGFixture(256)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(jpeg)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	host := upstream.Listener.Addr().(*net.TCPAddr).IP.String()
	port := fmt.Sprintf("%d", upstream.Listener.Addr().(*net.TCPAddr).Port)
	cfg.ResponseScanning.Enabled = false                // disabled
	cfg.ResponseScanning.ExemptDomains = []string{host} // but host listed exempt
	enabledTrue := true
	cfg.MediaPolicy.Enabled = &enabledTrue
	cfg.MediaPolicy.StripImageMetadata = &enabledTrue
	cfg.TLSInterception.MaxResponseBytes = 10 << 20 // large: media strip is what we assert, not size
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: host, TargetPort: port, Config: cfg, Scanner: sc,
			CertCache: cache, Logger: logger, Metrics: m,
			ClientIP: "10.0.0.1", RequestID: "test-exempt-scan-disabled",
			UpstreamRT: upstream.Client().Transport,
		})
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { _ = tlsConn.Close() })

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+":"+port+"/photo.jpg", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(string(body), "Exif") {
		t.Error("EXIF survived: media policy did not run on exempt host with response scanning disabled (passthrough not gated)")
	}
	if string(body) == string(jpeg) {
		t.Error("body unchanged: media policy did not strip (passthrough incorrectly triggered while response scanning disabled)")
	}
}
