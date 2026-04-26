// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// scannerUnavailableProxy builds a Proxy whose scanner is already closed.
// pinResolvedScanner triple-fails because every BeginUse call hits the
// closed flag, exercising the fail-closed branch in fetch / forward /
// WebSocket handlers. Returns the proxy, the recorder dir for receipt
// extraction, and a closeRec teardown.
func scannerUnavailableProxy(t *testing.T) (p *Proxy, dir string, closeRec func()) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	// Enable every transport whose fail-closed branch we want to cover.
	// buildHandler gates CONNECT and absolute-URI dispatch on
	// ForwardProxy.Enabled; the WebSocket entry point is gated on
	// WebSocketProxy.Enabled.
	cfg.ForwardProxy.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	cfg.ApplyDefaults()

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	sc.Close() // pinResolvedScanner triple-fails: resolved.Scanner == p.scannerPtr.Load() == this closed scanner.

	dir = t.TempDir()
	emitter, rec, _ := newCoverageEmitter(t, dir)

	proxy, err := New(cfg, logger, sc, metrics.New(),
		WithRecorder(rec),
		WithReceiptEmitter(emitter),
	)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return proxy, dir, func() {
		if err := rec.Close(); err != nil {
			t.Fatalf("recorder.Close: %v", err)
		}
	}
}

// assertScannerUnavailableReceipt finds the scanner_unavailable receipt
// in dir and verifies its shape. Centralizes the assertions so each
// transport-specific test reads as a wire-level scenario.
func assertScannerUnavailableReceipt(t *testing.T, dir, wantTransport string) {
	t.Helper()
	waitForReceiptOrTimeout(t, dir)
	receipts := extractReceiptsFromDir(t, dir)
	r := findReceiptByLayer(t, receipts, scannerLabelUnavailable)
	if r.ActionRecord.Transport != wantTransport {
		t.Errorf("Transport = %q, want %q", r.ActionRecord.Transport, wantTransport)
	}
	if r.ActionRecord.Verdict != config.ActionBlock {
		t.Errorf("Verdict = %q, want %q", r.ActionRecord.Verdict, config.ActionBlock)
	}
	if !strings.Contains(r.ActionRecord.Pattern, "scanner unavailable") {
		t.Errorf("Pattern = %q, expected substring %q", r.ActionRecord.Pattern, "scanner unavailable")
	}
	if r.ActionRecord.ActionID == "" {
		t.Error("ActionID empty on scanner_unavailable receipt")
	}
}

// TestHandleFetch_ScannerUnavailable_FailsClosedAndAttests verifies that
// when pinResolvedScanner cannot acquire the scanner during reload thrash,
// the fetch handler returns 503 AND emits an attested deny receipt under
// LayerUnavailable rather than silently dropping the request.
func TestHandleFetch_ScannerUnavailable_FailsClosedAndAttests(t *testing.T) {
	p, dir, closeRec := scannerUnavailableProxy(t)
	t.Cleanup(closeRec)

	srv := newIPv4Server(t, p.buildHandler(p.buildMux()))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/fetch?url=https://example.com/page", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	closeRec()
	assertScannerUnavailableReceipt(t, dir, TransportFetch)
}

// TestHandleConnect_ScannerUnavailable_FailsClosedAndAttests covers the
// CONNECT tunnel entry. The forward handler dispatches CONNECT through
// pinResolvedScanner before any tunnel setup, so a closed scanner makes
// the request fail closed at the request line with a 503.
func TestHandleConnect_ScannerUnavailable_FailsClosedAndAttests(t *testing.T) {
	p, dir, closeRec := scannerUnavailableProxy(t)
	t.Cleanup(closeRec)

	srv := newIPv4Server(t, p.buildHandler(p.buildMux()))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", host)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	closeRec()
	assertScannerUnavailableReceipt(t, dir, TransportConnect)
}

// TestHandleForward_ScannerUnavailable_FailsClosedAndAttests covers the
// absolute-URI forward path: a request with an absolute URL in the
// request-line (rather than CONNECT or /fetch?url=). pinResolvedScanner
// runs before any scanning logic.
func TestHandleForward_ScannerUnavailable_FailsClosedAndAttests(t *testing.T) {
	p, dir, closeRec := scannerUnavailableProxy(t)
	t.Cleanup(closeRec)

	srv := newIPv4Server(t, p.buildHandler(p.buildMux()))
	t.Cleanup(srv.Close)

	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://example.com/data", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	closeRec()
	assertScannerUnavailableReceipt(t, dir, TransportForward)
}

// TestHandleWebSocket_ScannerUnavailable_FailsClosedAndAttests covers the
// WebSocket handler's fail-closed branch.
func TestHandleWebSocket_ScannerUnavailable_FailsClosedAndAttests(t *testing.T) {
	p, dir, closeRec := scannerUnavailableProxy(t)
	t.Cleanup(closeRec)

	srv := newIPv4Server(t, p.buildHandler(p.buildMux()))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/ws?url=ws%3A%2F%2Fexample.com%2Fchat", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	closeRec()
	assertScannerUnavailableReceipt(t, dir, TransportWS)
}

// TestReverseProxy_ScannerUnavailable_FailsClosedAndAttests covers the
// reverse-proxy snapshotAndAcquire fail-closed branch, which uses a
// separate handler type than the four above.
func TestReverseProxy_ScannerUnavailable_FailsClosedAndAttests(t *testing.T) {
	cfg := reverseTestConfig()

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	upstreamURL, _ := url.Parse("http://127.0.0.1:1") // never dialed; fail-closed before forward.
	sc := scanner.New(cfg)
	sc.Close() // snapshotAndAcquire triple-fails.

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	rp := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger,
		metrics.New(), killswitch.New(cfg), nil, nil)

	dir := t.TempDir()
	emitter, rec, _ := newCoverageEmitter(t, dir)
	var emPtr atomic.Pointer[receipt.Emitter]
	emPtr.Store(emitter)
	rp.SetReceiptEmitter(&emPtr)

	srv := newIPv4Server(t, rp)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/data", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	assertScannerUnavailableReceipt(t, dir, TransportReverse)
}
