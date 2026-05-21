// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type captureMetadataObserver struct {
	mu      sync.Mutex
	records []capture.CaptureSummary
	ch      chan capture.CaptureSummary
}

func newCaptureMetadataObserver() *captureMetadataObserver {
	return &captureMetadataObserver{ch: make(chan capture.CaptureSummary, 16)}
}

func (o *captureMetadataObserver) append(s capture.CaptureSummary) {
	o.mu.Lock()
	o.records = append(o.records, s)
	o.mu.Unlock()
	o.ch <- s
}

func (o *captureMetadataObserver) ObserveURLVerdict(_ context.Context, rec *capture.URLVerdictRecord) {
	o.append(summaryFromURLRecord(rec))
}

func (o *captureMetadataObserver) ObserveResponseVerdict(_ context.Context, rec *capture.ResponseVerdictRecord) {
	o.append(capture.CaptureSummary{
		Surface:           capture.SurfaceResponse,
		Subsurface:        rec.Subsurface,
		ConfigHash:        rec.ConfigHash,
		Agent:             rec.Agent,
		Profile:           rec.Profile,
		ActionClass:       rec.ActionClass,
		SessionIDOriginal: rec.SessionIDOriginal,
		EffectiveAction:   rec.EffectiveAction,
		Outcome:           rec.Outcome,
		Request:           rec.Request,
	})
}

func (o *captureMetadataObserver) ObserveDLPVerdict(_ context.Context, rec *capture.DLPVerdictRecord) {
	o.append(capture.CaptureSummary{
		Surface:           capture.SurfaceDLP,
		Subsurface:        rec.Subsurface,
		ConfigHash:        rec.ConfigHash,
		Agent:             rec.Agent,
		Profile:           rec.Profile,
		ActionClass:       rec.ActionClass,
		SessionIDOriginal: rec.SessionIDOriginal,
		EffectiveAction:   rec.EffectiveAction,
		Outcome:           rec.Outcome,
		Request:           rec.Request,
	})
}

func (o *captureMetadataObserver) ObserveCEEVerdict(_ context.Context, rec *capture.CEERecord) {
	o.append(capture.CaptureSummary{
		Surface:           capture.SurfaceCEE,
		Subsurface:        rec.Subsurface,
		ConfigHash:        rec.ConfigHash,
		Agent:             rec.Agent,
		Profile:           rec.Profile,
		ActionClass:       rec.ActionClass,
		SessionIDOriginal: rec.SessionIDOriginal,
		EffectiveAction:   rec.EffectiveAction,
		Outcome:           rec.Outcome,
		Request:           rec.Request,
	})
}

func (o *captureMetadataObserver) ObserveToolPolicyVerdict(_ context.Context, rec *capture.ToolPolicyRecord) {
	o.append(capture.CaptureSummary{
		Surface:           capture.SurfaceToolPolicy,
		Subsurface:        rec.Subsurface,
		ConfigHash:        rec.ConfigHash,
		Agent:             rec.Agent,
		Profile:           rec.Profile,
		ActionClass:       rec.ActionClass,
		SessionIDOriginal: rec.SessionIDOriginal,
		EffectiveAction:   rec.EffectiveAction,
		Outcome:           rec.Outcome,
		Request:           rec.Request,
	})
}

func (o *captureMetadataObserver) ObserveToolScanVerdict(_ context.Context, rec *capture.ToolScanRecord) {
	o.append(capture.CaptureSummary{
		Surface:           capture.SurfaceToolScan,
		Subsurface:        rec.Subsurface,
		ConfigHash:        rec.ConfigHash,
		Agent:             rec.Agent,
		Profile:           rec.Profile,
		ActionClass:       rec.ActionClass,
		SessionIDOriginal: rec.SessionIDOriginal,
		EffectiveAction:   rec.EffectiveAction,
		Outcome:           rec.Outcome,
		Request:           rec.Request,
	})
}

func (o *captureMetadataObserver) Close() error { return nil }

func summaryFromURLRecord(rec *capture.URLVerdictRecord) capture.CaptureSummary {
	return capture.CaptureSummary{
		Surface:           capture.SurfaceURL,
		Subsurface:        rec.Subsurface,
		ConfigHash:        rec.ConfigHash,
		Agent:             rec.Agent,
		Profile:           rec.Profile,
		ActionClass:       rec.ActionClass,
		SessionIDOriginal: rec.SessionIDOriginal,
		EffectiveAction:   rec.EffectiveAction,
		Outcome:           rec.Outcome,
		Request:           rec.Request,
	}
}

func requireCaptureMetadata(t *testing.T, got capture.CaptureSummary, surface, subsurface string) {
	t.Helper()
	if got.Surface != surface {
		t.Fatalf("surface = %q, want %q (record=%+v)", got.Surface, surface, got)
	}
	if got.Subsurface != subsurface {
		t.Fatalf("subsurface = %q, want %q (record=%+v)", got.Subsurface, subsurface, got)
	}
	for field, value := range map[string]string{
		"config_hash":      got.ConfigHash,
		"profile":          got.Profile,
		"agent":            got.Agent,
		"action_class":     got.ActionClass,
		"effective_action": got.EffectiveAction,
		"outcome":          got.Outcome,
	} {
		if value == "" {
			t.Fatalf("%s is empty in capture record: %+v", field, got)
		}
	}
}

func waitCaptureRecord(t *testing.T, obs *captureMetadataObserver, surface, subsurface string) capture.CaptureSummary {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-obs.ch:
			if got.Surface == surface && got.Subsurface == subsurface {
				return got
			}
		case <-deadline:
			t.Fatalf("timeout waiting for capture record surface=%s subsurface=%s", surface, subsurface)
		}
	}
}

func newCaptureMetadataProxy(t *testing.T, cfg *config.Config, obs *captureMetadataObserver) *Proxy {
	t.Helper()
	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New(), WithCaptureObserver(obs))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func captureMetadataConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	cfg.WebSocketProxy.MaxMessageBytes = 1048576
	cfg.WebSocketProxy.MaxConcurrentConnections = 128
	cfg.WebSocketProxy.MaxConnectionSeconds = 10
	cfg.WebSocketProxy.IdleTimeoutSeconds = 5
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.ApplyDefaults()
	cfg.Internal = nil
	return cfg
}

func TestCaptureMetadata_ForwardTransport(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	obs := newCaptureMetadataObserver()
	p := newCaptureMetadataProxy(t, captureMetadataConfig(), obs)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleForwardHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	got := waitCaptureRecord(t, obs, capture.SurfaceURL, "forward_url")
	requireCaptureMetadata(t, got, capture.SurfaceURL, "forward_url")
}

func TestCaptureMetadata_ReverseTransport(t *testing.T) {
	t.Parallel()

	cfg := captureMetadataConfig()
	obs := newCaptureMetadataObserver()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should not be reached"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)
	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, audit.NewNop(), metrics.New(), killswitch.New(cfg), obs, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api", strings.NewReader(`{"key":"`+fakeAPIKey()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(AgentHeader, "reverse-agent")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reverse status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	got := waitCaptureRecord(t, obs, capture.SurfaceDLP, "dlp_reverse_request")
	requireCaptureMetadata(t, got, capture.SurfaceDLP, "dlp_reverse_request")
}

func TestCaptureMetadata_WebSocketTransport(t *testing.T) {
	t.Parallel()

	backendAddr, backendClose := wsEchoServer(t)
	defer backendClose()

	cfg := captureMetadataConfig()
	obs := newCaptureMetadataObserver()
	p := newCaptureMetadataProxy(t, cfg, obs)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	srv := &http.Server{
		Handler:           p.buildHandler(http.NewServeMux()),
		ReadHeaderTimeout: 5 * time.Second,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", p.handleWebSocket)
	srv.Handler = p.buildHandler(mux)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close() //nolint:errcheck // test cleanup

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, _, err := ws.Dialer{Extensions: nil}.Dial(ctx, "ws://"+ln.Addr().String()+"/ws?url=ws://"+backendAddr)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	_ = conn.Close()

	got := waitCaptureRecord(t, obs, capture.SurfaceURL, "ws_url")
	requireCaptureMetadata(t, got, capture.SurfaceURL, "ws_url")
}

// TestCaptureMetadata_InterceptTransport drives a TLS-intercepted GET through
// the intercept handler with a real Proxy + capture observer attached, and
// asserts the URL-pipeline capture record carries the metadata the LL pipeline
// needs (config_hash, profile, agent, effective_action, outcome). Closes the
// last gap in the v2.4 capture transport-parity matrix.
func TestCaptureMetadata_InterceptTransport(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
	enforceTrue := true
	cfg.Enforce = &enforceTrue

	obs := newCaptureMetadataObserver()
	p, err := New(cfg, logger, sc, m, WithCaptureObserver(obs))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

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
			ClientIP:   "10.0.0.42",
			RequestID:  "intercept-capture-test",
			Agent:      "intercept-agent",
			Profile:    "intercept-profile",
			UpstreamRT: upstream.Client().Transport,
			Proxy:      p,
		})
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(host, port)+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = net.JoinHostPort(host, port)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("intercept response status = %d, want 200", resp.StatusCode)
	}

	got := waitCaptureRecord(t, obs, capture.SurfaceURL, "intercept_url")
	requireCaptureMetadata(t, got, capture.SurfaceURL, "intercept_url")
	if got.Agent != "intercept-agent" {
		t.Fatalf("agent = %q, want intercept-agent", got.Agent)
	}
	if got.Profile != "intercept-profile" {
		t.Fatalf("profile = %q, want intercept-profile", got.Profile)
	}
}
