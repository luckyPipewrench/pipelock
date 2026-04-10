// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const testEnvelopeConfigHash = "abcdef0123456789abcdef0123456789"

// TestEnvelope_FetchInjectsHeader boots a proxy with envelope emission enabled,
// sends a fetch request, and verifies the upstream receives the
// Pipelock-Mediation header.
func TestEnvelope_FetchInjectsHeader(t *testing.T) {
	t.Parallel()

	// Upstream captures inbound request headers.
	var gotHeader string
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = true

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})

	p, err := New(cfg, logger, sc, metrics.New(),
		WithEnvelopeEmitter(em),
	)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL+"/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if gotHeader == "" {
		t.Fatal("upstream did not receive Pipelock-Mediation header")
	}

	// Parse the envelope and verify key fields.
	env, parseErr := envelope.Parse(gotHeader)
	if parseErr != nil {
		t.Fatalf("parse envelope: %v", parseErr)
	}
	if env.Version != 1 {
		t.Errorf("Version = %d, want 1", env.Version)
	}
	if env.Action != "read" {
		t.Errorf("Action = %q, want %q", env.Action, "read")
	}
	if env.Verdict != config.ActionAllow {
		t.Errorf("Verdict = %q, want %q", env.Verdict, config.ActionAllow)
	}
	if env.SideEffect != "external_read" {
		t.Errorf("SideEffect = %q, want %q", env.SideEffect, "external_read")
	}
	if env.Timestamp == 0 {
		t.Error("Timestamp should be non-zero")
	}
	if env.ReceiptID == "" {
		t.Error("ReceiptID should be non-empty")
	}
}

// TestEnvelope_FetchNoEmitter verifies that no Pipelock-Mediation header is
// injected when no envelope emitter is configured.
func TestEnvelope_FetchNoEmitter(t *testing.T) {
	t.Parallel()

	var gotHeader string
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)

	// No WithEnvelopeEmitter -- emitter is nil.
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL+"/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if gotHeader != "" {
		t.Errorf("expected no Pipelock-Mediation header, got: %q", gotHeader)
	}
}

// TestEnvelope_FetchStripsInbound verifies that an agent-supplied
// Pipelock-Mediation header is stripped before scanning (and replaced if
// envelope emission is enabled).
func TestEnvelope_FetchStripsInbound(t *testing.T) {
	t.Parallel()

	var gotHeader string
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = true

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})

	p, err := New(cfg, logger, sc, metrics.New(),
		WithEnvelopeEmitter(em),
	)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL+"/test", nil)
	// Inject a spoofed header.
	req.Header.Set(envelope.HeaderName, "act=\"spoofed\", vd=\"spoofed\"")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if gotHeader == "" {
		t.Fatal("upstream should receive a (genuine) Pipelock-Mediation header")
	}
	if strings.Contains(gotHeader, "spoofed") {
		t.Errorf("spoofed envelope reached upstream: %q", gotHeader)
	}
}

// TestEnvelope_ForwardHTTPInjectsHeader sends an absolute-URI HTTP request
// through the forward proxy and verifies the upstream receives the
// Pipelock-Mediation header.
func TestEnvelope_ForwardHTTPInjectsHeader(t *testing.T) {
	t.Parallel()

	// Destination server captures the mediation header.
	var gotHeader string
	dest := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "method=%s path=%s", r.Method, r.URL.Path)
	}))
	defer dest.Close()

	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})

	// Set up forward proxy with envelope emitter.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.MediationEnvelope.Enabled = true

	savedInternal := cfg.Internal
	cfg.ApplyDefaults()
	cfg.Internal = savedInternal

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m, WithEnvelopeEmitter(em))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, dest.URL+"/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}

	if gotHeader == "" {
		t.Fatal("upstream did not receive Pipelock-Mediation header via forward proxy")
	}

	// Parse and verify.
	env, parseErr := envelope.Parse(gotHeader)
	if parseErr != nil {
		t.Fatalf("parse envelope: %v", parseErr)
	}
	if env.Version != 1 {
		t.Errorf("Version = %d, want 1", env.Version)
	}
	if env.Verdict != config.ActionAllow {
		t.Errorf("Verdict = %q, want %q", env.Verdict, config.ActionAllow)
	}
	if env.ReceiptID == "" {
		t.Error("ReceiptID should be non-empty")
	}

	p.Close()
}

// TestEnvelope_ForwardHTTPNoEmitter verifies that the forward proxy does not
// inject an envelope header when no emitter is configured.
func TestEnvelope_ForwardHTTPNoEmitter(t *testing.T) {
	t.Parallel()

	var gotHeader string
	dest := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer dest.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, dest.URL+"/test")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}
	if gotHeader != "" {
		t.Errorf("expected no Pipelock-Mediation header without emitter, got: %q", gotHeader)
	}
}

// TestEnvelope_ForwardHTTPStripsInbound verifies that a spoofed
// Pipelock-Mediation header from the agent is stripped by the forward proxy.
func TestEnvelope_ForwardHTTPStripsInbound(t *testing.T) {
	t.Parallel()

	var gotHeader string
	dest := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer dest.Close()

	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.MediationEnvelope.Enabled = true

	savedInternal := cfg.Internal
	cfg.ApplyDefaults()
	cfg.Internal = savedInternal

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m, WithEnvelopeEmitter(em))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/fetch", p.handleFetch)
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
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, dest.URL+"/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Inject spoofed header.
	req.Header.Set(envelope.HeaderName, "act=\"spoofed\", vd=\"spoofed\"")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}
	if gotHeader == "" {
		t.Fatal("upstream should receive a genuine Pipelock-Mediation header")
	}
	if strings.Contains(gotHeader, "spoofed") {
		t.Errorf("spoofed envelope reached upstream via forward proxy: %q", gotHeader)
	}

	p.Close()
}

// TestEnvelope_ReloadEnablesEmitter verifies that reloading with
// MediationEnvelope.Enabled=true creates an envelope emitter when the proxy
// started without one.
func TestEnvelope_ReloadEnablesEmitter(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = false

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()

	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	if p.envelopeEmitterPtr.Load() != nil {
		t.Fatal("expected nil emitter before reload")
	}

	// Reload with envelope enabled.
	reloadCfg := config.Defaults()
	reloadCfg.Internal = nil
	reloadCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	reloadCfg.MediationEnvelope.Enabled = true
	reloadSc := scanner.New(reloadCfg)

	p.Reload(reloadCfg, reloadSc)

	if p.envelopeEmitterPtr.Load() == nil {
		t.Fatal("expected non-nil emitter after reload with envelope enabled")
	}
}

// TestEnvelope_ReloadDisablesEmitter verifies that reloading with
// MediationEnvelope.Enabled=false nils the envelope emitter.
func TestEnvelope_ReloadDisablesEmitter(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = true

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})

	p, err := New(cfg, logger, sc, m, WithEnvelopeEmitter(em))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	if p.envelopeEmitterPtr.Load() == nil {
		t.Fatal("expected non-nil emitter before reload")
	}

	// Reload with envelope disabled.
	reloadCfg := config.Defaults()
	reloadCfg.Internal = nil
	reloadCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	reloadCfg.MediationEnvelope.Enabled = false
	reloadSc := scanner.New(reloadCfg)

	p.Reload(reloadCfg, reloadSc)

	if p.envelopeEmitterPtr.Load() != nil {
		t.Fatal("expected nil emitter after reload with envelope disabled")
	}
}

// TestEnvelope_ReloadUpdatesHash verifies that reloading with the emitter
// already active updates the config hash without replacing the emitter.
func TestEnvelope_ReloadUpdatesHash(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = true

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})

	p, err := New(cfg, logger, sc, m, WithEnvelopeEmitter(em))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	origEmitter := p.envelopeEmitterPtr.Load()
	if origEmitter == nil {
		t.Fatal("expected non-nil emitter before reload")
	}

	// Reload with different config (changes hash) but same enabled state.
	reloadCfg := config.Defaults()
	reloadCfg.Internal = nil
	reloadCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	reloadCfg.MediationEnvelope.Enabled = true
	reloadCfg.FetchProxy.Monitoring.Blocklist = []string{"evil.example.com"}
	reloadSc := scanner.New(reloadCfg)

	p.Reload(reloadCfg, reloadSc)

	newEmitter := p.envelopeEmitterPtr.Load()
	if newEmitter == nil {
		t.Fatal("expected non-nil emitter after reload")
	}
	// Same emitter instance -- UpdateConfigHash was called, not replaced.
	if newEmitter != origEmitter {
		t.Fatal("expected same emitter instance (hash update, not replacement)")
	}
}

// TestEnvelope_EnvelopeEmitterPtrAccessor verifies that EnvelopeEmitterPtr()
// returns a pointer that tracks the proxy's atomic envelope emitter.
func TestEnvelope_EnvelopeEmitterPtrAccessor(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	m := metrics.New()

	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	ptr := p.EnvelopeEmitterPtr()
	if ptr == nil {
		t.Fatal("EnvelopeEmitterPtr() returned nil")
	}

	// Initially nil emitter.
	if ptr.Load() != nil {
		t.Fatal("expected nil emitter initially")
	}

	// Store an emitter and verify it's visible through the pointer.
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})
	ptr.Store(em)
	if ptr.Load() != em {
		t.Fatal("stored emitter not visible through pointer")
	}
}

// TestEnvelope_ReverseProxyInjectsHeader verifies that the reverse proxy
// handler injects the Pipelock-Mediation header when an envelope emitter
// is configured.
func TestEnvelope_ReverseProxyInjectsHeader(t *testing.T) {
	t.Parallel()

	var gotHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cfg := reverseTestConfig()

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	m := metrics.New()
	ks := killswitch.New(cfg)

	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, m, ks, nil, nil)

	// Wire the envelope emitter via SetEnvelopeEmitter.
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})
	var emPtr atomic.Pointer[envelope.Emitter]
	emPtr.Store(em)
	handler.SetEnvelopeEmitter(&emPtr)

	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, proxy.URL+"/test", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}

	if gotHeader == "" {
		t.Fatal("upstream did not receive Pipelock-Mediation header via reverse proxy")
	}

	// Parse and verify.
	env, parseErr := envelope.Parse(gotHeader)
	if parseErr != nil {
		t.Fatalf("parse envelope: %v", parseErr)
	}
	if env.Version != 1 {
		t.Errorf("Version = %d, want 1", env.Version)
	}
	if env.Verdict != config.ActionAllow {
		t.Errorf("Verdict = %q, want %q", env.Verdict, config.ActionAllow)
	}
	if env.ActorAuth != envelope.ActorAuthSelfDeclared {
		t.Errorf("ActorAuth = %q, want %q", env.ActorAuth, envelope.ActorAuthSelfDeclared)
	}
}

func TestEnvelope_ReverseProxyWarnBodyUsesWarnVerdict(t *testing.T) {
	t.Parallel()

	var gotHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cfg := reverseTestConfig()
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.ApplyDefaults()

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	m := metrics.New()
	ks := killswitch.New(cfg)
	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, m, ks, nil, nil)

	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})
	var emPtr atomic.Pointer[envelope.Emitter]
	emPtr.Store(em)
	handler.SetEnvelopeEmitter(&emPtr)

	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	fakeToken := "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	reqBody := fmt.Sprintf(`{"token":"%s"}`, fakeToken)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxy.URL+"/test", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}
	env, parseErr := envelope.Parse(gotHeader)
	if parseErr != nil {
		t.Fatalf("parse envelope: %v", parseErr)
	}
	if env.Verdict != config.ActionWarn {
		t.Fatalf("Verdict = %q, want %q", env.Verdict, config.ActionWarn)
	}
}

// TestEnvelope_ReverseProxyNoEmitter verifies that no Pipelock-Mediation
// header is injected when SetEnvelopeEmitter is not called.
func TestEnvelope_ReverseProxyNoEmitter(t *testing.T) {
	t.Parallel()

	var gotHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cfg := reverseTestConfig()

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	m := metrics.New()
	ks := killswitch.New(cfg)

	// No SetEnvelopeEmitter call.
	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, m, ks, nil, nil)

	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, proxy.URL+"/test", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}

	if gotHeader != "" {
		t.Errorf("expected no Pipelock-Mediation header, got: %q", gotHeader)
	}
}

// TestEnvelope_ReverseProxyStripsInbound verifies that a spoofed
// Pipelock-Mediation header from the client is stripped by the reverse proxy.
func TestEnvelope_ReverseProxyStripsInbound(t *testing.T) {
	t.Parallel()

	var gotHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(envelope.HeaderName)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cfg := reverseTestConfig()

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	m := metrics.New()
	ks := killswitch.New(cfg)

	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, m, ks, nil, nil)

	// Wire the envelope emitter.
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})
	var emPtr atomic.Pointer[envelope.Emitter]
	emPtr.Store(em)
	handler.SetEnvelopeEmitter(&emPtr)

	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, proxy.URL+"/test", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	// Inject spoofed header.
	req.Header.Set(envelope.HeaderName, "act=\"spoofed\", vd=\"spoofed\"")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d; body: %s", resp.StatusCode, body)
	}

	if gotHeader == "" {
		t.Fatal("upstream should receive a genuine Pipelock-Mediation header")
	}
	if strings.Contains(gotHeader, "spoofed") {
		t.Errorf("spoofed envelope reached upstream via reverse proxy: %q", gotHeader)
	}
}
