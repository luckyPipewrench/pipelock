// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/hex"
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

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func enableInboundEnvelopeVerificationForTest(t *testing.T, cfg *config.Config) {
	t.Helper()

	pub, _ := testInboundEnvelopeKey(t)
	cfg.MediationEnvelope.VerifyInbound.Enabled = true
	cfg.MediationEnvelope.VerifyInbound.TrustList = []config.MediationEnvelopeTrustedKey{{
		KeyID:        "partner-key",
		PublicKey:    hex.EncodeToString(pub),
		TrustDomains: []string{"partner.example"},
	}}
	cfg.MediationEnvelope.VerifyInbound.ReplayCache.Window = "5m"
	cfg.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries = 32
}

func TestFetchInboundEnvelopeVerificationMissingHeaderBlocks(t *testing.T) {
	t.Parallel()

	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		enableInboundEnvelopeVerificationForTest(t, cfg)
	})
	defer cleanup()

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"http://"+proxyAddr+"/fetch?url="+url.QueryEscape(upstream.URL+"/missing-envelope"),
		nil,
	)
	if err != nil {
		t.Fatalf("new fetch request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "inbound mediation envelope verification failed") {
		t.Fatalf("response body = %q", body)
	}
	if upstreamHit.Load() {
		t.Fatal("upstream should not be reached without inbound envelope")
	}
}

func TestForwardHTTPInboundEnvelopeVerificationMissingHeaderBlocks(t *testing.T) {
	t.Parallel()

	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		enableInboundEnvelopeVerificationForTest(t, cfg)
	})
	defer cleanup()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/missing-envelope", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseProxyURL(t, proxyAddr))}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward HTTP request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if upstreamHit.Load() {
		t.Fatal("upstream should not be reached without inbound envelope")
	}
}

func TestConnectInboundEnvelopeVerificationMissingHeaderBlocks(t *testing.T) {
	t.Parallel()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		enableInboundEnvelopeVerificationForTest(t, cfg)
	})
	defer cleanup()

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "403 Forbidden") {
		t.Fatalf("CONNECT response = %q, want 403", got)
	}
}

func TestWebSocketInboundEnvelopeVerificationMissingHeaderBlocks(t *testing.T) {
	t.Parallel()

	var upstreamHit atomic.Bool
	upLn := listenWebSocketInboundUpstream(t, &upstreamHit)

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.WebSocketProxy.Enabled = true
	cfg.WebSocketProxy.MaxMessageBytes = 1048576
	cfg.WebSocketProxy.MaxConcurrentConnections = 128
	cfg.WebSocketProxy.MaxConnectionSeconds = 10
	cfg.WebSocketProxy.IdleTimeoutSeconds = 5
	enableInboundEnvelopeVerificationForTest(t, cfg)

	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	lc := net.ListenConfig{}
	proxyLn, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ws", p.handleWebSocket)
		srv := &http.Server{
			Handler:           p.buildHandler(mux),
			ReadHeaderTimeout: 5 * time.Second,
			BaseContext:       func(_ net.Listener) context.Context { return ctx },
		}
		_ = srv.Serve(proxyLn)
	}()

	wsURL := fmt.Sprintf("ws://%s/ws?url=ws://%s", proxyLn.Addr().String(), upLn.Addr().String())
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, _, _, err := ws.Dial(dialCtx, wsURL)
	if err == nil {
		_ = conn.Close()
		t.Fatal("websocket dial should fail without inbound envelope")
	}
	if upstreamHit.Load() {
		t.Fatal("upstream websocket should not be reached without inbound envelope")
	}
}

func listenWebSocketInboundUpstream(t *testing.T, hit *atomic.Bool) net.Listener {
	t.Helper()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit.Store(true)
				conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
				if upgradeErr == nil {
					_ = conn.Close()
				}
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		_ = srv.Serve(ln)
	}()
	return ln
}

func TestReverseProxyInboundEnvelopeVerificationMissingHeaderBlocks(t *testing.T) {
	t.Parallel()

	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cfg := reverseTestConfig()
	enableInboundEnvelopeVerificationForTest(t, cfg)
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	handler := NewReverseProxy(
		upstreamURL,
		&cfgPtr,
		&scPtr,
		audit.NewNop(),
		metrics.New(),
		killswitch.New(cfg),
		nil,
		nil,
	)
	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	handler.SetEnvelopeVerifier(&p.envelopeVerifierPtr)

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/missing-envelope", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if upstreamHit.Load() {
		t.Fatal("upstream should not be reached without inbound envelope")
	}
}
