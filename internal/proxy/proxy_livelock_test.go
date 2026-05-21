// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func newFetchLiveLockProxy(t *testing.T, loader *contractruntime.Loader, upstreamAddr string) *Proxy {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5
	sc := scanner.New(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	if loader != nil {
		p.contractLoaderPtr.Store(loader)
	}
	installForwardTestDialer(p, upstreamAddr)
	return p
}

func serveFetchLiveLock(t *testing.T, p *Proxy, targetURL string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+targetURL, nil)
	req.Header.Set(AgentHeader, "agent-a")
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)
	return rec
}

func TestFetchLiveLock_NoActiveContractPassThrough(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := newFetchLiveLockProxy(t, emptyContractLoader(t), backend.Listener.Addr().String())
	rec := serveFetchLiveLock(t, p, "http://evil.example.com/v1/chat")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits.Load())
	}
}

func TestFetchLiveLock_AllowRulePasses(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodGet)
	p := newFetchLiveLockProxy(t, testContractLoader(t, contractruntime.ModeLive, rule), backend.Listener.Addr().String())
	rec := serveFetchLiveLock(t, p, "http://api.example.com/v1/chat")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits.Load())
	}
}

func TestFetchLiveLock_DefaultDenyBlocksUnmatchedDestination(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer backend.Close()

	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodGet)
	p := newFetchLiveLockProxy(t, testContractLoader(t, contractruntime.ModeLive, rule), backend.Listener.Addr().String())
	rec := serveFetchLiveLock(t, p, "http://evil.example.com/v1/chat")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != contractDefaultDenyReason {
		t.Fatalf("block reason = %q, want %s", got, contractDefaultDenyReason)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, want 0", hits.Load())
	}
}

func TestFetchLiveLock_ScannerBlockWinsOverContractAllow(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer backend.Close()

	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodGet)
	p := newFetchLiveLockProxy(t, testContractLoader(t, contractruntime.ModeLive, rule), backend.Listener.Addr().String())
	rec := serveFetchLiveLock(t, p, "http://api.example.com/v1/chat%250d%250aInjected:1")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.ParseError) {
		t.Fatalf("block reason = %q, want %s", got, blockreason.ParseError)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, want 0", hits.Load())
	}
}

func TestFetchLiveLock_ShadowModeObservesWithoutBlocking(t *testing.T) {
	fetchLiveLockObserveModeAllows(t, contractruntime.ModeShadow)
}

func TestFetchLiveLock_CaptureModeDoesNotBlock(t *testing.T) {
	fetchLiveLockObserveModeAllows(t, contractruntime.ModeCapture)
}

func fetchLiveLockObserveModeAllows(t *testing.T, mode contractruntime.Mode) {
	t.Helper()
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodGet)
	p := newFetchLiveLockProxy(t, testContractLoader(t, mode, rule), backend.Listener.Addr().String())
	rec := serveFetchLiveLock(t, p, "http://evil.example.com/v1/chat")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits.Load())
	}
}

func TestFetchLiveLock_KillSwitchBlocksBeforeContractAllow(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer backend.Close()

	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodGet)
	p := newFetchLiveLockProxy(t, testContractLoader(t, contractruntime.ModeLive, rule), backend.Listener.Addr().String())
	ks := killswitch.New(p.CurrentConfig())
	ks.SetAPI(true)
	p.ks = ks

	rec := serveFetchLiveLock(t, p, "http://api.example.com/v1/chat")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.KillSwitchActive) {
		t.Fatalf("block reason = %q, want %s", got, blockreason.KillSwitchActive)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, want 0", hits.Load())
	}
}

func doConnectLiveLock(t *testing.T, proxyAddr, target string) *http.Response {
	t.Helper()
	conn, resp := dialConnectLiveLock(t, proxyAddr, target)
	t.Cleanup(func() { _ = conn.Close() })
	return resp
}

func dialConnectLiveLock(t *testing.T, proxyAddr, target string) (net.Conn, *http.Response) {
	t.Helper()
	conn := dialProxy(t, proxyAddr)
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: agent-a\r\n\r\n", target, target, AgentHeader)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	return conn, resp
}

func assertConnectLiveLockEcho(t *testing.T, proxyAddr, target string, msg []byte) {
	t.Helper()
	conn, resp := dialConnectLiveLock(t, proxyAddr, target)
	defer func() { _ = conn.Close() }()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write CONNECT tunnel: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read CONNECT tunnel echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("CONNECT tunnel echo = %q, want %q", got, msg)
	}
}

func TestConnectLiveLock_NoActiveContractPassThrough(t *testing.T) {
	ln := listenEcho(t)
	defer func() { _ = ln.Close() }()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()
	p.contractLoaderPtr.Store(emptyContractLoader(t))

	resp := doConnectLiveLock(t, proxyAddr, ln.Addr().String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestConnectLiveLock_AllowRulePasses(t *testing.T) {
	ln := listenEcho(t)
	defer func() { _ = ln.Close() }()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
	p.ks = killswitch.New(p.CurrentConfig())
	rule := contractruntimetest.HTTPEnforceRule("r-connect", "127.0.0.1", "/", http.MethodConnect)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))

	assertConnectLiveLockEcho(t, proxyAddr, ln.Addr().String(), []byte("live lock connect allow"))
	assertContractContextAllowReceipt(t, rph, TransportConnect, contractruntime.WinningSourceContract)
}

func TestConnectLiveLock_DefaultDenyBlocksUnmatchedDestination(t *testing.T) {
	ln := listenEcho(t)
	defer func() { _ = ln.Close() }()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()
	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/", http.MethodConnect)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))

	resp := doConnectLiveLock(t, proxyAddr, ln.Addr().String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != contractDefaultDenyReason {
		t.Fatalf("block reason = %q, want %s", got, contractDefaultDenyReason)
	}
}

func TestConnectLiveLock_ScannerBlockWinsOverContractAllow(t *testing.T) {
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()
	fakeHost := "AKIA" + "IOSFODNN7EXAMPLE"
	rule := contractruntimetest.HTTPEnforceRule("r-connect", fakeHost, "/", http.MethodConnect)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))

	resp := doConnectLiveLock(t, proxyAddr, net.JoinHostPort(fakeHost, "443"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.DLPMatch) {
		t.Fatalf("block reason = %q, want %s", got, blockreason.DLPMatch)
	}
}

func TestConnectLiveLock_ShadowModeObservesWithoutBlocking(t *testing.T) {
	connectLiveLockObserveModeAllows(t, contractruntime.ModeShadow)
}

func TestConnectLiveLock_CaptureModeDoesNotBlock(t *testing.T) {
	connectLiveLockObserveModeAllows(t, contractruntime.ModeCapture)
}

func connectLiveLockObserveModeAllows(t *testing.T, mode contractruntime.Mode) {
	t.Helper()
	ln := listenEcho(t)
	defer func() { _ = ln.Close() }()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()
	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/", http.MethodConnect)
	p.contractLoaderPtr.Store(testContractLoader(t, mode, rule))

	resp := doConnectLiveLock(t, proxyAddr, ln.Addr().String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestConnectLiveLock_KillSwitchBlocksBeforeContractAllow(t *testing.T) {
	ln := listenEcho(t)
	defer func() { _ = ln.Close() }()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()
	rule := contractruntimetest.HTTPEnforceRule("r-connect", "127.0.0.1", "/", http.MethodConnect)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))
	ks := killswitch.New(p.CurrentConfig())
	ks.SetAPI(true)
	p.ks = ks

	resp := doConnectLiveLock(t, proxyAddr, ln.Addr().String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestConnectLiveLock_PathKeyedRuleCannotMatchConnect(t *testing.T) {
	ln := listenEcho(t)
	defer func() { _ = ln.Close() }()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()
	rule := contractruntimetest.HTTPEnforceRule("r-path", "127.0.0.1", "/v1/chat", http.MethodConnect)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))

	resp := doConnectLiveLock(t, proxyAddr, ln.Addr().String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != contractEnforceDefaultReason {
		t.Fatalf("block reason = %q, want %s", got, contractEnforceDefaultReason)
	}
}

func serveWSLiveLockStatus(t *testing.T, p *Proxy, targetURL string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ws?url="+targetURL, nil)
	req.Header.Set(AgentHeader, "agent-a")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rec := httptest.NewRecorder()
	p.handleWebSocket(rec, req)
	return rec
}

func TestWebSocketLiveLock_NoActiveContractPassThrough(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, p, cleanup := setupWSProxyWithProxy(t, func(cfg *config.Config) {
		cfg.WebSocketProxy.IdleTimeoutSeconds = 5
	})
	defer cleanup()
	p.contractLoaderPtr.Store(emptyContractLoader(t))

	assertWSLiveLockEcho(t, proxyAddr, backendAddr, []byte("live lock ws"))
}

func assertWSLiveLockEcho(t *testing.T, proxyAddr, backendAddr string, msg []byte) {
	t.Helper()
	conn := dialWSLiveLock(t, proxyAddr, backendAddr)
	if err := wsutil.WriteClientMessage(conn, ws.OpText, msg); err != nil {
		_ = conn.Close()
		t.Fatalf("write ws: %v", err)
	}
	got, op, err := wsutil.ReadServerData(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read ws: %v", err)
	}
	if op != ws.OpText || string(got) != string(msg) {
		_ = conn.Close()
		t.Fatalf("echo = op %v %q, want text %q", op, got, msg)
	}
	_ = ws.WriteFrame(conn, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "")))
	_ = conn.Close()
}

func dialWSLiveLock(t *testing.T, proxyAddr, backendAddr string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := fmt.Sprintf("ws://%s/ws?url=ws://%s", proxyAddr, backendAddr)
	dialer := ws.Dialer{
		Header: ws.HandshakeHeaderHTTP(http.Header{
			AgentHeader: []string{"agent-a"},
		}),
		Extensions: nil,
	}
	conn, _, _, err := dialer.Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return conn
}

func TestWebSocketLiveLock_AllowRulePassesHandshakeGate(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.WebSocketProxy.Enabled = true
	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	rule := contractruntimetest.HTTPEnforceRule("r-ws", "127.0.0.1", "/", http.MethodGet)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))

	rec := serveWSLiveLockStatus(t, p, "ws://127.0.0.1/")
	if rec.Code == http.StatusForbidden {
		t.Fatalf("status = 403, contract allow rule should pass handshake gate: %s", rec.Body.String())
	}
}

func TestWebSocketLiveLock_DefaultDenyBlocksUnmatchedDestination(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.WebSocketProxy.Enabled = true
	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	rule := contractruntimetest.HTTPEnforceRule("r-ws", "api.example.com", "/v1/chat", http.MethodGet)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))

	rec := serveWSLiveLockStatus(t, p, "ws://evil.example.com/v1/chat")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != contractDefaultDenyReason {
		t.Fatalf("block reason = %q, want %s", got, contractDefaultDenyReason)
	}
}

func TestWebSocketLiveLock_ScannerBlockWinsOverContractAllow(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.WebSocketProxy.Enabled = true
	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	rule := contractruntimetest.HTTPEnforceRule("r-ws", "api.example.com", "/v1/chat", http.MethodGet)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))

	rec := serveWSLiveLockStatus(t, p, "ws://api.example.com/v1/chat%250d%250aInjected:1")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.ParseError) {
		t.Fatalf("block reason = %q, want %s", got, blockreason.ParseError)
	}
}

func TestWebSocketLiveLock_ShadowModeObservesWithoutBlocking(t *testing.T) {
	webSocketLiveLockObserveModeAllows(t, contractruntime.ModeShadow)
}

func TestWebSocketLiveLock_CaptureModeDoesNotBlock(t *testing.T) {
	webSocketLiveLockObserveModeAllows(t, contractruntime.ModeCapture)
}

func webSocketLiveLockObserveModeAllows(t *testing.T, mode contractruntime.Mode) {
	t.Helper()
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	proxyAddr, p, cleanup := setupWSProxyWithProxy(t, nil)
	defer cleanup()
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
	rule := contractruntimetest.HTTPEnforceRule("r-ws", "api.example.com", "/v1/chat", http.MethodGet)
	p.contractLoaderPtr.Store(testContractLoader(t, mode, rule))

	assertWSLiveLockEcho(t, proxyAddr, backendAddr, []byte("live lock ws "+string(mode)))
	assertContractContextAllowReceipt(t, rph, TransportWS, contractruntime.WinningSourceScanner)
}

func assertContractContextAllowReceipt(t *testing.T, rph *receiptProxyHelper, transport, wantWinningSource string) {
	t.Helper()
	waitForReceiptOrTimeout(t, rph.dir)
	receipts := rph.findReceipts(t)
	for _, r := range receipts {
		if r.ActionRecord.Transport != transport || r.ActionRecord.Verdict != config.ActionAllow {
			continue
		}
		if wantWinningSource != "" && r.ActionRecord.ContractWinningSource != wantWinningSource {
			t.Fatalf("contract_winning_source = %q, want %s", r.ActionRecord.ContractWinningSource, wantWinningSource)
		}
		if r.ActionRecord.ActiveManifestHash == "" {
			t.Fatal("active_manifest_hash = empty, want contract receipt context")
		}
		if r.ActionRecord.ContractHash == "" {
			t.Fatal("contract_hash = empty, want contract receipt context")
		}
		return
	}
	t.Fatalf("no allow receipt found for transport %q in %d receipts", transport, len(receipts))
}

func TestWebSocketLiveLock_KillSwitchBlocksBeforeContractAllow(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.WebSocketProxy.Enabled = true
	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	rule := contractruntimetest.HTTPEnforceRule("r-ws", "api.example.com", "/v1/chat", http.MethodGet)
	p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, rule))
	ks := killswitch.New(p.CurrentConfig())
	ks.SetAPI(true)
	p.ks = ks

	rec := serveWSLiveLockStatus(t, p, "ws://api.example.com/v1/chat")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.KillSwitchActive) {
		t.Fatalf("block reason = %q, want %s", got, blockreason.KillSwitchActive)
	}
}

func TestProxyLiveLock_TransportNames(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportConnect, TransportWS} {
		if strings.TrimSpace(transport) == "" {
			t.Fatal("transport label must not be empty")
		}
	}
}
