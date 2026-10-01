// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// When flight_recorder.require_receipts is on, a credential-audience
// DLP allow must have its receipt durably confirmed BEFORE the request is
// forwarded; a confirmation failure blocks with a distinct
// credential_audience_receipt layer instead of silently forwarding.
// With require_receipts off, behavior is unchanged: best-effort, log+metric,
// forward regardless of emit outcome.

// audienceReceiptTestCredential is a synthetic pattern/value pair (mirrors
// credentialAudienceCarrierCases in credential_audience_test.go) declared to
// earn an audience allow only at a configured destination, so these tests do
// not depend on a compiled-in provider pattern's path restrictions.
const audienceReceiptTestCredential = "tstaud-" + "AAAAAAAAAAAAAAAAAAAAAAAA"

func audienceReceiptTestPattern(host string) config.DLPPattern {
	return config.DLPPattern{
		Name:                    "Test Audience Receipt Key",
		Regex:                   `tstaud-[A-Za-z0-9]{24}`,
		Severity:                config.SeverityCritical,
		CredentialAudienceHosts: []string{host},
	}
}

// ---- Fetch transport: genuine end-to-end ----

func fetchAudienceRequireReceiptsProxy(t *testing.T, require bool, emitFails bool, host string, mods ...func(*config.Config)) (*Proxy, *receiptProxyHelper) {
	t.Helper()
	cfg := testScannerConfig()
	cfg.Internal = nil
	cfg.ResponseScanning.Enabled = false
	cfg.FlightRecorder.RequireReceipts = require
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
	cfg.RequestBodyScanning.SensitiveHeaders = []string{"Authorization"}
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, audienceReceiptTestPattern(host))
	for _, mod := range mods {
		mod(cfg)
	}

	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
	if emitFails {
		if err := rph.rec.Close(); err != nil {
			t.Fatalf("recorder.Close: %v", err)
		}
	}
	p.receiptEmitterPtr.Store(rph.emitter)
	return p, rph
}

func TestHandleFetch_CredentialAudienceRequireReceipts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		require       bool
		emitFails     bool
		wantStatus    int
		wantUpstream  int32
		wantBlockedBy string
	}{
		{name: "on and emit fails blocks before egress", require: true, emitFails: true, wantStatus: http.StatusForbidden, wantUpstream: 0, wantBlockedBy: string(blockreason.ReceiptEmissionFailed)},
		{name: "on and emit succeeds forwards", require: true, emitFails: false, wantStatus: http.StatusOK, wantUpstream: 1},
		{name: "off and emit fails still forwards (unchanged)", require: false, emitFails: true, wantStatus: http.StatusOK, wantUpstream: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte("ok"))
			}))
			defer upstream.Close()

			host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
			if err != nil {
				t.Fatalf("SplitHostPort: %v", err)
			}

			p, rph := fetchAudienceRequireReceiptsProxy(t, tc.require, tc.emitFails, host)
			// The fetch client is the proxy's own outbound transport; it does not
			// trust the test server's self-signed cert by default, so exercising
			// the encrypted-scheme-only audience earn requires the same trust
			// override used by other TLS-upstream fetch tests in this package.
			p.client.Transport = upstream.Client().Transport

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
			req.Header.Set("Authorization", "Bearer "+audienceReceiptTestCredential)
			rec := httptest.NewRecorder()
			p.handleFetch(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := hits.Load(); got != tc.wantUpstream {
				t.Fatalf("upstream hits = %d, want %d", got, tc.wantUpstream)
			}
			if tc.wantBlockedBy != "" {
				if got := rec.Header().Get(blockreason.HeaderReason); got != tc.wantBlockedBy {
					t.Fatalf("block reason header = %q, want %q", got, tc.wantBlockedBy)
				}
				if got := rec.Header().Get(blockreason.HeaderLayer); got != blockLayerCredentialAudienceReceipt {
					t.Fatalf("block layer header = %q, want %q", got, blockLayerCredentialAudienceReceipt)
				}
				var resp FetchResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode FetchResponse: %v", err)
				}
				if !resp.Blocked {
					t.Fatalf("FetchResponse.Blocked = false, want true: %+v", resp)
				}
			}
			if tc.require && !tc.emitFails {
				found := false
				for _, r := range rph.findReceipts(t) {
					if r.ActionRecord.Layer == credentialAudienceReceiptExtensionKey {
						found = true
						if r.ActionRecord.Verdict != config.ActionAllow {
							t.Fatalf("audience receipt verdict = %q, want allow", r.ActionRecord.Verdict)
						}
					}
				}
				if !found {
					t.Fatal("no credential audience allow receipt emitted on success path")
				}
			}
		})
	}
}

// ---- Intercept (TLS-intercepted CONNECT) transport: genuine end-to-end ----

func TestInterceptTunnel_CredentialAudienceRequireReceipts(t *testing.T) {
	for _, tc := range []struct {
		name         string
		require      bool
		emitFails    bool
		wantStatus   int
		wantUpstream int32
	}{
		{name: "on and emit fails blocks before egress", require: true, emitFails: true, wantStatus: http.StatusForbidden, wantUpstream: 0},
		{name: "on and emit succeeds forwards", require: true, emitFails: false, wantStatus: http.StatusOK, wantUpstream: 1},
		{name: "off and emit fails still forwards (unchanged)", require: false, emitFails: true, wantStatus: http.StatusOK, wantUpstream: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if got := r.Header.Get("Authorization"); !strings.Contains(got, audienceReceiptTestCredential) {
					t.Errorf("Authorization header = %q, want test credential", got)
				}
				_, _ = w.Write([]byte("ok"))
			}))
			defer upstream.Close()

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			addr := upstream.Listener.Addr().String()
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatalf("SplitHostPort: %v", err)
			}

			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.Action = config.ActionBlock
			cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
			cfg.RequestBodyScanning.SensitiveHeaders = []string{"Authorization"}
			cfg.FlightRecorder.RequireReceipts = tc.require
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, audienceReceiptTestPattern(host))
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)

			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			t.Cleanup(p.Close)
			rph := newReceiptProxyHelperWithMetrics(t, m)
			if tc.emitFails {
				if err := rph.rec.Close(); err != nil {
					t.Fatalf("recorder.Close: %v", err)
				}
			}
			p.receiptEmitterPtr.Store(rph.emitter)

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/api", nil)
			req.Header.Set("Authorization", "Bearer "+audienceReceiptTestCredential)

			resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
				Upstream: upstream,
				Cache:    cache,
				Pool:     pool,
				Config:   cfg,
				Scanner:  sc,
				Logger:   logger,
				Metrics:  m,
				Request:  req,
				Proxy:    p,
			})
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if got := hits.Load(); got != tc.wantUpstream {
				t.Fatalf("upstream hits = %d, want %d", got, tc.wantUpstream)
			}
			if tc.require && tc.emitFails {
				if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.ReceiptEmissionFailed) {
					t.Fatalf("block reason header = %q, want %s", got, blockreason.ReceiptEmissionFailed)
				}
				if got := resp.Header.Get(blockreason.HeaderLayer); got != blockLayerCredentialAudienceReceipt {
					t.Fatalf("block layer header = %q, want %q", got, blockLayerCredentialAudienceReceipt)
				}
			}
			if tc.require && !tc.emitFails {
				found := false
				for _, r := range rph.findReceipts(t) {
					if r.ActionRecord.Layer == credentialAudienceReceiptExtensionKey {
						found = true
					}
				}
				if !found {
					t.Fatal("no credential audience allow receipt emitted on success path")
				}
			}
		})
	}
}

// ---- Reverse proxy transport: direct scanRequest call ----

func TestReverseProxy_ScanRequest_CredentialAudienceRequireReceipts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		require     bool
		emitFails   bool
		wantBlocked bool
	}{
		{name: "on and emit fails blocks before egress", require: true, emitFails: true, wantBlocked: true},
		{name: "on and emit succeeds forwards", require: true, emitFails: false, wantBlocked: false},
		{name: "off and emit fails still forwards (unchanged)", require: false, emitFails: true, wantBlocked: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.Action = config.ActionBlock
			cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, audienceReceiptTestPattern("api.vendor.example"))
			cfg.FlightRecorder.RequireReceipts = tc.require
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)

			upstream, err := url.Parse("https://api.vendor.example")
			if err != nil {
				t.Fatalf("parse upstream: %v", err)
			}

			rph := newReceiptProxyHelper(t)
			if tc.emitFails {
				if err := rph.rec.Close(); err != nil {
					t.Fatalf("recorder.Close: %v", err)
				}
			}

			handler := &ReverseProxyHandler{
				upstream:   upstream,
				logger:     audit.NewNop(),
				metrics:    metrics.New(),
				captureObs: capture.NopObserver{},
			}
			handler.cfgPtr = &atomic.Pointer[config.Config]{}
			handler.cfgPtr.Store(cfg)
			handler.receiptEmitterPtr = &atomic.Pointer[receipt.Emitter]{}
			handler.receiptEmitterPtr.Store(rph.emitter)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://proxy.vendor.example/v1",
				strings.NewReader(`{"key":"`+audienceReceiptTestCredential+`"}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			blocked, _, _, _ := handler.scanRequest(rec, req, cfg, sc, nil, reverseBlockReceiptInput{Target: "https://api.vendor.example/v1"})
			if blocked != tc.wantBlocked {
				t.Fatalf("blocked = %v, want %v; response=%s", blocked, tc.wantBlocked, rec.Body.String())
			}
			if tc.require && tc.emitFails {
				if got := rec.Header().Get(blockreason.HeaderLayer); got != blockLayerCredentialAudienceReceipt {
					t.Fatalf("block layer header = %q, want %q", got, blockLayerCredentialAudienceReceipt)
				}
			}
		})
	}
}

// ---- WebSocket transport: direct header-scan and body-result call ----

func TestDLPScanWSHeaders_CredentialAudienceRequireReceipts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		require   bool
		emitFails bool
	}{
		{name: "on and emit fails returns receiptErr", require: true, emitFails: true},
		{name: "on and emit succeeds returns no error", require: true, emitFails: false},
		{name: "off and emit fails returns no error (unchanged)", require: false, emitFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.RequestBodyScanning.Enabled = true
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, audienceReceiptTestPattern("api.vendor.example"))
			cfg.FlightRecorder.RequireReceipts = tc.require
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)

			rph := newReceiptProxyHelper(t)
			if tc.emitFails {
				if err := rph.rec.Close(); err != nil {
					t.Fatalf("recorder.Close: %v", err)
				}
			}
			p := &Proxy{
				logger:  audit.NewNop(),
				metrics: metrics.New(),
			}
			p.cfgPtr.Store(cfg)
			p.receiptEmitterPtr.Store(rph.emitter)

			headers := http.Header{"Authorization": []string{"Bearer " + audienceReceiptTestCredential}}
			actx := newHTTPAuditContext(t.Context(), p.logger, httpAuditEvent{Method: "WS", TargetURL: "wss://api.vendor.example/socket"})
			_, _, _, _, receiptErr := p.dlpScanWSHeaders(t.Context(), headers, sc, cfg, "wss://api.vendor.example/socket", actx)

			wantErr := tc.require && tc.emitFails
			if (receiptErr != nil) != wantErr {
				t.Fatalf("receiptErr = %v, want non-nil=%v", receiptErr, wantErr)
			}
		})
	}
}

func TestHandleClientMessageBodyResult_CredentialAudienceReceiptErrBlocks(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = clientPeer.Close() })
	upstreamConn, upstreamPeer := net.Pipe()
	t.Cleanup(func() { _ = upstreamConn.Close(); _ = upstreamPeer.Close() })

	// Drain both peer ends so WriteCloseFrame does not block the test.
	go func() { _, _ = io.Copy(io.Discard, clientPeer) }()
	go func() { _, _ = io.Copy(io.Discard, upstreamPeer) }()

	cfg := config.Defaults()
	cfg.Internal = nil
	relay := &wsRelay{
		proxy:        &Proxy{logger: audit.NewNop(), metrics: metrics.New()},
		cfg:          cfg,
		clientConn:   clientConn,
		upstreamConn: upstreamConn,
		targetURL:    "wss://api.vendor.example/socket",
		requestID:    "req-1",
		agent:        "agent-1",
	}

	result := BodyScanResult{Clean: true, CredentialAudienceReceiptErr: errCredentialAudienceReceiptEmitterUnavailable}
	blocked := relay.handleClientMessageBodyResult(audit.NewNop(), nil, result)
	if !blocked {
		t.Fatal("handleClientMessageBodyResult did not block on a credential audience receipt error")
	}
}

// ---- Hot reload: flipping require_receipts on a live proxy changes the
// credential-audience-allow failure direction without restarting. ----

func TestHandleFetch_CredentialAudienceRequireReceipts_HotReload(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	// Start with require_receipts OFF and a broken (closed) recorder: the
	// allow is best-effort, so the request forwards.
	p, _ := fetchAudienceRequireReceiptsProxy(t, false, true, host)
	p.client.Transport = upstream.Client().Transport
	t.Cleanup(p.Close)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
	req.Header.Set("Authorization", "Bearer "+audienceReceiptTestCredential)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-reload status = %d, want 200 (require_receipts off): body=%s", rec.Code, rec.Body.String())
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("pre-reload upstream hits = %d, want 1", got)
	}

	// Flip require_receipts ON via a live reload. The recorder stays closed
	// (still failing), so the same request must now block before egress.
	reloadedCfg := p.cfgPtr.Load().Clone()
	reloadedCfg.FlightRecorder.RequireReceipts = true
	if !p.Reload(reloadedCfg, scanner.MustNew(reloadedCfg)) {
		t.Fatal("Reload returned false")
	}

	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
	req2.Header.Set("Authorization", "Bearer "+audienceReceiptTestCredential)
	rec2 := httptest.NewRecorder()
	p.handleFetch(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("post-reload status = %d, want 403 (require_receipts on, receipt still broken): body=%s", rec2.Code, rec2.Body.String())
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("post-reload upstream hits = %d, want 1 (still blocked before egress)", got)
	}
	if got := rec2.Header().Get(blockreason.HeaderLayer); got != blockLayerCredentialAudienceReceipt {
		t.Fatalf("post-reload block layer header = %q, want %q", got, blockLayerCredentialAudienceReceipt)
	}
}

// ---- CONNECT handshake header: end to end through the proxy handler ----

func TestConnectHeader_CredentialAudienceRequireReceipts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		require    bool
		emitFails  bool
		wantStatus int
	}{
		{name: "on and emit fails blocks before dial", require: true, emitFails: true, wantStatus: http.StatusForbidden},
		{name: "on and emit succeeds tunnels", require: true, emitFails: false, wantStatus: http.StatusOK},
		{name: "off and emit fails still tunnels (unchanged)", require: false, emitFails: true, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lc := net.ListenConfig{}
			target, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = target.Close() }()
			var dials atomic.Int32
			go func() {
				for {
					c, err := target.Accept()
					if err != nil {
						return
					}
					dials.Add(1)
					_ = c.Close()
				}
			}()

			p, _ := fetchAudienceRequireReceiptsProxy(t, tc.require, tc.emitFails, "127.0.0.1", func(cfg *config.Config) {
				cfg.ForwardProxy.Enabled = true
				cfg.ForwardProxy.MaxTunnelSeconds = 10
				cfg.ForwardProxy.IdleTimeoutSeconds = 2
				cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
				cfg.APIAllowlist = nil
			})
			// A hijacked CONNECT handler outlives srv.Close and records its
			// close event after the relay ends. Wait for it to return before
			// the recorder's temp dir is removed, or cleanup races the write.
			var inflight sync.WaitGroup
			defer inflight.Wait()
			handler := p.buildHandler(http.NewServeMux())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inflight.Add(1)
				defer inflight.Done()
				handler.ServeHTTP(w, r)
			}))
			defer srv.Close()

			conn := dialProxy(t, srv.Listener.Addr().String())
			defer func() { _ = conn.Close() }()
			addr := target.Addr().String()
			if _, err := io.WriteString(conn, "CONNECT "+addr+" HTTP/1.1\r\nHost: "+addr+"\r\nAuthorization: Bearer "+audienceReceiptTestCredential+"\r\n\r\n"); err != nil {
				t.Fatalf("write CONNECT: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d; layer=%q", resp.StatusCode, tc.wantStatus, resp.Header.Get(blockreason.HeaderLayer))
			}
			if tc.wantStatus == http.StatusForbidden {
				if got := resp.Header.Get(blockreason.HeaderLayer); got != blockLayerCredentialAudienceReceipt {
					t.Fatalf("block layer header = %q, want %q", got, blockLayerCredentialAudienceReceipt)
				}
				if got := dials.Load(); got != 0 {
					t.Fatalf("target dialed %d times after a receipt-confirmation block", got)
				}
			}
		})
	}
}
