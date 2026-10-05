// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestFullResponsePolicyTransports(t *testing.T) {
	for _, transport := range []string{"intercept", "forward", "reverse"} {
		for _, tc := range []struct {
			name          string
			headers       http.Header
			body          string
			unexpected304 bool
			method        string
			status        int
		}{
			{name: "stale conditional range", headers: http.Header{"Range": {"bytes=0-3"}, "If-Range": {`"stale"`}}, body: "PART full representation", method: http.MethodGet, status: http.StatusOK},
			{name: "bare range", headers: http.Header{"Range": {"bytes=0-3"}}, body: "PART full representation", method: http.MethodGet, status: http.StatusOK},
			{name: "range full scan", headers: http.Header{"Range": {"bytes=0-3"}, "If-Range": {`"stale"`}}, body: "PART hidden_instruction", method: http.MethodGet, status: http.StatusForbidden},
			{name: "conditional full scan", headers: http.Header{"If-None-Match": {`"origin"`}, "If-Modified-Since": {"Wed, 01 Oct 2025 12:00:00 GMT"}}, body: "full representation", method: http.MethodGet, status: http.StatusOK},
			{name: "conditional scan block", headers: http.Header{"If-None-Match": {`"origin"`}}, body: "hidden_instruction", method: http.MethodGet, status: http.StatusForbidden},
			{name: "unexpected not modified", unexpected304: true, method: http.MethodGet, status: http.StatusBadGateway},
			{name: "unexpected not modified head", unexpected304: true, method: http.MethodHead, status: http.StatusBadGateway},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				seen := make(chan http.Header, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Header.Clone()
					w.Header().Set("ETag", `"origin"`)
					w.Header().Set("Content-Type", "application/javascript")
					w.Header().Set("Cache-Control", "public, max-age=60")
					if tc.unexpected304 || r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
						w.WriteHeader(http.StatusNotModified)
						return
					}
					if r.Header.Get("Range") != "" && r.Header.Get("If-Range") == "" {
						w.Header().Set("Content-Range", "bytes 0-3/24")
						w.WriteHeader(http.StatusPartialContent)
						_, _ = io.WriteString(w, "PART")
						return
					}
					_, _ = io.WriteString(w, tc.body)
				})
				configure := func(cfg *config.Config) {
					cfg.ResponseScanning.Enabled = true
					cfg.ResponseScanning.Action = config.ActionBlock
					cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "full representation marker", Regex: "hidden_instruction"})
				}
				var resp *http.Response
				switch transport {
				case "intercept":
					origin := httptest.NewTLSServer(handler)
					defer origin.Close()
					cache, pool, cfg, _, logger, m := testInterceptSetup(t)
					configure(cfg)
					sc := scanner.MustNew(cfg)
					defer sc.Close()
					req, err := http.NewRequestWithContext(t.Context(), tc.method, origin.URL+"/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header = tc.headers.Clone()
					resp = interceptAndRequest(t, origin, cache, pool, cfg, sc, logger, m, req)
				case "reverse":
					cfg := config.Defaults()
					configure(cfg)
					proxy := reverseTestSetup(t, cfg, handler)
					req, err := http.NewRequestWithContext(t.Context(), tc.method, proxy.URL+"/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header = tc.headers.Clone()
					resp, err = proxy.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
				default:
					origin := httptest.NewServer(handler)
					defer origin.Close()
					addr, p, cleanup := setupForwardProxyWithInstance(t, configure)
					defer cleanup()
					installForwardTestDialer(p, origin.Listener.Addr().String())
					client := forwardHTTPClient(t, addr)
					defer client.CloseIdleConnections()
					req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://api.example.com/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header = tc.headers.Clone()
					resp, err = client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != tc.status {
					t.Errorf("status=%d body=%q, want %d", resp.StatusCode, body, tc.status)
				}
				upstreamHeaders := <-seen
				for _, name := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
					if got := upstreamHeaders.Get(name); got != "" {
						t.Errorf("upstream %s=%q, want removed", name, got)
					}
				}
				if tc.status == http.StatusOK {
					if string(body) != tc.body {
						t.Errorf("body=%q, want full %q", body, tc.body)
					}
					if resp.Header.Get("ETag") != `"origin"` || resp.Header.Get("Cache-Control") != "public, max-age=60" {
						t.Fatal("origin cache policy was changed")
					}
				} else if resp.Header.Get("ETag") != "" {
					t.Fatal("unapproved origin validator released")
				}
			})
		}
	}
}

func TestFullResponsePolicyWebSocketUpgrade(t *testing.T) {
	headers := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "If-None-Match": {`"origin"`}, "Range": {"bytes=0-3"}}
	if !applyFullResponsePolicy(headers, nil) || !applyFullResponsePolicy(nil, &http.Response{StatusCode: http.StatusSwitchingProtocols}) {
		t.Fatal("WebSocket upgrade refused by full-response policy")
	}
	if headers.Get("Connection") != "Upgrade" || headers.Get("Upgrade") != "websocket" {
		t.Fatal("upgrade headers removed")
	}
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	addr, cleanup := setupWSProxy(t, nil)
	defer cleanup()
	conn, err := dialWSConnWithHeader(addr, backend, headers)
	if err != nil {
		t.Fatalf("WebSocket upgrade: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const message = "ordinary message"
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(message)); err != nil {
		t.Fatal(err)
	}
	body, op, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if op != ws.OpText || string(body) != message {
		t.Fatalf("echo=(%q,%v), want text %q", body, op, message)
	}
}

func TestForwardUnexpectedNotModifiedReceipts(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer origin.Close()
	addr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = true
	})
	defer cleanup()
	rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(rph.emitter)
	installForwardTestDialer(p, origin.Listener.Addr().String())
	client := forwardHTTPClient(t, addr)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.example.com/asset.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", resp.StatusCode)
	}
	var foundBlock, foundOutcome bool
	for _, record := range rph.findReceipts(t) {
		if record.ActionRecord.Verdict == config.ActionBlock && record.ActionRecord.Layer == "browser_cache" {
			foundBlock = true
		}
		if record.ActionRecord.Layer == receiptOutcomeLayer && record.ActionRecord.Pattern == receiptOutcomePattern("502", -1, "unbound_not_modified") {
			foundOutcome = true
		}
	}
	if !foundBlock || !foundOutcome {
		t.Fatalf("missing refusal evidence: block=%v outcome=%v", foundBlock, foundOutcome)
	}
}
