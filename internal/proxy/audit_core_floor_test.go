// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
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
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const auditFloorPatternName = "Audit Floor Probe"

// auditFloorValue returns the probe value for a finding class: a built-in core
// credential, or an operator pattern that is critical but not core.
func auditFloorValue(kind string) string {
	if kind == "core" {
		return "AKIA" + "IOSFODNN7EXAMPLE"
	}
	return "auditprobe-" + "12345678"
}

// auditFloorConfig shapes a config for one matrix row. Request scanning warns
// so only the enforce flag and the finding class decide the outcome.
func auditFloorConfig(enforce bool, blockedHost string) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.Enforce = &enforce
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: auditFloorPatternName, Regex: `auditprobe-[0-9]{8}`, Severity: config.SeverityCritical})
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.CrossRequestDetection.Enabled = false
		cfg.AdaptiveEnforcement.Enabled = false
		cfg.Taint.Enabled = false
		if blockedHost != "" {
			cfg.FetchProxy.Monitoring.Blocklist = []string{blockedHost}
		}
	}
}

type auditFloorOutcome struct {
	blocked bool
	hits    int32
	detail  string
}

func auditFloorHTTPOutcome(w *httptest.ResponseRecorder, hits int32) auditFloorOutcome {
	return auditFloorOutcome{blocked: w.Code == http.StatusForbidden, hits: hits, detail: fmt.Sprintf("status=%d body=%.160s", w.Code, w.Body.String())}
}

// auditFloorRequest builds a request carrying value on the given surface.
func auditFloorRequest(t *testing.T, target, surface, value string) *http.Request {
	t.Helper()
	method, body := http.MethodGet, http.NoBody
	switch surface {
	case "url":
		target += "?token=" + value
	case "body":
		method = http.MethodPost
	}
	var req *http.Request
	if surface == "body" {
		req = httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader("token="+value))
		req.Header.Set("Content-Type", "text/plain")
	} else {
		req = httptest.NewRequestWithContext(t.Context(), method, target, body)
	}
	if surface == "header" {
		req.Header.Set("Authorization", "Bearer "+value)
	}
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func driveAuditFloor(t *testing.T, transport, kind, surface string, enforce bool) auditFloorOutcome {
	t.Helper()
	value := auditFloorValue(kind)
	if kind == "blocklist" {
		value = "hello"
	}
	// coreblocked carries a core credential to a blocklisted host: the
	// blocklist stage ends the URL scan before the core floor runs, and audit
	// mode must still find and block the credential.
	if kind == "coreblocked" {
		value = auditFloorValue("core")
	}
	var hits atomic.Int32
	counting := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})
	blocked := func(host string) string {
		if kind == "blocklist" || kind == "coreblocked" {
			return host
		}
		return ""
	}
	switch transport {
	case "forward", "fetch":
		upstream := newIPv4Server(t, counting)
		t.Cleanup(upstream.Close)
		_, p, cleanup := setupForwardProxyWithInstance(t, auditFloorConfig(enforce, blocked("127.0.0.1")))
		t.Cleanup(cleanup)
		w := httptest.NewRecorder()
		if transport == "forward" {
			p.handleForwardHTTP(w, auditFloorRequest(t, upstream.URL+"/x", surface, value))
			return auditFloorHTTPOutcome(w, hits.Load())
		}
		target := upstream.URL + "/x"
		if surface == "url" {
			target += "?token=" + value
		}
		req := auditFloorRequest(t, "/fetch?url="+url.QueryEscape(target), "", value)
		if surface == "header" {
			req.Header.Set("Authorization", "Bearer "+value)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/fetch", p.handleFetch)
		mux.ServeHTTP(w, req)
		return auditFloorHTTPOutcome(w, hits.Load())
	case "intercept":
		cfg := config.Defaults()
		auditFloorConfig(enforce, blocked("peer.example"))(cfg)
		cfg.ApplyDefaults()
		cfg.Internal = nil
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		handler := newInterceptHandler(&InterceptContext{
			TargetHost: "peer.example", TargetPort: "443", Config: cfg, Scanner: sc,
			Logger: audit.NewNop(), Metrics: metrics.New(), ClientIP: testLoopbackIP,
			RequestID: "audit-floor", Agent: agentAnonymous,
		}, roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			hits.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: http.NoBody}, nil
		}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, auditFloorRequest(t, "https://peer.example/x", surface, value))
		return auditFloorHTTPOutcome(w, hits.Load())
	case "reverse":
		cfg := reverseParityBaseConfig(t)
		auditFloorConfig(enforce, blocked("reverse.example"))(cfg)
		rp, _, _ := newReverseParityHarness(t, cfg, counting)
		w := httptest.NewRecorder()
		req := auditFloorRequest(t, "http://reverse.example/x", surface, value)
		req.RemoteAddr = "10.0.0.41:9000"
		rp.ServeHTTP(w, req)
		return auditFloorHTTPOutcome(w, hits.Load())
	case "connect":
		backend := newIPv4Server(t, counting)
		t.Cleanup(backend.Close)
		proxyAddr, cleanup := setupForwardProxy(t, auditFloorConfig(enforce, blocked("127.0.0.1")))
		t.Cleanup(cleanup)
		conn := dialProxy(t, proxyAddr)
		t.Cleanup(func() { _ = conn.Close() })
		host := strings.TrimPrefix(backend.URL, "http://")
		extra := ""
		if surface == "header" {
			extra = "Authorization: Bearer " + value + "\r\n"
		}
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", host, host, extra)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		_ = resp.Body.Close()
		return auditFloorOutcome{blocked: resp.StatusCode != http.StatusOK, detail: fmt.Sprintf("status=%d", resp.StatusCode)}
	case "websocket":
		backendAddr, backendCleanup := wsEchoServer(t)
		t.Cleanup(backendCleanup)
		proxyAddr, proxyCleanup := setupWSProxy(t, auditFloorConfig(enforce, blocked("127.0.0.1")))
		t.Cleanup(proxyCleanup)
		var conn net.Conn
		var err error
		switch surface {
		case "url":
			conn, err = dialWSConnToTarget(proxyAddr, "ws://"+backendAddr+"/?token="+value)
		case "header":
			conn, err = dialWSConnWithHeader(proxyAddr, backendAddr, http.Header{"Authorization": []string{"Bearer " + value}})
		default:
			conn, err = dialWSConn(proxyAddr, backendAddr)
		}
		if err != nil {
			return auditFloorOutcome{blocked: true, detail: err.Error()}
		}
		t.Cleanup(func() { _ = conn.Close() })
		if surface != "body" {
			return auditFloorOutcome{detail: "handshake accepted"}
		}
		if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("token="+value)); err != nil {
			return auditFloorOutcome{blocked: true, detail: err.Error()}
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		reply, _, err := wsutil.ReadServerData(conn)
		if err != nil || !strings.Contains(string(reply), value) {
			return auditFloorOutcome{blocked: true, detail: fmt.Sprintf("reply=%q err=%v", reply, err)}
		}
		return auditFloorOutcome{detail: "frame echoed"}
	}
	t.Fatalf("unknown transport %q", transport)
	return auditFloorOutcome{}
}

// TestAuditModeCoreCredentialFloor pins the audit-mode contract on every
// outbound transport: with enforce: false, a built-in core credential still
// blocks before reaching upstream, while ordinary configured policy (a
// critical operator pattern, a blocklisted host) is observed and forwarded.
// Enforce mode blocks every class.
func TestAuditModeCoreCredentialFloor(t *testing.T) {
	surfaces := map[string][]string{
		"fetch":     {"url", "header"},
		"forward":   {"url", "header", "body"},
		"connect":   {"header"},
		"intercept": {"url", "header", "body"},
		"reverse":   {"url", "header", "body"},
		"websocket": {"url", "header", "body"},
	}
	for transport, list := range surfaces {
		for _, enforce := range []bool{false, true} {
			for _, kind := range []string{"core", "dlp", "blocklist", "coreblocked"} {
				for _, surface := range list {
					// The reverse proxy fronts one configured upstream; its
					// request Host is not a destination the blocklist governs.
					if (kind == "blocklist" || kind == "coreblocked") && (surface != list[0] || transport == "reverse") {
						continue
					}
					if kind == "coreblocked" && surface != "url" {
						continue
					}
					t.Run(fmt.Sprintf("%s/enforce=%v/%s/%s", transport, enforce, kind, surface), func(t *testing.T) {
						got := driveAuditFloor(t, transport, kind, surface, enforce)
						wantBlocked := enforce || kind == "core" || kind == "coreblocked"
						if got.blocked != wantBlocked {
							t.Fatalf("blocked = %v, want %v (%s)", got.blocked, wantBlocked, got.detail)
						}
						if transport == "connect" || transport == "websocket" {
							return
						}
						wantHits := int32(1)
						if wantBlocked {
							wantHits = 0
						}
						if got.hits != wantHits {
							t.Fatalf("upstream hits = %d, want %d (%s)", got.hits, wantHits, got.detail)
						}
					})
				}
			}
		}
	}
}

// TestAuditModeA2ACoreCredentialFloor applies the same contract to the A2A
// branch with request body scanning off, so A2A scanning alone decides. The
// A2A action is block, so enforce mode blocks every finding and audit mode
// blocks only the core credential.
func TestAuditModeA2ACoreCredentialFloor(t *testing.T) {
	payloads := map[string]string{
		"benign": `{"text":"hello"}`,
		"core":   `{"token":"` + auditFloorValue("core") + `"}`,
		"policy": `{"url":"https://blocked.example/message"}`,
		// A core credential bound for a blocklisted host: the blocklist ends
		// the URL scan before its core floor stage.
		"coreblocked": `{"url":"https://blocked.example/message?token=` + auditFloorValue("core") + `"}`,
	}
	for _, transport := range []string{"forward", "intercept"} {
		for _, direction := range []string{"request", "response", "header"} {
			for _, enforce := range []bool{false, true} {
				for kind, payload := range payloads {
					t.Run(fmt.Sprintf("%s/%s/enforce=%v/%s", transport, direction, enforce, kind), func(t *testing.T) {
						cfg := config.Defaults()
						cfg.Internal = nil
						cfg.A2AScanning.Enabled = true
						cfg.A2AScanning.Action = config.ActionBlock
						cfg.RequestBodyScanning.Enabled = false
						cfg.ResponseScanning.Enabled = false
						cfg.Enforce = &enforce
						cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
						var w *httptest.ResponseRecorder
						var hits int32
						switch direction {
						case "request":
							w, hits, _ = driveProxyA2AHardening(t, transport, payload, `{"text":"hello"}`, "application/a2a+json", cfg)
						case "response":
							w, hits, _ = driveProxyA2AHardening(t, transport, `{"text":"hello"}`, payload, "application/a2a+json", cfg)
						default:
							uri := "https://ext.example/v1"
							switch kind {
							case "core":
								uri += "?token=" + auditFloorValue("core")
							case "policy":
								uri = "https://blocked.example/v1"
							case "coreblocked":
								uri = "https://blocked.example/v1?token=" + auditFloorValue("core")
							}
							w, hits = driveA2AHeaderAuditFloor(t, transport, uri, cfg)
						}
						wantBlocked := kind == "core" || kind == "coreblocked" || (enforce && kind == "policy")
						wantHits := int32(1)
						if wantBlocked && direction != "response" {
							wantHits = 0
						}
						if (w.Code == http.StatusForbidden) != wantBlocked || hits != wantHits {
							t.Fatalf("status=%d hits=%d, want blocked=%v hits=%d: %.200s", w.Code, hits, wantBlocked, wantHits, w.Body.String())
						}
					})
				}
			}
		}
	}
}

// driveA2AHeaderAuditFloor sends a benign A2A body with an A2A-Extensions
// header naming uri through the forward or intercept path.
func driveA2AHeaderAuditFloor(t *testing.T, transport, uri string, cfg *config.Config) (*httptest.ResponseRecorder, int32) {
	t.Helper()
	var hits atomic.Int32
	w := httptest.NewRecorder()
	if transport == "forward" {
		upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/a2a+json")
			_, _ = w.Write([]byte(`{"text":"hello"}`))
		}))
		t.Cleanup(upstream.Close)
		_, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) {
			c.A2AScanning = cfg.A2AScanning
			c.RequestBodyScanning = cfg.RequestBodyScanning
			c.ResponseScanning = cfg.ResponseScanning
			c.Enforce = cfg.Enforce
			c.FetchProxy.Monitoring.Blocklist = cfg.FetchProxy.Monitoring.Blocklist
		})
		t.Cleanup(cleanup)
		req := newA2AForwardBodyRequest(t, upstream.URL+"/message:send", `{"text":"hello"}`)
		req.Header.Set("A2A-Extensions", uri)
		p.handleForwardHTTP(w, req)
		return w, hits.Load()
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	handler := newInterceptHandler(&InterceptContext{
		TargetHost: "peer.example", TargetPort: "443", Config: cfg, Scanner: sc,
		Logger: audit.NewNop(), Metrics: metrics.New(), ClientIP: testLoopbackIP,
		RequestID: "a2a-audit-floor", Agent: agentAnonymous,
	}, roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		hits.Add(1)
		body := `{"text":"hello"}`
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/a2a+json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}, nil
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://peer.example/message:send", strings.NewReader(`{"text":"hello"}`))
	req.Header.Set("Content-Type", "application/a2a+json")
	req.Header.Set("A2A-Extensions", uri)
	handler.ServeHTTP(w, req)
	return w, hits.Load()
}
