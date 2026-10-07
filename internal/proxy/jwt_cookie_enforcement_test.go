// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// jwtCookieHeaders is a plain, unencoded JWT in Cookie: the shape that used to
// be forced to warn on every transport. The token is assembled at runtime so no
// literal credential appears in source.
func jwtCookieHeaders() http.Header {
	return http.Header{"Cookie": []string{"session=" + issuerJWTShapedValue()}}
}

// jwtAuthorizationHeaders carries the same token in a non-cookie header, which
// always followed the configured action.
func jwtAuthorizationHeaders() http.Header {
	return http.Header{"Authorization": []string{"Bearer " + issuerJWTShapedValue()}}
}

// jwtHeaderOutcome is what one transport did with a request carrying the header.
type jwtHeaderOutcome struct {
	status      int
	upstreamHit bool
}

func jwtHeaderScanConfig(cfg *config.Config, action string) {
	cfg.Mode = config.ModeStrict
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.Action = action
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
	cfg.RequestBodyScanning.SensitiveHeaders = []string{"Cookie", "Authorization"}
}

// jwtTransportRunners lists every transport whose header scan goes through
// headerDLPDecision. MCP header DLP does not use that function and is not here.
func jwtTransportRunners() map[string]func(t *testing.T, action string, headers http.Header) jwtHeaderOutcome {
	return map[string]func(t *testing.T, action string, headers http.Header) jwtHeaderOutcome{
		"fetch": func(t *testing.T, action string, headers http.Header) jwtHeaderOutcome {
			var hit atomic.Bool
			upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hit.Store(true)
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(upstream.Close)
			proxyAddr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				jwtHeaderScanConfig(cfg, action)
			})
			t.Cleanup(cleanup)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+proxyAddr+"/fetch?url="+url.QueryEscape(upstream.URL+"/app"), nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header = headers.Clone()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("fetch request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			return jwtHeaderOutcome{status: resp.StatusCode, upstreamHit: hit.Load()}
		},
		"forward": func(t *testing.T, action string, headers http.Header) jwtHeaderOutcome {
			var hit atomic.Bool
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hit.Store(true)
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(backend.Close)
			proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				jwtHeaderScanConfig(cfg, action)
			})
			t.Cleanup(cleanup)
			installForwardTestDialer(p, backend.Listener.Addr().String())
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.example.com/v1/chat", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header = headers.Clone()
			resp, err := forwardHTTPClient(t, proxyAddr).Do(req)
			if err != nil {
				t.Fatalf("forward request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			return jwtHeaderOutcome{status: resp.StatusCode, upstreamHit: hit.Load()}
		},
		"intercept": func(t *testing.T, action string, headers http.Header) jwtHeaderOutcome {
			var hit atomic.Bool
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hit.Store(true)
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(upstream.Close)
			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			jwtHeaderScanConfig(cfg, action)
			cfg.APIAllowlist = []string{"127.0.0.1"}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/app", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header = headers.Clone()
			resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			return jwtHeaderOutcome{status: resp.StatusCode, upstreamHit: hit.Load()}
		},
		"reverse": func(t *testing.T, action string, headers http.Header) jwtHeaderOutcome {
			var hit atomic.Bool
			cfg := reverseTestConfig()
			jwtHeaderScanConfig(cfg, action)
			proxy := reverseTestSetup(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				hit.Store(true)
				_, _ = io.WriteString(w, "ok")
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxy.URL+"/api/data", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header = headers.Clone()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("reverse request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			return jwtHeaderOutcome{status: resp.StatusCode, upstreamHit: hit.Load()}
		},
		"websocket": func(t *testing.T, action string, headers http.Header) jwtHeaderOutcome {
			backendAddr, backendCleanup := wsEchoServer(t)
			t.Cleanup(backendCleanup)
			proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
				jwtHeaderScanConfig(cfg, action)
				// The handshake scans only headers it forwards, and Cookie is
				// forwarded only on opt-in; a dropped cookie reaches nobody.
				cfg.WebSocketProxy.ForwardCookies = true
			})
			t.Cleanup(proxyCleanup)
			resp := requestWSHandshake(t, proxyAddr, backendAddr, headers)
			defer func() { _ = resp.Body.Close() }()
			// A completed upgrade is the WebSocket equivalent of reaching the
			// upstream.
			return jwtHeaderOutcome{status: resp.StatusCode, upstreamHit: resp.StatusCode == http.StatusSwitchingProtocols}
		},
	}
}

// TestJWTCookieFollowsConfiguredHeaderActionAcrossTransports pins the
// behavior that replaced the unconditional JWT-in-Cookie warning: an unencoded
// JWT in Cookie follows request_body_scanning.action on every transport that
// scans headers, exactly as the same token in Authorization does.
func TestJWTCookieFollowsConfiguredHeaderActionAcrossTransports(t *testing.T) {
	for name, run := range jwtTransportRunners() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				label     string
				headers   http.Header
				action    string
				wantBlock bool
			}{
				{"JWT cookie under block is denied", jwtCookieHeaders(), config.ActionBlock, true},
				{"JWT cookie under warn is forwarded", jwtCookieHeaders(), config.ActionWarn, false},
				{"JWT in Authorization under block is denied", jwtAuthorizationHeaders(), config.ActionBlock, true},
				{"JWT in Authorization under warn is forwarded", jwtAuthorizationHeaders(), config.ActionWarn, false},
			} {
				t.Run(tc.label, func(t *testing.T) {
					got := run(t, tc.action, tc.headers)
					if tc.wantBlock {
						if got.status != http.StatusForbidden || got.upstreamHit {
							t.Fatalf("outcome = %+v, want 403 and no upstream hit", got)
						}
						return
					}
					if got.status >= http.StatusBadRequest || !got.upstreamHit {
						t.Fatalf("outcome = %+v, want a forwarded request", got)
					}
				})
			}
		})
	}
}

// TestJWTCookieConnectHandshakeFollowsConfiguredAction covers the CONNECT
// handshake itself, which scans the headers the client sent with CONNECT.
func TestJWTCookieConnectHandshakeFollowsConfiguredAction(t *testing.T) {
	for _, tc := range []struct {
		action    string
		wantBlock bool
	}{
		{config.ActionBlock, true},
		{config.ActionWarn, false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			target := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
			t.Cleanup(target.Close)
			proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
				jwtHeaderScanConfig(cfg, tc.action)
			})
			t.Cleanup(cleanup)
			conn := dialProxy(t, proxyAddr)
			defer func() { _ = conn.Close() }()
			host := target.Listener.Addr().String()
			_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n", host, host, jwtCookieHeaders().Get("Cookie"))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read CONNECT response: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if tc.wantBlock && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for a JWT cookie under block", resp.StatusCode)
			}
			if !tc.wantBlock && resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 for a JWT cookie under warn", resp.StatusCode)
			}
		})
	}
}

// TestJWTCookieHeaderDLPDecisionHasNoCookieSpecialCase is the unit-level
// statement of the same rule: headerDLPDecision treats Cookie like any header.
func TestJWTCookieHeaderDLPDecisionHasNoCookieSpecialCase(t *testing.T) {
	cfg := config.Defaults()
	cfg.RequestBodyScanning.Action = config.ActionBlock
	jwt := scanner.TextDLPMatch{PatternName: "JWT Token", Severity: config.SeverityHigh}
	for _, header := range []string{"Cookie", "Authorization", "X-Session"} {
		action, hard := headerDLPDecision(&BodyScanResult{DLPMatches: []scanner.TextDLPMatch{jwt}, HeaderName: header}, cfg)
		if action != config.ActionBlock {
			t.Fatalf("%s: action = %q (hard=%v), want %q", header, action, hard, config.ActionBlock)
		}
	}
	cfg.RequestBodyScanning.Action = config.ActionWarn
	action, hard := headerDLPDecision(&BodyScanResult{DLPMatches: []scanner.TextDLPMatch{jwt}, HeaderName: "Cookie"}, cfg)
	if action != config.ActionWarn || hard {
		t.Fatalf("Cookie under warn = (%q, %v), want (%q, false)", action, hard, config.ActionWarn)
	}
}

// TestJWTCookieIssuerBoundOmissionIsTheOnlyException is the positive control for
// the rule above. Under a configured block, a JWT session cookie that an
// intercepted HTTPS origin issued to this identity is returned to that origin
// without a finding, while the same cookie before issuance, or presented by an
// identity the evidence was not recorded for, is denied. No other condition
// downgrades it.
func TestJWTCookieIssuerBoundOmissionIsTheOnlyException(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	jwt := issuerJWTShapedValue()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Add("Set-Cookie", "session="+jwt+"; Path=/; Secure; HttpOnly")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	issuerCookieTestConfig(t, cfg)
	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	do := func(agent string, path, cookie string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
			Logger: logger, Metrics: m, Request: req, Proxy: p,
			Agent: agent, ActorAuth: envelope.ActorAuthBound,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	returned := "session=" + jwt
	if got := do("agent-one", "/account", returned); got != http.StatusForbidden {
		t.Fatalf("before issuance = %d, want 403", got)
	}
	if got := do("agent-one", "/login", ""); got != http.StatusOK {
		t.Fatalf("issuing response = %d, want 200", got)
	}
	if got := do("agent-one", "/account", returned); got != http.StatusOK {
		t.Fatalf("issuer-bound return = %d, want 200 (issuer-bound omission must still apply)", got)
	}
	if got := do("agent-two", "/account", returned); got != http.StatusForbidden {
		t.Fatalf("another identity = %d, want 403", got)
	}
}
