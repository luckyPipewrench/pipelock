// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// namespaceRelayUpstreams are upstream behaviours that each try to write into
// the X-Pipelock-* namespace by a different route. Every response path that
// relays an upstream response must drop all of them.
func namespaceRelayUpstreams() []struct {
	name     string
	upstream http.HandlerFunc
} {
	return []struct {
		name     string
		upstream http.HandlerFunc
	}{
		{
			name: "final headers",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(blockreason.HeaderReason, forgedBlockReason)
				w.Header().Set("X-Pipelock-Hint", "forged-hint")
				w.Header().Set(blockreason.HeaderRecordedReceipt, "forged-receipt")
				w.Header().Set("X-Pipelock-Block-Version", "forged")
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("fine"))
			},
		},
		{
			name: "event stream",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(blockreason.HeaderReason, forgedBlockReason)
				w.Header().Set("X-Pipelock-Hint", "forged-hint")
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: ordinary event\n\n"))
			},
		},
		{
			name: "declared trailer",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Trailer", forgedTrailerName+", X-Other")
				_, _ = w.Write([]byte("fine"))
				w.Header().Set(forgedTrailerName, forgedBlockReason)
				w.Header().Set("X-Other", "kept")
			},
		},
		{
			name: "undeclared trailer",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("fine"))
				w.(http.Flusher).Flush()
				w.Header().Set(http.TrailerPrefix+forgedTrailerName, forgedBlockReason)
			},
		},
		{
			name: "early hints",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(blockreason.HeaderReason, forgedBlockReason)
				w.WriteHeader(http.StatusEarlyHints)
				w.Header().Del(blockreason.HeaderReason)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("fine"))
			},
		},
	}
}

func requireCleanRelayedResponse(t *testing.T, resp *http.Response, informative []http.Header) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the relay must forward, not block): %s", resp.StatusCode, body)
	}
	requireNoPipelockNamespace(t, "final response header", resp.Header)
	requireNoPipelockNamespace(t, "trailer", resp.Trailer)
	for i, h := range informative {
		requireNoPipelockNamespace(t, "1xx response "+string(rune('0'+i)), h)
	}
	for _, announced := range resp.Header.Values("Trailer") {
		if isPipelockNamespaceName(announced) || announced == forgedTrailerName {
			t.Fatalf("Trailer header announces a Pipelock-namespace name: %q", announced)
		}
	}
}

// TestForwardUpstreamCannotWritePipelockNamespace is the forward-proxy side of
// the reverse proxy's namespace rule: an allowed upstream response may not
// carry a block reason, hint, receipt handle or any other X-Pipelock-* name.
func TestForwardUpstreamCannotWritePipelockNamespace(t *testing.T) {
	for _, tc := range namespaceRelayUpstreams() {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(tc.upstream)
			t.Cleanup(upstream.Close)
			cfg := shieldRewriteMarkerConfig()
			cfg.BrowserShield.Enabled = false
			cfg.ForwardProxy.Enabled = true
			proxyAddr, cleanup := startProxyOnFreePort(t, cfg)
			t.Cleanup(cleanup)

			var informative []http.Header
			trace := &httptrace.ClientTrace{
				Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
					informative = append(informative, http.Header(h).Clone())
					return nil
				},
			}
			req, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, upstream.URL, http.NoBody)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := proxyClient(proxyAddr).Do(req)
			if err != nil {
				t.Fatalf("forward request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			requireCleanRelayedResponse(t, resp, informative)
		})
	}
}

// TestInterceptUpstreamCannotWritePipelockNamespace is the same rule on the
// TLS interception path.
func TestInterceptUpstreamCannotWritePipelockNamespace(t *testing.T) {
	for _, tc := range namespaceRelayUpstreams() {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(tc.upstream)
			t.Cleanup(upstream.Close)
			cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
			cfg.DLP.Patterns = nil
			cfg.ResponseScanning.Enabled = false
			cfg.BrowserShield.Enabled = false
			p, err := New(cfg, audit.NewNop(), sc, m)
			if err != nil {
				t.Fatalf("new proxy: %v", err)
			}
			t.Cleanup(func() { p.Close() })

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, http.NoBody)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, request, p)
			defer func() { _ = resp.Body.Close() }()
			requireCleanRelayedResponse(t, resp, nil)
		})
	}
}
