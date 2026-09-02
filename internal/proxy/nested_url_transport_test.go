// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const nestedMetadataQuery = "target=http://169.254.169.254/latest/meta-data/"

func nestedURLProxyConfig() *config.Config {
	cfg := config.Defaults()
	cfg.APIAllowlist = nil
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.DLP.Patterns = nil
	return cfg
}

func TestFetchEndpoint_NestedMetadataURLBlocked(t *testing.T) {
	cfg := nestedURLProxyConfig()
	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	target := "https://mirror.vendor.example/pkg?" + nestedMetadataQuery
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", w.Code, w.Body.String())
	}
	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Blocked {
		t.Fatal("expected blocked=true")
	}
	if !strings.Contains(resp.BlockReason, "nested URL") {
		t.Fatalf("block_reason=%q want nested URL", resp.BlockReason)
	}
}

func TestForwardHTTP_NestedMetadataURLBlocked(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
		cfg.DLP.Patterns = nil
	})
	defer cleanup()

	resp := doGet(t, proxyClient(proxyAddr), backend.URL+"/pkg?"+nestedMetadataQuery)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 403 body=%s", resp.StatusCode, body)
	}
	if hits.Load() != 0 {
		t.Fatal("upstream invoked despite nested metadata URL")
	}
}

func TestInterceptTunnel_NestedMetadataURLBlocked(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.DLP.Patterns = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	addr := upstream.Listener.Addr().String()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/api?"+nestedMetadataQuery, nil)
	resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
}

func TestFetchEndpoint_RedirectNestedMetadataURLBlocked(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://mirror.vendor.example/pkg?"+nestedMetadataQuery, http.StatusFound)
	}))
	defer backend.Close()

	cfg := nestedURLProxyConfig()
	cfg.FetchProxy.TimeoutSeconds = 5
	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(backend.URL+"/start"), nil)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", w.Code, w.Body.String())
	}
	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Blocked {
		t.Fatal("expected blocked=true")
	}
	if !strings.Contains(resp.BlockReason, "nested URL") {
		t.Fatalf("block_reason=%q want nested URL", resp.BlockReason)
	}
}

func TestSubmitProfile_NestedMetadataURLBlocked(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.DLP.Patterns = nil
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	reqURL := proxy.URL + "/v1/batch?" + nestedMetadataQuery
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, reqURL, strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
	if upstreamHit.Load() {
		t.Fatal("upstream invoked despite nested metadata URL")
	}
}
