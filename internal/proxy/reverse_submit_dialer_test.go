// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestSubmitProfile_SetSafeDialerIsUsed proves that after SetSafeDialer,
// the reverse proxy dials the upstream through the supplied dialer rather
// than the default transport. A sentinel dialer records that it was
// invoked and then delegates to a real dial so the request still
// completes end-to-end.
func TestSubmitProfile_SetSafeDialerIsUsed(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)

	var dialerCalls atomic.Int32
	sentinel := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalls.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	handlerProxy := submitProfileReverseProxyWithDialer(t, cfg, upstreamURL, sentinel)

	reqURL := handlerProxy.URL + "/v1/batch"
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, reqURL, strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !upstreamHit.Load() {
		t.Error("upstream was not reached")
	}
	if dialerCalls.Load() == 0 {
		t.Error("safe dialer was never invoked; SetSafeDialer did not take effect")
	}
}

// TestSubmitProfile_SetSafeDialerNilIsNoop verifies a nil dialer leaves the
// handler on its default transport (no panic, request still forwards).
func TestSubmitProfile_SetSafeDialerNilIsNoop(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	proxy := submitProfileReverseProxyWithDialer(t, cfg, upstreamURL, nil)

	reqURL := proxy.URL + "/v1/batch"
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, reqURL, strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (nil dialer must be a no-op)", resp.StatusCode)
	}
	if !upstreamHit.Load() {
		t.Error("upstream not reached with nil dialer")
	}
}

func TestSubmitProfile_ProxySafeDialerUsesScannerResolver(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL := submitProfileHostOverrideURL(t, upstream.URL, "submit.test")
	cfg, parsedUpstream := submitProfileTestConfig(upstreamURL)
	cfg.Internal = []string{"127.0.0.0/8"}
	cfg.TrustedDomains = []string{"submit.test"}
	cfg.DNS.HostOverrides = map[string][]string{
		"submit.test": {"127.0.0.1"},
	}

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	logger := audit.NewNop()
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("New proxy: %v", err)
	}

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	handler := NewReverseProxy(parsedUpstream, &cfgPtr, &scPtr, logger, metrics.New(), nil, nil, nil)
	handler.SetSafeDialer(p.SafeDialer())

	proxy := newIPv4Server(t, handler)
	t.Cleanup(proxy.Close)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, proxy.URL+"/v1/batch", strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post through reverse proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !upstreamHit.Load() {
		t.Fatal("upstream was not reached through Proxy.SafeDialer")
	}
}

func TestProxy_SafeDialerBlocksInternalIP(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = []string{"127.0.0.0/8"}

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("New proxy: %v", err)
	}

	dial := p.SafeDialer()
	if dial == nil {
		t.Fatal("SafeDialer returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", "127.0.0.1:1")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("SafeDialer allowed internal IP dial")
	}
	if !strings.Contains(err.Error(), "SSRF blocked") {
		t.Fatalf("SafeDialer error = %v, want SSRF blocked", err)
	}
}

func submitProfileHostOverrideURL(t *testing.T, upstreamURL, host string) string {
	t.Helper()

	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split upstream host: %v", err)
	}
	u.Host = net.JoinHostPort(host, port)
	return u.String()
}
