// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
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
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestConfiguredMetricsListenerBlocksMediatedAgentTraffic proves the
// containment oracle cannot be reopened by the generic SSRF IP allowlist.
// Each subtest reaches the same configured metrics address through a separate
// proxy transport surface and requires the dial path to refuse it before any
// request reaches the endpoint. WebSocket, MCP stdio, and MCP HTTP/SSE are not
// repeated here because their network paths converge on the same
// ssrfSafeDialContext covered below.
func TestConfiguredMetricsListenerBlocksMediatedAgentTraffic(t *testing.T) {
	var hits atomic.Int64
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer metricsServer.Close()

	metricsAddr := strings.TrimPrefix(metricsServer.URL, "http://")
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.Internal = config.Defaults().Internal
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
		cfg.MetricsListen = metricsAddr
	})
	defer cleanup()

	assertBlocked := func(t *testing.T, status int, body string) {
		t.Helper()
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body=%s", status, http.StatusForbidden, body)
		}
		if got := hits.Load(); got != 0 {
			t.Fatalf("metrics listener received %d request(s), want 0", got)
		}
	}

	t.Run("fetch", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(metricsServer.URL+"/metrics"), nil)
		rec := httptest.NewRecorder()
		p.handleFetch(rec, req)
		assertBlocked(t, rec.Code, rec.Body.String())
	})

	t.Run("forward proxy", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, metricsServer.URL+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := proxyClient(proxyAddr).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertBlocked(t, resp.StatusCode, string(body))
	})

	t.Run("CONNECT", func(t *testing.T) {
		conn := dialProxy(t, proxyAddr)
		defer func() { _ = conn.Close() }()
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", metricsAddr, metricsAddr); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertBlocked(t, resp.StatusCode, string(body))
	})

	t.Run("absolute URI", func(t *testing.T) {
		conn := dialProxy(t, proxyAddr)
		defer func() { _ = conn.Close() }()
		if _, err := fmt.Fprintf(conn, "GET %s/metrics HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", metricsServer.URL, metricsAddr); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertBlocked(t, resp.StatusCode, string(body))
	})
}

func TestConfiguredMetricsListenerDenyPrecedesGenericExceptions(t *testing.T) {
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer metricsServer.Close()

	metricsAddr := strings.TrimPrefix(metricsServer.URL, "http://")
	_, metricsPort, err := net.SplitHostPort(metricsAddr)
	if err != nil {
		t.Fatal(err)
	}

	newMetricsProxy := func(t *testing.T, cfg *config.Config, options scanner.Options) (*Proxy, *scanner.Scanner) {
		t.Helper()
		sc, err := scanner.NewWithOptions(cfg, options)
		if err != nil {
			t.Fatalf("scanner.NewWithOptions: %v", err)
		}
		p, err := New(cfg, audit.NewNop(), sc, metrics.New())
		if err != nil {
			sc.Close()
			t.Fatalf("proxy.New: %v", err)
		}
		t.Cleanup(p.Close)
		return p, sc
	}
	assertBlocked := func(t *testing.T, p *Proxy, ctx context.Context, target string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		conn, err := p.ssrfSafeDialContext(ctx, "tcp", target)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatalf("dial to configured metrics listener succeeded through %s", target)
		}
		var blocked *ssrfDialBlockError
		if !errors.As(err, &blocked) || !strings.Contains(blocked.detail, "configured metrics listener") {
			t.Fatalf("dial error = %T %v, want configured-metrics denial", err, err)
		}
	}

	t.Run("trusted domain", func(t *testing.T) {
		const host = "metrics-trusted.example"
		cfg := config.Defaults()
		cfg.Internal = config.Defaults().Internal
		cfg.MetricsListen = metricsAddr
		cfg.TrustedDomains = []string{host}
		cfg.DNS.HostOverrides = map[string][]string{host: {"127.0.0.1"}}
		p, sc := newMetricsProxy(t, cfg, scanner.Options{})
		scan := sc.Scan(t.Context(), "http://"+net.JoinHostPort(host, metricsPort)+"/metrics")
		if !scan.Allowed {
			t.Fatalf("trusted-domain scan blocked: %+v", scan)
		}
		assertBlocked(t, p, t.Context(), net.JoinHostPort(host, metricsPort))
	})

	t.Run("destination grant", func(t *testing.T) {
		const host = "metrics-grant.example"
		cfg := config.Defaults()
		cfg.Internal = config.Defaults().Internal
		cfg.MetricsListen = metricsAddr
		cfg.DNS.HostOverrides = map[string][]string{host: {"127.0.0.1"}}
		grantPort, err := destination.ParsePort(metricsPort)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := destination.NewGrant(destination.NetworkTCP, host, grantPort)
		if err != nil {
			t.Fatal(err)
		}
		grants, err := destination.NewGrantSet(grant)
		if err != nil {
			t.Fatal(err)
		}
		p, sc := newMetricsProxy(t, cfg, scanner.Options{DestinationGrants: grants})
		scan := sc.Scan(t.Context(), "http://"+net.JoinHostPort(host, metricsPort)+"/metrics")
		if !scan.Allowed {
			t.Fatalf("guard-granted scan blocked: %+v", scan)
		}
		if !scannerDestinationGranted(sc, host, metricsPort) {
			t.Fatal("destination grant did not authorize the metrics host and port")
		}
		ctx := withAllowedSSRFDialScanSnapshot(t.Context(), sc, host, metricsPort, scan)
		assertBlocked(t, p, ctx, net.JoinHostPort(host, metricsPort))
	})

	t.Run("IP allowlist", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Internal = config.Defaults().Internal
		cfg.MetricsListen = metricsAddr
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
		p, _ := newMetricsProxy(t, cfg, scanner.Options{})
		assertBlocked(t, p, t.Context(), metricsAddr)
	})
}

func TestConfiguredWildcardMetricsListenerBlocksLocalAddressesOnNumericPort(t *testing.T) {
	for _, listen := range []string{":09091", "0.0.0.0:9091", "[::]:9091"} {
		t.Run(listen, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.MetricsListen = listen
			p := &Proxy{}
			p.ConfigPtr().Store(cfg)

			err := p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "9091", net.ParseIP("127.0.0.1"))
			var blocked *ssrfDialBlockError
			if !errors.As(err, &blocked) || !strings.Contains(blocked.detail, "configured metrics listener") {
				t.Fatalf("blockIfConfiguredMetricsTarget error = %T %v, want configured-metrics denial", err, err)
			}
		})
	}

	t.Run("different port remains available", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.MetricsListen = ":9091"
		p := &Proxy{}
		p.ConfigPtr().Store(cfg)
		if err := p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "9092", net.ParseIP("127.0.0.1")); err != nil {
			t.Fatalf("different port blocked: %v", err)
		}
	})
}

func localhostIPv4(t *testing.T) net.IP {
	t.Helper()
	resolved, err := net.DefaultResolver.LookupHost(t.Context(), "localhost")
	if err != nil {
		t.Fatalf("lookup localhost: %v", err)
	}
	for _, addr := range resolved {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil && v4.IsLoopback() {
			return v4
		}
	}
	t.Fatal("localhost did not resolve to an IPv4 loopback address")
	return nil
}

func assertConfiguredMetricsDenied(t *testing.T, err error) {
	t.Helper()
	var blocked *ssrfDialBlockError
	if !errors.As(err, &blocked) || !strings.Contains(blocked.detail, "configured metrics listener") {
		t.Fatalf("error = %T %v, want configured-metrics denial", err, err)
	}
}

// TestHostnameConfiguredMetricsListenerBlocksResolvedAddress is the
// reproduction for the hostname fail-open: MetricsListen is a hostname
// (localhost), the dial target is the IP that hostname resolves to, and
// the generic SSRF IP allowlist would otherwise permit the hop. Before
// the fix, net.ParseIP("localhost") is nil and the guard returns nil
// (ALLOW). After the fix, the same dial is denied.
func TestHostnameConfiguredMetricsListenerBlocksResolvedAddress(t *testing.T) {
	loopback := localhostIPv4(t)
	const metricsPort = "9091"
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("localhost", metricsPort)
	p := &Proxy{}
	p.ConfigPtr().Store(cfg)

	err := p.blockIfConfiguredMetricsTarget(t.Context(), loopback.String(), metricsPort, loopback)
	assertConfiguredMetricsDenied(t, err)
}

func TestHostnameConfiguredMetricsListenerBlocksDialThroughAllowlist(t *testing.T) {
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer metricsServer.Close()

	metricsAddr := strings.TrimPrefix(metricsServer.URL, "http://")
	metricsHost, metricsPort, err := net.SplitHostPort(metricsAddr)
	if err != nil {
		t.Fatal(err)
	}
	metricsIP := net.ParseIP(metricsHost)
	if metricsIP == nil || !metricsIP.Equal(localhostIPv4(t)) {
		t.Fatalf("test listener %s is not the IPv4 localhost address this reproduction dials", metricsAddr)
	}

	cfg := config.Defaults()
	cfg.Internal = config.Defaults().Internal
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.MetricsListen = net.JoinHostPort("localhost", metricsPort)
	sc, err := scanner.NewWithOptions(cfg, scanner.Options{})
	if err != nil {
		t.Fatalf("scanner.NewWithOptions: %v", err)
	}
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		sc.Close()
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, dialErr := p.ssrfSafeDialContext(ctx, "tcp", metricsAddr)
	if conn != nil {
		_ = conn.Close()
	}
	if dialErr == nil {
		t.Fatalf("dial to %s succeeded; hostname-configured metrics guard failed open", metricsAddr)
	}
	assertConfiguredMetricsDenied(t, dialErr)
}
