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
			p.refreshMetricsDialTarget(cfg.MetricsListen)

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
		p.refreshMetricsDialTarget(cfg.MetricsListen)
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
	p.refreshMetricsDialTarget(cfg.MetricsListen)

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

func TestHostnameMetricsListenerUnresolvableFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p := &Proxy{
		lookupMetricsHost: func(_ context.Context, host string) ([]string, error) {
			return nil, fmt.Errorf("stub nxdomain for %s", host)
		},
	}
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)

	err := p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "9091", net.ParseIP("127.0.0.1"))
	var blocked *ssrfDialBlockError
	if !errors.As(err, &blocked) || !strings.Contains(blocked.detail, "cannot verify") {
		t.Fatalf("error = %T %v, want cannot-verify denial", err, err)
	}
	if err := p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "9092", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("different port blocked while hostname was unverified: %v", err)
	}
}

func TestHostnameMetricsListenerEmptyResolutionFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			return []string{}, nil
		},
	}
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)

	err := p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10"))
	var blocked *ssrfDialBlockError
	if !errors.As(err, &blocked) || !strings.Contains(blocked.detail, "cannot verify") {
		t.Fatalf("error = %T %v, want cannot-verify denial", err, err)
	}
}

func TestHostnameMetricsListenerAllowsUnrelatedIPAndPort(t *testing.T) {
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.10"}, nil
		},
	}
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)

	if err := p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.11", "9091", net.ParseIP("192.0.2.11")); err != nil {
		t.Fatalf("unrelated IP blocked: %v", err)
	}
	if err := p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9092", net.ParseIP("192.0.2.10")); err != nil {
		t.Fatalf("different port blocked: %v", err)
	}
}

func TestHostnameMetricsListenerLookupCachedAcrossDials(t *testing.T) {
	var lookups atomic.Int64
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			lookups.Add(1)
			return []string{"192.0.2.10"}, nil
		},
	}
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	ip := net.ParseIP("192.0.2.10")
	for range 8 {
		assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", ip))
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("lookups = %d, want 1 (hot path must not resolve per dial)", got)
	}
}

func TestHostnameMetricsListenerReloadsWhenListenChanges(t *testing.T) {
	var seen []string
	p := &Proxy{
		lookupMetricsHost: func(_ context.Context, host string) ([]string, error) {
			seen = append(seen, host)
			switch host {
			case "metrics-a.internal":
				return []string{"192.0.2.10"}, nil
			case "metrics-b.internal":
				return []string{"192.0.2.20"}, nil
			default:
				return nil, fmt.Errorf("unexpected host %s", host)
			}
		},
	}

	cfgA := config.Defaults()
	cfgA.MetricsListen = net.JoinHostPort("metrics-a.internal", "9091")
	p.ConfigPtr().Store(cfgA)
	p.refreshMetricsDialTarget(cfgA.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10")))
	if err := p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.20", "9091", net.ParseIP("192.0.2.20")); err != nil {
		t.Fatalf("other IP blocked before reload: %v", err)
	}

	cfgB := config.Defaults()
	cfgB.MetricsListen = net.JoinHostPort("metrics-b.internal", "9091")
	p.ConfigPtr().Store(cfgB)
	p.refreshMetricsDialTarget(cfgB.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.20", "9091", net.ParseIP("192.0.2.20")))
	if err := p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10")); err != nil {
		t.Fatalf("previous metrics IP still blocked after reload: %v", err)
	}
	if len(seen) != 2 || seen[0] != "metrics-a.internal" || seen[1] != "metrics-b.internal" {
		t.Fatalf("lookups = %v, want [metrics-a.internal metrics-b.internal]", seen)
	}
}

func TestHostnameMetricsListenerRefreshReresolvesSameListen(t *testing.T) {
	var lookups atomic.Int64
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			if lookups.Add(1) == 1 {
				return []string{"192.0.2.10"}, nil
			}
			return []string{"192.0.2.20"}, nil
		},
	}
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10")))

	p.refreshMetricsDialTarget(cfg.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.20", "9091", net.ParseIP("192.0.2.20")))
	if err := p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10")); err != nil {
		t.Fatalf("stale metrics IP still blocked after refresh: %v", err)
	}
}

func TestBoundMetricsListenerAddressOverridesHostnameResolution(t *testing.T) {
	boundListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = boundListener.Close() })
	boundHost, boundPort, err := net.SplitHostPort(boundListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	boundIP := net.ParseIP(boundHost)
	if boundIP == nil {
		t.Fatalf("bound listener host %q is not an IP address", boundHost)
	}

	var lookups atomic.Int64
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			lookups.Add(1)
			return []string{"192.0.2.10"}, nil
		},
	}
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", boundPort)
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)

	if err := p.blockIfConfiguredMetricsTarget(t.Context(), boundIP.String(), boundPort, boundIP); err != nil {
		t.Fatalf("precondition: stale hostname resolution blocked bound address: %v", err)
	}

	p.UpdateMetricsDialTargetFromBoundAddr(boundListener.Addr().String())
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), boundIP.String(), boundPort, boundIP))
	if got := lookups.Load(); got != 1 {
		t.Fatalf("lookups = %d, want 1; the bound numeric address must not be resolved", got)
	}
}

func TestMalformedBoundMetricsListenerAddressFailsClosed(t *testing.T) {
	p := &Proxy{}
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	p.UpdateMetricsDialTargetFromBoundAddr("not-a-host-port")

	err := p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10"))
	var blocked *ssrfDialBlockError
	if !errors.As(err, &blocked) || !strings.Contains(blocked.detail, "cannot verify") {
		t.Fatalf("error = %T %v, want cannot-verify denial", err, err)
	}
}

func TestMetricsDialTargetRefreshClearsEmptyListen(t *testing.T) {
	var nilProxy *Proxy
	nilProxy.refreshMetricsDialTarget("localhost:9091")

	p := &Proxy{}
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p.lookupMetricsHost = func(context.Context, string) ([]string, error) {
		return []string{"192.0.2.10"}, nil
	}
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10")))
	p.refreshMetricsDialTarget("")
	if cached := p.metricsTargetPtr.Load(); cached != nil {
		t.Fatal("empty listen left a cached metrics target")
	}
}

func TestMalformedMetricsListenAllowsDial(t *testing.T) {
	t.Run("unparseable address", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.MetricsListen = "not-a-host-port"
		p := &Proxy{}
		p.ConfigPtr().Store(cfg)
		p.refreshMetricsDialTarget(cfg.MetricsListen)
		if err := p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "9091", net.ParseIP("127.0.0.1")); err != nil {
			t.Fatalf("unparseable MetricsListen blocked: %v", err)
		}
	})
	t.Run("unparseable port", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.MetricsListen = "localhost:notaport"
		p := &Proxy{}
		p.ConfigPtr().Store(cfg)
		p.refreshMetricsDialTarget(cfg.MetricsListen)
		if err := p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "9091", net.ParseIP("127.0.0.1")); err != nil {
			t.Fatalf("unparseable metrics port blocked: %v", err)
		}
	})
}

func TestHostnameMetricsListenerWithSignedPortFromLoadBlocks(t *testing.T) {
	cfg, err := config.LoadBytes([]byte("metrics_listen: metrics.internal:+9091\n"))
	if err != nil {
		t.Fatalf("config.LoadBytes: %v", err)
	}
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.10"}, nil
		},
	}
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)

	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10")))
}

func TestHostnameMetricsListenerSkipsUnparseableLookupRecords(t *testing.T) {
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			return []string{"not-an-ip", "192.0.2.10"}, nil
		},
	}
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "192.0.2.10", "9091", net.ParseIP("192.0.2.10")))
}

// TestBoundMetricsTargetSurvivesUnrelatedReload pins the reload direction of the
// bound-address handoff. With a configured port of 0 the configured string
// carries no usable port, so rebuilding the target from it during an unrelated
// reload would drop the only value a dial can match and silently reopen the
// metrics listener to every mediated transport.
func TestBoundMetricsTargetSurvivesUnrelatedReload(t *testing.T) {
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		},
	}
	cfg := config.Defaults()
	cfg.MetricsListen = "metrics.internal:0"
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)

	// The listener binds an ephemeral port and reports what it actually got,
	// which is the only form carrying a port a dial can match.
	p.UpdateMetricsDialTargetFromBoundAddr("127.0.0.1:44321")
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "44321", net.ParseIP("127.0.0.1")))

	// An unrelated reload leaves metrics_listen untouched.
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "44321", net.ParseIP("127.0.0.1")))
}

// TestChangedMetricsListenReplacesBoundTarget is the other direction: a reload
// that genuinely changes metrics_listen must stop defending the retired port
// and start defending the new one, or the guard protects an address the process
// no longer listens on while leaving the live one open.
func TestChangedMetricsListenReplacesBoundTarget(t *testing.T) {
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		},
	}
	cfg := config.Defaults()
	cfg.MetricsListen = "metrics.internal:0"
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	p.UpdateMetricsDialTargetFromBoundAddr("127.0.0.1:44322")

	changed := config.Defaults()
	changed.MetricsListen = "127.0.0.1:44323"
	p.ConfigPtr().Store(changed)
	p.refreshMetricsDialTarget(changed.MetricsListen)

	if err := p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "44322", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("dial to the retired metrics port = %v, want it no longer treated as the metrics listener", err)
	}
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "44323", net.ParseIP("127.0.0.1")))
}

// TestUnpublishedMetricsTargetFailsClosedWithoutLookup covers a dial reaching
// the guard with no published snapshot. The dial path deliberately does not
// resolve, because doing so would block every mediated request for up to the
// lookup timeout and concurrent misses would each repeat the work. The only
// honest answers are block-as-unverifiable or allow, and allow is the fail-open
// this guard exists to prevent.
func TestUnpublishedMetricsTargetFailsClosedWithoutLookup(t *testing.T) {
	var lookups atomic.Int64
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			lookups.Add(1)
			return []string{"10.1.2.3"}, nil
		},
	}
	cfg := config.Defaults()
	cfg.MetricsListen = net.JoinHostPort("metrics.internal", "9091")
	p.ConfigPtr().Store(cfg)
	// Deliberately publish nothing, standing in for a stale or absent snapshot.

	err := p.blockIfConfiguredMetricsTarget(t.Context(), "metrics.internal", "9091", net.ParseIP("10.1.2.3"))
	if err == nil {
		t.Fatal("dial with no published metrics target was allowed, want an unverifiable denial")
	}
	if !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("denial reason = %v, want a cannot-verify denial", err)
	}
	if got := lookups.Load(); got != 0 {
		t.Fatalf("lookups on the dial path = %d, want 0", got)
	}
}

func TestLiteralMetricsListenerDoesNotLookupHost(t *testing.T) {
	var lookups atomic.Int64
	p := &Proxy{
		lookupMetricsHost: func(context.Context, string) ([]string, error) {
			lookups.Add(1)
			return []string{"127.0.0.1"}, nil
		},
	}
	cfg := config.Defaults()
	cfg.MetricsListen = "127.0.0.1:9091"
	p.ConfigPtr().Store(cfg)
	p.refreshMetricsDialTarget(cfg.MetricsListen)
	assertConfiguredMetricsDenied(t, p.blockIfConfiguredMetricsTarget(t.Context(), "127.0.0.1", "9091", net.ParseIP("127.0.0.1")))
	if got := lookups.Load(); got != 0 {
		t.Fatalf("lookups = %d, want 0 for a literal MetricsListen", got)
	}
}
