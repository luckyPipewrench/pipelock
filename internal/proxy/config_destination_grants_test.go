// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const proxyGrantHost = "preview.vendor.example"

func proxyGrantConfig(t *testing.T, address string) *config.Config {
	t.Helper()
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.ForwardProxy.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	cfg.DestinationGrants = []config.DestinationGrant{{Protocol: "tcp", Host: proxyGrantHost, Port: uint16(port)}}
	cfg.DNS.HostOverrides = map[string][]string{proxyGrantHost: {"127.0.0.1"}, "other.vendor.example": {"127.0.0.1"}}
	return cfg
}

func newConfigGrantProxy(t *testing.T, cfg *config.Config) *Proxy {
	t.Helper()
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestProxyDestinationGrantsTransportsAndReload(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/socket" {
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_ = wsutil.WriteServerText(conn, []byte("approved preview"))
			return
		}
		_, _ = io.WriteString(w, "approved preview")
	}))
	defer upstream.Close()
	cfg := proxyGrantConfig(t, upstream.Listener.Addr().String())
	p := newConfigGrantProxy(t, cfg)
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	portText := strconv.Itoa(int(cfg.DestinationGrants[0].Port))
	target := "http://" + net.JoinHostPort(proxyGrantHost, portText) + "/"
	request := func(t *testing.T, raw string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		requestClient := client
		if strings.HasPrefix(raw, server.URL+"/") {
			requestClient = server.Client()
		}
		resp, err := requestClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("status=%d body=%s, want %d", resp.StatusCode, body, want)
		}
		if want == http.StatusOK && !strings.Contains(string(body), "approved preview") {
			t.Fatalf("missing preview: %s", body)
		}
	}
	t.Run("forward", func(t *testing.T) { request(t, target, http.StatusOK) })
	t.Run("fetch", func(t *testing.T) { request(t, server.URL+"/fetch?url="+url.QueryEscape(target), http.StatusOK) })
	t.Run("websocket", func(t *testing.T) {
		raw := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?url=" + url.QueryEscape(strings.Replace(target, "http:", "ws:", 1)+"socket")
		dialer := ws.Dialer{Timeout: 5 * time.Second}
		conn, reader, _, err := dialer.Dial(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var source io.Reader = conn
		if reader != nil {
			source = reader
		}
		payload, _, err := wsutil.ReadServerData(struct {
			io.Reader
			io.Writer
		}{Reader: source, Writer: conn})
		if err != nil || string(payload) != "approved preview" {
			t.Fatalf("frame=%q, err=%v", payload, err)
		}
	})
	for _, tc := range []struct{ name, target string }{
		{"wrong host", "http://other.vendor.example:" + portText + "/"},
		{"wrong port", "http://preview.vendor.example:1/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := hits.Load()
			request(t, tc.target, http.StatusForbidden)
			if hits.Load() != before {
				t.Fatal("refused request reached upstream")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		grants []config.DestinationGrant
		status int
	}{
		{"unrelated reload preserves", cfg.DestinationGrants, http.StatusOK},
		{"reload revokes", nil, http.StatusForbidden},
		{"regrant", cfg.DestinationGrants, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := cfg.Clone()
			next.DestinationGrants = tc.grants
			next.ExplainBlocks = new(true)
			sc, err := scanner.New(next)
			if err != nil {
				t.Fatal(err)
			}
			if !p.Reload(next, sc) {
				t.Fatal("Reload failed")
			}
			request(t, target, tc.status)
		})
	}
}

func TestProxyDestinationGrantsEncryptedCONNECT(t *testing.T) {
	t.Parallel()
	ca, key, _, err := certgen.GenerateCA("Preview test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certgen.GenerateLeaf(ca, key, proxyGrantHost, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "encrypted preview")
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
	upstream.StartTLS()
	defer upstream.Close()
	cfg := proxyGrantConfig(t, upstream.Listener.Addr().String())
	p := newConfigGrantProxy(t, cfg)
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, tc := range []struct {
		name    string
		grants  []config.DestinationGrant
		allowed bool
	}{
		{"grant", cfg.DestinationGrants, true},
		{"revoke", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := cfg.Clone()
			next.DestinationGrants = tc.grants
			sc, err := scanner.New(next)
			if err != nil {
				t.Fatal(err)
			}
			if !p.Reload(next, sc) {
				t.Fatal("Reload failed")
			}
			transport.CloseIdleConnections()
			raw := "https://" + net.JoinHostPort(proxyGrantHost, strconv.Itoa(int(cfg.DestinationGrants[0].Port))) + "/"
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if !tc.allowed {
				if resp != nil {
					_ = resp.Body.Close()
				}
				if err == nil || !strings.Contains(err.Error(), "Forbidden") {
					t.Fatalf("revoked CONNECT = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != "encrypted preview" {
				t.Fatalf("encrypted response=%q, err=%v", body, err)
			}
		})
	}
}

func TestProxyDestinationGrantsDNSChangesFailClosed(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	cfg := proxyGrantConfig(t, upstream.Listener.Addr().String())
	p := newConfigGrantProxy(t, cfg)
	port := strconv.Itoa(int(cfg.DestinationGrants[0].Port))
	for _, tc := range []struct {
		name    string
		scanned []string
		reason  blockreason.Reason
	}{
		{"changed answer", []string{"203.0.113.10"}, blockreason.SSRFDNSRebind},
		{"missing snapshot", nil, blockreason.SSRFPrivateIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := withSSRFDialScanSnapshot(context.Background(), proxyGrantHost, port, tc.scanned)
			conn, err := p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort(proxyGrantHost, port))
			if conn != nil {
				_ = conn.Close()
			}
			var blocked *ssrfDialBlockError
			if !errors.As(err, &blocked) || blocked.reason != tc.reason {
				t.Fatalf("dial error=%v, want %s", err, tc.reason)
			}
		})
	}
	for _, ip := range []string{"169.254.169.254", "169.254.1.2", "224.0.0.1", "0.0.0.0"} {
		t.Run("protected "+ip, func(t *testing.T) {
			next := cfg.Clone()
			next.DNS.HostOverrides = map[string][]string{proxyGrantHost: {ip}}
			sc, err := scanner.New(next)
			if err != nil {
				t.Fatal(err)
			}
			if !p.Reload(next, sc) {
				t.Fatal("Reload failed")
			}
			ctx := withSSRFDialScanSnapshot(context.Background(), proxyGrantHost, port, []string{ip})
			conn, err := p.ssrfSafeDialContext(ctx, "tcp", net.JoinHostPort(proxyGrantHost, port))
			if conn != nil {
				_ = conn.Close()
			}
			var blocked *ssrfDialBlockError
			if !errors.As(err, &blocked) {
				t.Fatalf("protected dial error=%v", err)
			}
		})
	}
}
