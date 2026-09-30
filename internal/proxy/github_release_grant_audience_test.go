// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const releaseGrantHost = "release-assets.githubusercontent.com"

// releaseGrantJWT builds a structurally valid JWT at runtime.
func releaseGrantJWT() string {
	enc := base64.RawURLEncoding
	sum := sha256.Sum256([]byte("release-grant-fixture"))
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc.EncodeToString([]byte(`{"aud":"release-assets.githubusercontent.com","iss":"github.com","path":"/asset","exp":1}`)) + "." +
		enc.EncodeToString(sum[:])
}

// CONNECT with TLS interception: the release host is dialed at its real name
// through a local override. Only a query-carried JWT reaches the upstream; a
// path-carried one, a header-carried one, and a query JWT at another host all
// block before the upstream sees them.
func TestInterceptTunnel_GitHubReleaseGrantJWT(t *testing.T) {
	jwt := releaseGrantJWT()
	for _, tc := range []struct {
		name      string
		host      string
		path      string
		header    string
		wantAllow bool
	}{
		{name: "query at release host", host: releaseGrantHost, path: "/asset/1?jwt=" + jwt, wantAllow: true},
		{name: "query at other host", host: "download.vendor.example", path: "/asset/1?jwt=" + jwt},
		{name: "query at lookalike host", host: releaseGrantHost + ".evil.example", path: "/asset/1?jwt=" + jwt},
		{name: "path at release host", host: releaseGrantHost, path: "/asset/" + jwt},
		{name: "header at release host", host: releaseGrantHost, path: "/asset/1?x=1", header: "Bearer " + jwt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				_, _ = fmt.Fprint(w, "asset")
			}))
			defer upstream.Close()

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			addr := upstream.Listener.Addr().String()
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatalf("SplitHostPort: %v", err)
			}
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.Action = config.ActionBlock
			cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
			cfg.RequestBodyScanning.SensitiveHeaders = []string{"Authorization"}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+tc.host+":"+port+tc.path, nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			dialer := &net.Dialer{}
			upstreamRT := upstream.Client().Transport.(*http.Transport).Clone()
			upstreamRT.TLSClientConfig = upstreamRT.TLSClientConfig.Clone()
			upstreamRT.TLSClientConfig.ServerName = upstream.Listener.Addr().(*net.TCPAddr).IP.String()
			upstreamRT.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}
			t.Cleanup(upstreamRT.CloseIdleConnections)

			resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
				Upstream:   upstream,
				TargetHost: tc.host,
				UpstreamRT: upstreamRT,
				Cache:      cache,
				Pool:       pool,
				Config:     cfg,
				Scanner:    sc,
				Logger:     logger,
				Metrics:    m,
				Request:    req,
				Proxy:      &Proxy{captureObs: capture.NopObserver{}, metrics: m},
			})
			defer func() { _ = resp.Body.Close() }()

			if !tc.wantAllow {
				if resp.StatusCode == http.StatusOK || upstreamHits.Load() != 0 {
					t.Fatalf("grant JWT reached the upstream: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
				}
				return
			}
			if resp.StatusCode != http.StatusOK || upstreamHits.Load() != 1 {
				t.Fatalf("release download grant blocked: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
			}
			assertMetricSampleValue(t, m,
				`pipelock_dlp_credential_audience_allows_total{pattern="JWT Token",surface="url"}`, 1)
		})
	}
}

// Fetch and redirect-follow: GitHub answers a release download with a 302 to
// the storage host carrying the grant. The fetch handler follows it itself, so
// the redirect scan decides. The control redirects the same grant to another
// host and must block before that host is dialed.
func TestFetchEndpoint_GitHubReleaseGrantRedirect(t *testing.T) {
	jwt := releaseGrantJWT()
	for _, tc := range []struct {
		name         string
		redirectHost string
		wantOK       bool
	}{
		{name: "release storage host", redirectHost: releaseGrantHost, wantOK: true},
		{name: "other host", redirectHost: "download.vendor.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var storageHits atomic.Int32
			storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				storageHits.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprint(w, "release asset bytes")
			}))
			defer storage.Close()
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+tc.redirectHost+"/asset/1?jwt="+jwt, http.StatusFound)
			}))
			defer origin.Close()

			cfg := config.Defaults()
			cfg.FetchProxy.TimeoutSeconds = 5
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.APIAllowlist = nil
			sc := scanner.MustNew(cfg)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			t.Cleanup(p.Close)

			pool := x509.NewCertPool()
			pool.AddCert(storage.Certificate())
			p.client.Transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					switch addr {
					case "github.example:80":
						return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
					case tc.redirectHost + ":443":
						return (&net.Dialer{}).DialContext(ctx, network, storage.Listener.Addr().String())
					}
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
				TLSClientConfig:    &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
				DisableCompression: true,
			}

			w := serveFetch(t, p, "http://github.example/o/r/releases/download/v1/tool.tar.gz")
			if tc.wantOK {
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "release asset bytes") || storageHits.Load() != 1 {
					t.Fatalf("release redirect not followed: status=%d hits=%d body=%s", w.Code, storageHits.Load(), w.Body.String())
				}
				return
			}
			if w.Code != http.StatusForbidden || storageHits.Load() != 0 {
				t.Fatalf("grant redirected to another host: status=%d hits=%d body=%s", w.Code, storageHits.Load(), w.Body.String())
			}
		})
	}
}

// Fetch pre-scan and forward-proxy absolute-URI: both refuse before any dial.
// The forward-proxy absolute-URI form is cleartext http, which never earns an
// audience allow, so it blocks even at the release host; https reaches the
// forward proxy as CONNECT, covered by the interception test above.
func TestGitHubReleaseGrantJWT_RefusedBeforeDial(t *testing.T) {
	jwt := releaseGrantJWT()

	t.Run("fetch", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.FetchProxy.TimeoutSeconds = 5
		cfg.Internal = nil
		sc := scanner.MustNew(cfg)
		p, err := New(cfg, audit.NewNop(), sc, metrics.New())
		if err != nil {
			t.Fatalf("proxy.New: %v", err)
		}
		t.Cleanup(p.Close)
		for name, target := range map[string]string{
			"other host":         "https://download.vendor.example/asset?jwt=" + jwt,
			"path at release":    "https://" + releaseGrantHost + "/asset/" + jwt,
			"cleartext at host":  "http://" + releaseGrantHost + "/asset?jwt=" + jwt,
			"userinfo lookalike": "https://" + releaseGrantHost + "@download.vendor.example/asset?jwt=" + url.QueryEscape(jwt),
		} {
			w := serveFetch(t, p, target)
			// The targets do not resolve, so a request that reached the dial
			// would fail as a gateway error; a 403 naming DLP is the pre-dial
			// scanner refusal.
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "DLP") {
				t.Errorf("%s: status = %d, want a 403 DLP refusal; body=%s", name, w.Code, w.Body.String())
			}
		}
	})

	t.Run("forward proxy absolute URI", func(t *testing.T) {
		proxyAddr, cleanup := setupForwardProxy(t, nil)
		defer cleanup()
		client := &http.Client{Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: proxyAddr}, nil },
		}}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+releaseGrantHost+"/asset?jwt="+jwt, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (cleartext earns no audience allow)", resp.StatusCode)
		}
	})
}
