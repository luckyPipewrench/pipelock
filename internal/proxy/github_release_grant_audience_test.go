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
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const releaseGrantHost = "release-assets.githubusercontent.com"

// The default release grant fixture is valid from 1000 to 1300. These clock
// values are an hour outside that window, well past the scanner's leeway.
const (
	releaseGrantExpiredNow = 1300 + 3600
	releaseGrantFutureNow  = 1000 - 3600
)

// releaseGrantJWT builds a structurally valid JWT at runtime.
func releaseGrantJWT() string {
	return releaseGrantJWTForHost(releaseGrantHost, 300)
}

// releaseGrantJWTForHost builds a structurally valid JWT with the given
// audience and lifetime.
func releaseGrantJWTForHost(host string, lifetimeSeconds int64) string {
	enc := base64.RawURLEncoding
	sum := sha256.Sum256([]byte("release-grant-fixture-" + host))
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc.EncodeToString([]byte(fmt.Sprintf(`{"aud":%q,"iss":"github.com","path":"releaseassetproduction.blob.core.windows.net","nbf":1000,"exp":%d}`, host, 1000+lifetimeSeconds))) + "." +
		enc.EncodeToString(sum[:])
}

// releaseGrantSASQuery builds GitHub's real release-asset redirect query
// shape: the Azure user-delegation SAS signature (32 raw bytes -> 44 base64
// characters, the exact shape of a real HMAC-SHA256 signature) beside the
// full set of signed SAS parameters and the release download grant JWT.
func releaseGrantSASQuery(jwt, sigSeed string) string {
	sum := sha256.Sum256([]byte(sigSeed))
	sig := base64.StdEncoding.EncodeToString(sum[:])
	return "sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-09-30T00%3A37%3A09Z" +
		"&skoid=00000000-0000-4000-8000-000000000001&sktid=00000000-0000-4000-8000-000000000002" +
		"&skt=2026-09-29T23%3A36%3A42Z&ske=2026-09-30T00%3A37%3A09Z&sks=b&skv=2018-11-09" +
		"&sig=" + url.QueryEscape(sig) + "&jwt=" + jwt
}

// CONNECT with TLS interception: the release host is dialed at its real name
// through a local override. Only a query-carried JWT reaches the upstream; a
// path-carried one, a header-carried one, and a query JWT at another host all
// block before the upstream sees them.
func TestInterceptTunnel_GitHubReleaseGrantJWT(t *testing.T) {
	jwt := releaseGrantJWT()
	for _, tc := range []struct {
		now       int64
		name      string
		host      string
		path      string
		header    string
		wantAllow bool
	}{
		{name: "expired validity window", host: releaseGrantHost, path: "/asset/1?jwt=" + jwt, now: releaseGrantExpiredNow},
		{name: "future validity window", host: releaseGrantHost, path: "/asset/1?jwt=" + jwt, now: releaseGrantFutureNow},
		{name: "query at release host", host: releaseGrantHost, path: "/asset/1?jwt=" + jwt, wantAllow: true},
		{name: "one hour grant", host: releaseGrantHost, path: "/asset/1?jwt=" + releaseGrantJWTForHost(releaseGrantHost, 3600), wantAllow: true},
		{name: "grant one second past cap", host: releaseGrantHost, path: "/asset/1?jwt=" + releaseGrantJWTForHost(releaseGrantHost, 3601)},
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
			now := int64(1100)
			if tc.now != 0 {
				now = tc.now
			}
			sc := releaseGrantScanner(t, cfg, time.Unix(now, 0))

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
				if resp.StatusCode != http.StatusForbidden || upstreamHits.Load() != 0 {
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
			sc := releaseGrantScanner(t, cfg, time.Unix(1100, 0))
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
	jwt := releaseGrantJWTForHost(releaseGrantHost, 3600)

	t.Run("fetch", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.FetchProxy.TimeoutSeconds = 5
		cfg.Internal = nil
		sc := releaseGrantScanner(t, cfg, time.Unix(1100, 0))
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

	// The real redirect shape: the Azure SAS travels beside the JWT. Cleartext
	// never earns an audience allow for either credential, so the SAS keeps
	// blocking even at the exact release host with a shape-valid grant beside
	// it.
	t.Run("forward proxy absolute URI, SAS beside a valid grant", func(t *testing.T) {
		proxyAddr, cleanup := setupForwardProxy(t, nil)
		defer cleanup()
		client := &http.Client{Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: proxyAddr}, nil },
		}}
		query := releaseGrantSASQuery(jwt, "cleartext-sas-fixture")
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+releaseGrantHost+"/asset?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (cleartext SAS earns no audience allow)", resp.StatusCode)
		}
	})
}

// CONNECT with TLS interception carrying the real redirect shape: the Azure
// SAS is allowed only beside a grant this scanner verifies for that exact
// host, with GitHub's whole delegation-key parameter set present. Every
// listed way to break that co-occurrence keeps the request blocked before the
// upstream sees it.
func TestInterceptTunnel_GitHubReleaseGrantSAS(t *testing.T) {
	jwt := releaseGrantJWT()
	otherHost := "download.vendor.example"
	for _, tc := range []struct {
		now       int64
		name      string
		host      string
		query     string
		wantAllow bool
	}{
		{name: "expired grant validity window", host: releaseGrantHost, query: releaseGrantSASQuery(jwt, "expired-window"), now: releaseGrantExpiredNow},
		{name: "future grant validity window", host: releaseGrantHost, query: releaseGrantSASQuery(jwt, "future-window"), now: releaseGrantFutureNow},
		{name: "expired SAS validity window", host: releaseGrantHost, query: strings.Replace(releaseGrantSASQuery(jwt, "sas-expiry-window"), "se=2026-09-30T00%3A37%3A09Z", "se=1970-01-01T00%3A00%3A00Z", 1)},
		{
			name:      "allow: real redirect shape",
			host:      releaseGrantHost,
			query:     releaseGrantSASQuery(jwt, "intercept-allow-fixture"),
			wantAllow: true,
		},
		{
			name:      "allow: one hour grant with SAS",
			host:      releaseGrantHost,
			query:     releaseGrantSASQuery(releaseGrantJWTForHost(releaseGrantHost, 3600), "intercept-hour-fixture"),
			wantAllow: true,
		},
		{
			name:  "deny: grant one second past cap with SAS",
			host:  releaseGrantHost,
			query: releaseGrantSASQuery(releaseGrantJWTForHost(releaseGrantHost, 3601), "intercept-over-cap-fixture"),
		},
		{
			name: "deny: SAS without any jwt",
			host: releaseGrantHost,
			query: strings.Replace(
				releaseGrantSASQuery(jwt, "intercept-no-jwt-fixture"), "&jwt="+jwt, "", 1),
		},
		{
			name: "deny: jwt issued for a different host",
			host: releaseGrantHost,
			query: strings.Replace(
				releaseGrantSASQuery(jwt, "intercept-wrong-aud-fixture"), jwt, releaseGrantJWTForHost(otherHost, 300), 1),
		},
		{
			name:  "deny: SAS on a lookalike host",
			host:  releaseGrantHost + ".evil.example",
			query: releaseGrantSASQuery(jwt, "intercept-lookalike-fixture"),
		},
		{
			name:  "deny: SAS on a real Azure blob host",
			host:  "vendorstorage.blob.core.windows.net",
			query: releaseGrantSASQuery(jwt, "intercept-azureblob-fixture"),
		},
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
			now := int64(1100)
			if tc.now != 0 {
				now = tc.now
			}
			sc := releaseGrantScanner(t, cfg, time.Unix(now, 0))

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"https://"+tc.host+":"+port+"/asset/1?"+tc.query, nil)

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
				if resp.StatusCode != http.StatusForbidden || upstreamHits.Load() != 0 {
					t.Fatalf("SAS reached the upstream: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
				}
				return
			}
			if resp.StatusCode != http.StatusOK || upstreamHits.Load() != 1 {
				t.Fatalf("release download SAS blocked: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
			}
			assertMetricSampleValue(t, m,
				`pipelock_dlp_credential_audience_allows_total{pattern="Azure SAS Token",surface="url"}`, 1)
		})
	}
}

// The Azure SAS shape in a request BODY never carries the url_query surface,
// so it blocks even at the exact release host with a shape-valid grant
// riding in the URL beside it.
func TestInterceptTunnel_GitHubReleaseGrantSAS_RequestBodyStaysBlocked(t *testing.T) {
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
	cfg.RequestBodyScanning.Action = config.ActionBlock
	sc := releaseGrantScanner(t, cfg, time.Unix(1100, 0))

	jwt := releaseGrantJWTForHost(releaseGrantHost, 3600)
	query := releaseGrantSASQuery(jwt, "body-sas-fixture")
	body := `{"redirect":"https://` + releaseGrantHost + `/asset/1?` + query + `"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+releaseGrantHost+":"+port+"/asset/1?"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

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
		TargetHost: releaseGrantHost,
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

	if resp.StatusCode != http.StatusForbidden || upstreamHits.Load() != 0 {
		t.Fatalf("SAS in a request body reached the upstream: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
	}
}

// Fetch and redirect-follow with the real Azure SAS shape beside the JWT.
// GitHub's actual redirect carries both, so the fix must admit both together,
// not merely the JWT alone.
func TestFetchEndpoint_GitHubReleaseGrantRedirect_WithSAS(t *testing.T) {
	jwt := releaseGrantJWT()
	for _, tc := range []struct {
		now          int64
		name         string
		redirectHost string
		query        func() string
		wantOK       bool
	}{
		{name: "expired grant validity window", redirectHost: releaseGrantHost, query: func() string { return releaseGrantSASQuery(jwt, "expired-window") }, now: releaseGrantExpiredNow},
		{name: "future grant validity window", redirectHost: releaseGrantHost, query: func() string { return releaseGrantSASQuery(jwt, "future-window") }, now: releaseGrantFutureNow},
		{name: "expired SAS validity window", redirectHost: releaseGrantHost, query: func() string {
			return strings.Replace(releaseGrantSASQuery(jwt, "sas-expiry-window"), "se=2026-09-30T00%3A37%3A09Z", "se=1970-01-01T00%3A00%3A00Z", 1)
		}},
		{
			name:         "release storage host, real SAS shape",
			redirectHost: releaseGrantHost,
			query:        func() string { return releaseGrantSASQuery(jwt, "fetch-allow-fixture") },
			wantOK:       true,
		},
		{
			name:         "release storage host, one hour grant with SAS",
			redirectHost: releaseGrantHost,
			query: func() string {
				return releaseGrantSASQuery(releaseGrantJWTForHost(releaseGrantHost, 3600), "fetch-hour-fixture")
			},
			wantOK: true,
		},
		{
			name:         "release storage host, grant one second past cap with SAS",
			redirectHost: releaseGrantHost,
			query: func() string {
				return releaseGrantSASQuery(releaseGrantJWTForHost(releaseGrantHost, 3601), "fetch-over-cap-fixture")
			},
		},
		{
			name:         "other host, real SAS shape",
			redirectHost: "download.vendor.example",
			query:        func() string { return releaseGrantSASQuery(jwt, "fetch-other-host-fixture") },
		},
		{
			name:         "release storage host, SAS without a jwt",
			redirectHost: releaseGrantHost,
			query: func() string {
				return strings.Replace(releaseGrantSASQuery(jwt, "fetch-no-jwt-fixture"), "&jwt="+jwt, "", 1)
			},
		},
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
				http.Redirect(w, r, "https://"+tc.redirectHost+"/asset/1?"+tc.query(), http.StatusFound)
			}))
			defer origin.Close()

			cfg := config.Defaults()
			cfg.FetchProxy.TimeoutSeconds = 5
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.APIAllowlist = nil
			now := int64(1100)
			if tc.now != 0 {
				now = tc.now
			}
			sc := releaseGrantScanner(t, cfg, time.Unix(now, 0))
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
					t.Fatalf("release redirect with real SAS shape not followed: status=%d hits=%d body=%s", w.Code, storageHits.Load(), w.Body.String())
				}
				return
			}
			if w.Code != http.StatusForbidden || storageHits.Load() != 0 {
				t.Fatalf("SAS admitted without a valid grant: status=%d hits=%d body=%s", w.Code, storageHits.Load(), w.Body.String())
			}
		})
	}
}

func releaseGrantScanner(t *testing.T, cfg *config.Config, now time.Time) *scanner.Scanner {
	t.Helper()
	sc, err := scanner.NewWithOptions(cfg, scanner.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	return sc
}
