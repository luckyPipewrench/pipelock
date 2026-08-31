// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Daybreak Blue scan reproductions. A failing test means the finding's
// security property is violated at this revision.

func TestDaybreak_ForwardTrailerSecretIsBlockedOrDropped(t *testing.T) {
	var sawTrailer string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		sawTrailer = r.Trailer.Get("X-Pipelock-Test")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	bodySecret, err := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/body", strings.NewReader(`{"k":"`+fakeAPIKey()+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	bodySecret.Header.Set("Content-Type", "application/json")
	bodyResp, err := client.Do(bodySecret)
	if err != nil {
		t.Fatalf("body secret request: %v", err)
	}
	_, _ = io.Copy(io.Discard, bodyResp.Body)
	_ = bodyResp.Body.Close()
	if bodyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("control: body secret status = %d, want 403", bodyResp.StatusCode)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/trailer", strings.NewReader("ok"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Trailer", "X-Pipelock-Test")
	req.Trailer = http.Header{"X-Pipelock-Test": {fakeAPIKey()}}
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("trailer secret request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("trailer secret status = %d, want 403; upstream trailer=%q", resp.StatusCode, sawTrailer)
	}
}

func TestDaybreak_TrailerSecretFailsClosedAcrossHTTPPaths(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "forward", run: testDaybreakForwardTrailerBlock},
		{name: "tls intercept", run: testDaybreakInterceptTrailerBlock},
		{name: "reverse", run: testDaybreakReverseTrailerBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func newDaybreakTrailerRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader("ok"))
	if err != nil {
		t.Fatalf("new trailer request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Trailer", "X-Pipelock-Test")
	req.Trailer = http.Header{"X-Pipelock-Test": {fakeAPIKey()}}
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	return req
}

func testDaybreakForwardTrailerBlock(t *testing.T) {
	t.Helper()
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
	})
	defer cleanup()
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: proxyAddr}, nil
	}}}

	resp, err := client.Do(newDaybreakTrailerRequest(t, upstream.URL+"/trailer"))
	if err != nil {
		t.Fatalf("forward trailer request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
}

func testDaybreakInterceptTrailerBlock(t *testing.T) {
	t.Helper()
	cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	var upstreamHits atomic.Int32
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		upstreamHits.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{headerContentType: {"text/plain"}},
			Body:       io.NopCloser(strings.NewReader("unexpected")),
		}, nil
	})

	resp := interceptWithRT(t, cache, pool, cfg, sc, logger, m, rt,
		&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443"},
		newDaybreakTrailerRequest(t, "https://api.vendor.example/trailer"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("upstream RoundTrip calls = %d, want 0", got)
	}
}

func testDaybreakReverseTrailerBlock(t *testing.T) {
	t.Helper()
	var upstreamHits atomic.Int32
	proxy := reverseTestSetup(t, reverseTestConfig(), func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.WriteHeader(http.StatusOK)
	})

	resp, err := http.DefaultClient.Do(newDaybreakTrailerRequest(t, proxy.URL+"/trailer"))
	if err != nil {
		t.Fatalf("reverse trailer request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
}

func TestDaybreak_AbsoluteFormHostOverride(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	_, p, cleanup := setupForwardProxyWithInstance(t, nil)
	defer cleanup()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/path", nil)
	req.Host = "other.vendor.example"
	req.Header.Set("Host", "other.vendor.example")
	rec := httptest.NewRecorder()
	p.handleForwardHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotHost != req.URL.Host {
		t.Errorf("upstream Host = %q, want scanned URL authority %q", gotHost, req.URL.Host)
	}
}

func TestDaybreak_RedirectReusesSuppressedBodyDLP(t *testing.T) {
	secretBody := `{"input":"` + fakeAnthropicKey() + `"}`
	var secondBody string
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		secondBody = string(b)
		_, _ = w.Write([]byte("final"))
	}))
	defer second.Close()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", second.URL+"/finish")
		w.WriteHeader(http.StatusPermanentRedirect)
	}))
	defer first.Close()

	firstURL, err := url.Parse(first.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		cfg.Suppress = []config.SuppressEntry{{
			Rule:   "Anthropic API Key",
			Path:   "*" + firstURL.Hostname() + "*",
			Reason: "daybreak redirect reproduction",
		}}
	})
	defer cleanup()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, first.URL+"/start", strings.NewReader(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(secretBody)), nil
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("redirected post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("redirect status = %d, want 403", resp.StatusCode)
	}
	if secondBody != "" {
		t.Errorf("308 replay reached %s with body %q", second.URL, secondBody)
	}
}

func TestDaybreak_TrailerSecretFailsClosedInWarnMode(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.Mode = config.ModeAudit
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
	})
	defer cleanup()
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: proxyAddr}, nil
	}}}

	resp, err := client.Do(newDaybreakTrailerRequest(t, upstream.URL+"/trailer"))
	if err != nil {
		t.Fatalf("warn-mode trailer request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("audit/warn trailer status = %d, want 403", resp.StatusCode)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
}

func TestDaybreak_SameHost308StillFollowed(t *testing.T) {
	var hits atomic.Int32
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/finish")
		w.WriteHeader(http.StatusPermanentRedirect)
	})
	mux.HandleFunc("/finish", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		_, _ = w.Write([]byte("final"))
	})

	proxyAddr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
	})
	defer cleanup()
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: proxyAddr}, nil
	}}}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/start", strings.NewReader(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("same-host 308: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-host 308 status = %d, want 200", resp.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("finish hits = %d, want 1", hits.Load())
	}
}

func TestRedirectReplaysBodyToNewAuthorityGuards(t *testing.T) {
	t.Parallel()

	getBody := func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("{}")), nil
	}
	req := &http.Request{
		URL:     &url.URL{Host: "second.vendor.example"},
		GetBody: getBody,
	}

	if redirectReplaysBodyToNewAuthority(req, []*http.Request{nil}) {
		t.Fatal("nil previous hop should not count as an authority change")
	}
	if redirectReplaysBodyToNewAuthority(req, []*http.Request{{GetBody: getBody}}) {
		t.Fatal("previous hop without a URL should not count as an authority change")
	}
	previous := &http.Request{URL: &url.URL{Host: "first.vendor.example"}}
	if !redirectReplaysBodyToNewAuthority(req, []*http.Request{previous}) {
		t.Fatal("307/308 replay to a different host should count as an authority change")
	}
}
