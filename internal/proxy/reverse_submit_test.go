// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// upstreamURLFromHTTPTest parses a host:port out of an httptest.Server URL
// (e.g., "http://127.0.0.1:NNNN"). Used by the URL-scan isolation test
// when configuring a blocklist entry that matches only the upstream host.
func upstreamURLFromHTTPTest(httpURL string) string {
	u, err := url.Parse(httpURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// submitProfileTestConfig builds a config wired up for submit profile,
// targeting the upstream URL passed in. Skips Validate() because httptest
// URLs are IP literals (127.0.0.1) and submit profile rejects IP literals
// on trusted_upstream.host by design - tests still exercise request-time
// gating which doesn't care about the load-time hostname constraint.
func submitProfileTestConfig(upstreamURL string) (*config.Config, *url.URL) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}

	u, err := url.Parse(upstreamURL)
	if err != nil {
		panic("submitProfileTestConfig: parse upstream URL: " + err.Error())
	}

	cfg.ReverseProxy.Enabled = true
	cfg.ReverseProxy.Profile = config.ReverseProxyProfileSubmit
	cfg.ReverseProxy.Listen = "127.0.0.1:0" // tests use newIPv4Server
	cfg.ReverseProxy.Upstream = upstreamURL
	cfg.ReverseProxy.AllowedMethods = []string{http.MethodPost}
	cfg.ReverseProxy.AllowedPaths = []config.ReverseProxyPathRule{
		{Exact: "/v1/batch"},
	}
	cfg.ReverseProxy.MaxBodyBytes = 6 * 1024 * 1024
	cfg.ReverseProxy.RequestTimeoutSeconds = 30

	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	cfg.ReverseProxy.TrustedUpstream = config.ReverseProxyTrustedUpstream{
		Host:   host,
		Port:   port,
		Reason: "test upstream",
		Added:  "2026-05-26",
	}

	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.MaxBodyBytes = 6 * 1024 * 1024

	return cfg, u
}

// submitProfileReverseProxy spins up a NewReverseProxy fronting a test
// upstream, parameterized on cfg + upstream URL since submit-profile tests
// need to control both. Equivalent to the dialer variant with a nil dialer.
func submitProfileReverseProxy(t *testing.T, cfg *config.Config, upstreamURL *url.URL) *httptest.Server {
	t.Helper()
	return submitProfileReverseProxyWithDialer(t, cfg, upstreamURL, nil)
}

// submitProfileReverseProxyWithDialer builds the submit-profile reverse proxy
// test server and applies SetSafeDialer(dial). A nil dialer leaves the handler
// on its default transport (and exercises the no-op branch of SetSafeDialer),
// which is why the plain submitProfileReverseProxy delegates here.
func submitProfileReverseProxyWithDialer(t *testing.T, cfg *config.Config, upstreamURL *url.URL, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *httptest.Server {
	t.Helper()

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	m := metrics.New()
	ks := killswitch.New(cfg)

	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, m, ks, nil, nil)
	handler.SetSafeDialer(dial)
	proxy := newIPv4Server(t, handler)
	t.Cleanup(proxy.Close)
	return proxy
}

// TestSubmitProfile_BodyDLPBlocksBeforeForward is the gating CI test
// from the submit-mode design doc. A DLP-positive body sent to the
// configured allowed path must:
//
//  1. Return 403 to the caller
//  2. Carry X-Pipelock-Block-Reason: dlp_match
//  3. Never reach the upstream handler (asserted via t.Fatalf)
func TestSubmitProfile_BodyDLPBlocksBeforeForward(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		t.Errorf("upstream MUST NOT be invoked when body trips DLP; got %s %s", r.Method, r.URL.Path)
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	body := `{"k":"AKIA` + `IOSFODNN7EXAMPLE"}`
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		proxy.URL+"/v1/batch",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (DLP body match must block)", resp.StatusCode)
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.DLPMatch) {
		t.Errorf("block reason = %q, want %s", got, blockreason.DLPMatch)
	}
	if upstreamHit.Load() {
		t.Error("upstream was invoked despite body DLP block — fail-closed contract violated")
	}
}

// TestSubmitProfile_MethodNotAllowed verifies the per-listener method
// allowlist rejects requests with a non-allowed method before any
// scanning or upstream dial.
func TestSubmitProfile_MethodNotAllowed(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, proxy.URL+"/v1/batch", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405 (GET not in allowed_methods)", resp.StatusCode)
	}
	if upstreamHit.Load() {
		t.Error("upstream was invoked despite method allowlist denial")
	}
}

// TestSubmitProfile_PathRejection verifies that paths outside the
// allowed_paths exact-match list are rejected before any scanning.
func TestSubmitProfile_PathRejection(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantStatus     int
		wantBlockedRaw bool
	}{
		{"path-not-in-allowlist", "/v1/other", http.StatusNotFound, false},
		{"encoded-traversal", "/v1/%2e%2e/etc/passwd", http.StatusBadRequest, true},
		{"double-encoded-traversal", "/v1/%252e%252e/etc/passwd", http.StatusBadRequest, true},
		{"encoded-slash", "/v1%2fbatch", http.StatusBadRequest, true},
		{"encoded-backslash", "/v1%5cbatch", http.StatusBadRequest, true},
		{"semicolon-param", "/v1/batch;foo=bar", http.StatusBadRequest, true},
		{"encoded-semicolon", "/v1/batch%3bfoo=bar", http.StatusBadRequest, true},
		{"double-slash-canonicalizes", "//v1//batch", http.StatusBadRequest, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHit atomic.Bool
			upstream := newIPv4Server(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				upstreamHit.Store(true)
			}))
			defer upstream.Close()

			cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
			proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

			req, _ := http.NewRequestWithContext(context.Background(),
				http.MethodPost, proxy.URL+tc.path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d for path %q", resp.StatusCode, tc.wantStatus, tc.path)
			}
			if upstreamHit.Load() {
				t.Errorf("upstream invoked despite path rejection for %q", tc.path)
			}
		})
	}
}

// TestSubmitProfile_BodyTooLarge verifies oversized bodies are rejected
// with 413 BEFORE forwarding - body never reaches upstream.
func TestSubmitProfile_BodyTooLarge(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	cfg.ReverseProxy.MaxBodyBytes = 1024 // tiny cap for test
	cfg.RequestBodyScanning.MaxBodyBytes = 1024
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	oversized := strings.Repeat("a", 2048)
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, proxy.URL+"/v1/batch", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(oversized))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 (body cap exceeded)", resp.StatusCode)
	}
	if upstreamHit.Load() {
		t.Error("upstream invoked despite oversized body")
	}
}

func TestSubmitProfile_URLScanUsesScannerBlockReason(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
	}))
	defer upstream.Close()

	// Isolate the NEW upstream-URL scan path from the pre-existing
	// path+query DLP scan: use a blocklist trigger that only fires on
	// the full upstream URL (which includes the upstream's host), not
	// on the path-only r.URL.RequestURI() that the path-DLP scan sees.
	// Without this isolation, a credential in ?token=... would also fire
	// the path-DLP scan and the test could not tell which code path
	// produced the 403.
	upstreamHost, _, splitErr := net.SplitHostPort(upstreamURLFromHTTPTest(upstream.URL))
	if splitErr != nil {
		t.Fatalf("split upstream host: %v", splitErr)
	}
	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	cfg.FetchProxy.Monitoring.Blocklist = []string{upstreamHost}
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	reqURL := proxy.URL + "/v1/batch"
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, reqURL, strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	// The upstream URL scan denies on domain_blocklist; this proves the
	// submit-profile URL scan ran (the path-only DLP scan cannot trigger
	// blocklist denials because it operates on r.URL.RequestURI() which
	// has no host component).
	if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.DomainBlocklist) {
		t.Errorf("block reason = %q, want %s", got, blockreason.DomainBlocklist)
	}
	if upstreamHit.Load() {
		t.Error("upstream invoked despite upstream URL scan denial")
	}
}

// TestSubmitProfile_CleanRequestForwards verifies a request that satisfies
// every gate (allowed method, allowed path, body within cap, no DLP) DOES
// reach the upstream.
func TestSubmitProfile_CleanRequestForwards(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/batch" {
			t.Errorf("upstream got unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, proxy.URL+"/v1/batch", strings.NewReader(`{"clean":true}`))
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
		t.Error("upstream was NOT invoked for a clean request that should forward")
	}
}

func TestSubmitProfile_RequestTimeoutApplied(t *testing.T) {
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(1500 * time.Millisecond):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	cfg.ReverseProxy.RequestTimeoutSeconds = 1
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, proxy.URL+"/v1/batch", strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 from upstream timeout", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 1400*time.Millisecond {
		t.Errorf("request took %s, want timeout before upstream handler completes", elapsed)
	}
}

// TestSubmitProfile_GenericProfileUnaffected verifies the gate is a no-op
// when profile is empty (the default generic reverse proxy). A request
// that would be denied under submit profile (wrong path) goes through
// the existing generic pipeline unchanged.
func TestSubmitProfile_GenericProfileUnaffected(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	// Strip submit-profile selector - request path should now be allowed
	// to reach upstream because the generic profile has no allowlist.
	cfg.ReverseProxy.Profile = ""
	cfg.ReverseProxy.AllowedMethods = nil
	cfg.ReverseProxy.AllowedPaths = nil
	cfg.ReverseProxy.TrustedUpstream = config.ReverseProxyTrustedUpstream{}
	cfg.ReverseProxy.MaxBodyBytes = 0
	cfg.ReverseProxy.RequestTimeoutSeconds = 0
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodGet, proxy.URL+"/anything", nil) // GET would be denied under submit
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if !upstreamHit.Load() {
		t.Errorf("generic profile should not gate; upstream was not reached (status %d)", resp.StatusCode)
	}
}

func TestSubmitProfileRawPathRejection(t *testing.T) {
	tests := []struct {
		path     string
		wantBad  bool
		wantWhat string
	}{
		{"/v1/batch", false, ""},
		{"/v1/%2e%2e/etc", true, "encoded dot"},
		{"/v1/%2E", true, "encoded dot"},
		{"/v1/%252e%252e/etc", true, "encoded percent"},
		{"/v1%2fbatch", true, "encoded slash"},
		{"/v1%2Fbatch", true, "encoded slash"},
		{"/v1%5cbatch", true, "encoded backslash"},
		{"/v1/batch;foo=bar", true, "semicolon"},
		{"/v1/batch%3bfoo=bar", true, "encoded semicolon"},
		{"/v1/batch%3Bfoo=bar", true, "encoded semicolon"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			reason, ok := submitProfileRawPathRejection(tc.path)
			if tc.wantBad && ok {
				t.Errorf("expected %q rejected, got ok", tc.path)
			}
			if !tc.wantBad && !ok {
				t.Errorf("expected %q allowed, got rejected: %s", tc.path, reason)
			}
			if tc.wantBad && !strings.Contains(reason, tc.wantWhat) {
				t.Errorf("reason %q does not mention %q", reason, tc.wantWhat)
			}
		})
	}
}

func TestEffectiveSubmitBodyCap(t *testing.T) {
	tests := []struct {
		name        string
		listenerCap int64
		scannerCap  int
		want        int64
	}{
		{"listener-smaller-wins", 1024, 4096, 1024},
		{"scanner-smaller-wins", 4096, 1024, 1024},
		{"only-listener-set", 1024, 0, 1024},
		{"only-scanner-set", 0, 1024, 1024},
		{"neither-set-returns-zero", 0, 0, 0},
		{"equal-caps", 1024, 1024, 1024},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.ReverseProxy.MaxBodyBytes = tc.listenerCap
			cfg.RequestBodyScanning.MaxBodyBytes = tc.scannerCap
			got := effectiveSubmitBodyCap(cfg)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}
