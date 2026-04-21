// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// placeholderAWS is the expected upstream-facing placeholder for an AWS
// access-key match in redaction profile "code". Sequence is per-request
// so the first match always gets `<pl:aws-access-key:1>`.
const placeholderAWS = "<pl:aws-access-key:1>"

// redactionE2ESecret builds the test AWS access key at runtime to avoid
// triggering DLP on the test source itself.
func redactionE2ESecret() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

// applyRedactionTestProfile enables a minimal redaction config matching
// only ClassAWSAccessKey so the three transport tests converge on the
// same expected placeholder.
func applyRedactionTestProfile(cfg *config.Config) {
	cfg.Redaction = redact.Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]redact.ProfileSpec{
			"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
		},
		Limits: redact.DefaultLimits(),
	}
}

// TestForwardProxy_Redaction_RewritesJSONBody proves the forward-proxy
// call site actually rewrites secrets before the body reaches the
// upstream. Fills the transport-coverage gap flagged by CodeRabbit
// round 2 on #416.
func TestForwardProxy_Redaction_RewritesJSONBody(t *testing.T) {
	var receivedBody atomic.Value // string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		applyRedactionTestProfile(cfg)
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	secret := redactionE2ESecret()
	bodyJSON := `{"prompt":"use ` + secret + ` to deploy"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		upstream.URL+"/api", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward request: %v", err)
	}
	_ = resp.Body.Close()

	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, secret) {
		t.Fatalf("forward proxy leaked AWS key to upstream: %q", got)
	}
	if !strings.Contains(got, placeholderAWS) {
		t.Fatalf("forward proxy did not redact; upstream saw %q", got)
	}
}

// TestForwardProxy_Redaction_FailClosedNonJSONBlocksForward covers the
// transport-level fail-closed path for the forward proxy: redaction is
// enabled, request-body action is warn (non-blocking), but the body is
// not JSON and the target host is not on allowlist_unparseable. The
// proxy must refuse to forward regardless of enforce-mode because
// redaction integrity failures are mode-independent.
func TestForwardProxy_Redaction_FailClosedNonJSONBlocksForward(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		enforceOff := false
		cfg.Enforce = &enforceOff
		applyRedactionTestProfile(cfg)
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		upstream.URL+"/api", strings.NewReader("opaque binary payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward request: %v", err)
	}
	_ = resp.Body.Close()

	if upstreamHit.Load() {
		t.Fatal("forward proxy forwarded a non-JSON body with redaction enabled and no allowlist entry")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 block response, got %d", resp.StatusCode)
	}
}

// TestReverseProxy_Redaction_RewritesJSONBody proves the reverse-proxy
// call site wires the matcher correctly and redacts JSON bodies end to
// end. Complements the existing non-JSON fail-closed test.
func TestReverseProxy_Redaction_RewritesJSONBody(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	applyRedactionTestProfile(cfg)

	var receivedBody atomic.Value
	upstream := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		w.WriteHeader(http.StatusOK)
	}

	proxy := reverseTestSetup(t, cfg, upstream)
	secret := redactionE2ESecret()
	bodyJSON := `{"prompt":"use ` + secret + ` to deploy"}`
	resp := testPost(t, proxy.URL+"/api/send", contentTypeJSON, bodyJSON)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reverse proxy status = %d, want 200", resp.StatusCode)
	}
	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, secret) {
		t.Fatalf("reverse proxy leaked AWS key to upstream: %q", got)
	}
	if !strings.Contains(got, placeholderAWS) {
		t.Fatalf("reverse proxy did not redact; upstream saw %q", got)
	}
}

// TestInterceptTunnel_Redaction_RewritesJSONBody drives the CONNECT +
// TLS-interception path with a JSON request body carrying a secret and
// asserts the upstream handler sees the placeholder, not the raw key.
func TestInterceptTunnel_Redaction_RewritesJSONBody(t *testing.T) {
	var receivedBody atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	applyRedactionTestProfile(cfg)
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	proxy := testInterceptRedactProxy(t, cfg)

	addr := upstream.Listener.Addr().String()
	secret := redactionE2ESecret()
	bodyJSON := `{"prompt":"use ` + secret + ` to deploy"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+addr+"/api", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("intercept status = %d, want 200", resp.StatusCode)
	}
	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, secret) {
		t.Fatalf("intercept leaked AWS key to upstream: %q", got)
	}
	if !strings.Contains(got, placeholderAWS) {
		t.Fatalf("intercept did not redact; upstream saw %q", got)
	}
}
