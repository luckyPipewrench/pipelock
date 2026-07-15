// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func applyProviderSecretRedactionTestProfile(cfg *config.Config) {
	cfg.Redaction = redact.Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]redact.ProfileSpec{
			"code": {Classes: []string{
				string(redact.ClassEnvSecret),
				string(redact.ClassTelegramToken),
				string(redact.ClassSeedPhrase),
			}},
		},
		Limits: redact.DefaultLimits(),
	}
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     "Telegram Bot Token",
		Regex:    `[0-9]{8,10}:[A-Za-z0-9_-]{35}`,
		Severity: config.SeverityCritical,
	})
}

func writeKnownSecretFile(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known-secrets.txt")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write known secret file: %v", err)
	}
	return path
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
		enforceFalse := false
		cfg.Enforce = &enforceFalse
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
	enforceFalse := false
	cfg.Enforce = &enforceFalse
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
	enforceFalse := false
	cfg.Enforce = &enforceFalse
	applyRedactionTestProfile(cfg)
	sc := scanner.MustNew(cfg)
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

func TestInterceptTunnel_Redaction_ProviderCriticalDLPForwardsSanitizedWithEnforce(t *testing.T) {
	var receivedBody atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	enforceTrue := true
	cfg.Enforce = &enforceTrue
	applyRedactionTestProfile(cfg)
	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, host)
	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })
	proxy := testInterceptRedactProxy(t, cfg)

	secret := redactionE2ESecret()
	bodyJSON := `{"messages":[{"role":"user","content":"use ` + secret + ` to deploy"}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+upstream.Listener.Addr().String()+"/v1/chat/completions", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("intercept status = %d, want upstream 401 for sanitized provider body", resp.StatusCode)
	}
	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, secret) {
		t.Fatalf("provider request leaked AWS key to upstream: %q", got)
	}
	if !strings.Contains(got, placeholderAWS) {
		t.Fatalf("provider request was not redacted before forward: %q", got)
	}
}

func TestInterceptTunnel_Redaction_NonProviderCriticalDLPStillBlocksWithEnforce(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	enforceTrue := true
	cfg.Enforce = &enforceTrue
	applyRedactionTestProfile(cfg)
	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })
	proxy := testInterceptRedactProxy(t, cfg)

	bodyJSON := `{"prompt":"use ` + redactionE2ESecret() + ` to deploy"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+upstream.Listener.Addr().String()+"/api", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("intercept status = %d, want 403 for non-provider critical DLP", resp.StatusCode)
	}
	if upstreamHit.Load() {
		t.Fatal("non-provider critical DLP reached upstream")
	}
}

func TestInterceptTunnel_Redaction_ProviderEnvTokenForwardsSanitizedWithEnforce(t *testing.T) {
	var receivedBody atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	enforceTrue := true
	cfg.Enforce = &enforceTrue
	applyProviderSecretRedactionTestProfile(cfg)
	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, host)
	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })
	proxy := testInterceptRedactProxy(t, cfg)

	token := "1234567890:" + strings.Repeat("F", 35)
	assignment := "TELEGRAM_BOT_TOKEN=" + token
	bodyJSON := `{"messages":[{"role":"user","content":"runtime env ` + assignment + `"}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+upstream.Listener.Addr().String()+"/backend-api/codex/responses", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("intercept status = %d, want upstream 401 for sanitized provider body", resp.StatusCode)
	}
	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, token) || strings.Contains(got, assignment) {
		t.Fatalf("provider request leaked env token to upstream: %q", got)
	}
	if !strings.Contains(got, "<pl:env-secret:1>") {
		t.Fatalf("provider request did not redact env assignment before forward: %q", got)
	}
}

func TestInterceptTunnel_Redaction_ProviderSeedPhraseForwardsSanitizedWithEnforce(t *testing.T) {
	var receivedBody atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	enforceTrue := true
	cfg.Enforce = &enforceTrue
	applyProviderSecretRedactionTestProfile(cfg)
	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, host)
	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })
	proxy := testInterceptRedactProxy(t, cfg)

	seed := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	bodyJSON := `{"messages":[{"role":"user","content":"wallet words ` + seed + `"}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+upstream.Listener.Addr().String()+"/backend-api/codex/responses", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("intercept status = %d, want upstream 401 for sanitized provider body", resp.StatusCode)
	}
	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, seed) {
		t.Fatalf("provider request leaked seed phrase to upstream: %q", got)
	}
	if !strings.Contains(got, "<pl:seed-phrase:1>") {
		t.Fatalf("provider request did not redact seed phrase before forward: %q", got)
	}
}

func TestInterceptTunnel_Redaction_ProviderKnownFileSecretForwardsSanitizedWithEnforce(t *testing.T) {
	tests := []struct {
		name        string
		bodySecret  func(string) string
		leakChecker func(string, string) bool
	}{
		{
			name:       "raw",
			bodySecret: func(secret string) string { return secret },
			leakChecker: func(body, secret string) bool {
				return strings.Contains(body, secret)
			},
		},
		{
			name: "base64",
			bodySecret: func(secret string) string {
				return base64.StdEncoding.EncodeToString([]byte(secret))
			},
			leakChecker: func(body, secret string) bool {
				return strings.Contains(body, secret) ||
					strings.Contains(body, base64.StdEncoding.EncodeToString([]byte(secret)))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedBody atomic.Value
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				receivedBody.Store(string(body))
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer upstream.Close()

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.Action = config.ActionWarn
			cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
			cfg.DLP.ScanEnv = false
			enforceTrue := true
			cfg.Enforce = &enforceTrue
			applyProviderSecretRedactionTestProfile(cfg)
			host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
			if err != nil {
				t.Fatalf("split upstream addr: %v", err)
			}
			cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, host)
			secret := "KnownProviderSecretValue12345!"
			cfg.DLP.SecretsFile = writeKnownSecretFile(t, secret)
			sc := scanner.MustNew(cfg)
			t.Cleanup(func() { sc.Close() })
			proxy := testInterceptRedactProxyWithScanner(t, cfg, sc)

			bodyJSON := `{"messages":[{"role":"user","content":"runtime context ` + tt.bodySecret(secret) + `"}]}`
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				"https://"+upstream.Listener.Addr().String()+"/backend-api/codex/responses", strings.NewReader(bodyJSON))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", contentTypeJSON)

			resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("intercept status = %d, want upstream 401 for sanitized provider body", resp.StatusCode)
			}
			got, _ := receivedBody.Load().(string)
			if tt.leakChecker(got, secret) {
				t.Fatalf("provider request leaked known file secret to upstream: %q", got)
			}
			if !strings.Contains(got, "<pl:known-secret:1>") {
				t.Fatalf("provider request did not redact known file secret before forward: %q", got)
			}
		})
	}
}
