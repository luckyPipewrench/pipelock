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
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
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

// unredactableAWSResourceID builds an AWS IAM resource-ID (AIDA prefix) at
// runtime. The detector flags it critical, but the ClassAWSAccessKey redact
// pattern (narrowed to AKIA/ASIA by #1308) cannot rewrite it, so it must fail
// closed on every request-body transport rather than leak. Split literal keeps
// gosec G101 quiet.
func unredactableAWSResourceID() string {
	return "AIDA" + "IOSFODNN7EXAMPLE"
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

// TestInterceptTunnel_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost
// is the issue #1308 regression: an AWS ID the detector flags as critical but the
// redactor cannot rewrite (an IAM resource-ID prefix) must hard-block even on a
// redact-and-forward exempt host, because the post-redaction re-scan still finds
// it. Contrast ...ProviderCriticalDLPForwardsSanitizedWithEnforce, where a real
// AKIA access key on the same exempt host redacts-and-forwards.
func TestInterceptTunnel_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost(t *testing.T) {
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
	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, host)
	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })
	proxy := testInterceptRedactProxy(t, cfg)

	// AIDA is an IAM resource-ID prefix: detected as a critical AWS Access ID but
	// absent from the redact class, so it survives redaction and must fail closed.
	unredactable := unredactableAWSResourceID()
	bodyJSON := `{"messages":[{"role":"user","content":"use ` + unredactable + ` to deploy"}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+upstream.Listener.Addr().String()+"/v1/chat/completions", strings.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("intercept status = %d, want 403 (unredactable AWS ID must fail closed even on an exempt host)", resp.StatusCode)
	}
	if upstreamHit.Load() {
		t.Fatal("unredactable AWS ID reached upstream despite surviving the post-redaction re-scan")
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

// TestForwardProxy_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost is
// the forward-proxy #1308 regression, made self-validating on one exempt host
// under enforce. Half one sends a real AKIA key and asserts it redacts-and-
// forwards (upstream sees the placeholder) to prove the exempt redact-and-
// forward path is live; half two sends an AIDA resource-ID the detector flags
// critical but the redactor cannot rewrite, which must hard-block 403 so the
// block cannot be mistaken for the exemption failing to match. The forward gate
// sees r.URL.Hostname() (127.0.0.1), so the loopback upstream host is exempt.
func TestForwardProxy_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost(t *testing.T) {
	var receivedBody atomic.Value // string
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		enforceTrue := true
		cfg.Enforce = &enforceTrue
		applyRedactionTestProfile(cfg)
		cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, host)
	})
	defer cleanup()

	client := proxyClient(proxyAddr)

	// Half 1: a real AKIA key redacts-and-forwards on the exempt host.
	secret := redactionE2ESecret()
	akiaReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		upstream.URL+"/api", strings.NewReader(`{"prompt":"use `+secret+` to deploy"}`))
	if err != nil {
		t.Fatalf("new AKIA request: %v", err)
	}
	akiaReq.Header.Set("Content-Type", contentTypeJSON)
	akiaResp, err := client.Do(akiaReq)
	if err != nil {
		t.Fatalf("forward AKIA request: %v", err)
	}
	_ = akiaResp.Body.Close()
	if akiaResp.StatusCode != http.StatusOK {
		t.Fatalf("AKIA status = %d, want 200 (redact-and-forward on exempt host)", akiaResp.StatusCode)
	}
	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, secret) {
		t.Fatalf("forward proxy leaked AWS key to upstream: %q", got)
	}
	if !strings.Contains(got, placeholderAWS) {
		t.Fatalf("forward proxy did not redact AKIA on exempt host; upstream saw %q", got)
	}
	hitsAfterAKIA := upstreamHits.Load()

	// Half 2: the unredactable AIDA resource-ID must fail closed even here.
	unredactable := unredactableAWSResourceID()
	aidaReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		upstream.URL+"/api", strings.NewReader(`{"prompt":"use `+unredactable+` to deploy"}`))
	if err != nil {
		t.Fatalf("new AIDA request: %v", err)
	}
	aidaReq.Header.Set("Content-Type", contentTypeJSON)
	aidaResp, err := client.Do(aidaReq)
	if err != nil {
		t.Fatalf("forward AIDA request: %v", err)
	}
	_ = aidaResp.Body.Close()
	if aidaResp.StatusCode != http.StatusForbidden {
		t.Fatalf("AIDA status = %d, want 403 (unredactable AWS ID must fail closed even on an exempt host)", aidaResp.StatusCode)
	}
	if upstreamHits.Load() != hitsAfterAKIA {
		t.Fatal("unredactable AWS ID reached upstream despite surviving the post-redaction re-scan")
	}
}

// TestReverseProxy_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost is
// the reverse-proxy #1308 regression, self-validating on one exempt host under
// enforce: an AKIA key redacts-and-forwards while the unredactable AIDA
// resource-ID hard-blocks 403. reverseTestSetup fronts an IPv4 loopback
// upstream, so the gate sees 127.0.0.1 as rp.upstream.Hostname().
func TestReverseProxy_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	enforceTrue := true
	cfg.Enforce = &enforceTrue
	applyRedactionTestProfile(cfg)
	cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, "127.0.0.1")

	var receivedBody atomic.Value // string
	var upstreamHits atomic.Int32
	upstream := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(string(body))
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}
	proxy := reverseTestSetup(t, cfg, upstream)

	// Half 1: AKIA redacts-and-forwards on the exempt host.
	secret := redactionE2ESecret()
	akiaResp := testPost(t, proxy.URL+"/api/send", contentTypeJSON, `{"prompt":"use `+secret+` to deploy"}`)
	_ = akiaResp.Body.Close()
	if akiaResp.StatusCode != http.StatusOK {
		t.Fatalf("AKIA status = %d, want 200 (redact-and-forward on exempt host)", akiaResp.StatusCode)
	}
	got, _ := receivedBody.Load().(string)
	if strings.Contains(got, secret) {
		t.Fatalf("reverse proxy leaked AWS key to upstream: %q", got)
	}
	if !strings.Contains(got, placeholderAWS) {
		t.Fatalf("reverse proxy did not redact AKIA on exempt host; upstream saw %q", got)
	}
	hitsAfterAKIA := upstreamHits.Load()

	// Half 2: the unredactable AIDA resource-ID must fail closed.
	unredactable := unredactableAWSResourceID()
	aidaResp := testPost(t, proxy.URL+"/api/send", contentTypeJSON, `{"prompt":"use `+unredactable+` to deploy"}`)
	_ = aidaResp.Body.Close()
	if aidaResp.StatusCode != http.StatusForbidden {
		t.Fatalf("AIDA status = %d, want 403 (unredactable AWS ID must fail closed even on an exempt host)", aidaResp.StatusCode)
	}
	if upstreamHits.Load() != hitsAfterAKIA {
		t.Fatal("unredactable AWS ID reached upstream despite surviving the post-redaction re-scan")
	}
}

// wsCountingEchoServer is wsEchoServer plus a counter of how many client
// messages actually reach the backend. The counter lets a test assert that a
// blocked frame produced no upstream delivery, not merely that the client
// connection closed.
func wsCountingEchoServer(t *testing.T) (addr string, delivered *atomic.Int32, cleanup func()) {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var count atomic.Int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
			if upgradeErr != nil {
				return
			}
			defer conn.Close() //nolint:errcheck // test
			for {
				msg, op, readErr := wsutil.ReadClientData(conn)
				if readErr != nil {
					return
				}
				count.Add(1)
				if writeErr := wsutil.WriteServerMessage(conn, op, msg); writeErr != nil {
					return
				}
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), &count, func() { _ = srv.Close() }
}

// TestWSProxy_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost is the
// WebSocket #1308 regression, self-validating on one exempt host under enforce.
// A block closes the connection, so the two halves use separate dials: the AKIA
// message redacts-and-forwards (the echoed reply carries the placeholder, and the
// backend records the delivery), while the unredactable AIDA message both closes
// the client connection AND reaches the backend zero times — the same
// no-upstream-leak invariant the forward/reverse tests assert via a hit counter.
func TestWSProxy_Redaction_UnredactableAWSResourceIDFailsClosedOnExemptHost(t *testing.T) {
	backendAddr, backendDeliveries, backendCleanup := wsCountingEchoServer(t)
	defer backendCleanup()

	proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
		enforceTrue := true
		cfg.Enforce = &enforceTrue
		applyRedactionTestProfile(cfg)
		cfg.ResponseScanning.ExemptDomains = append(cfg.ResponseScanning.ExemptDomains, "127.0.0.1", backendAddr)
	})
	defer proxyCleanup()

	// Half 1: AKIA redacts-and-forwards; the echo returns the placeholder, which
	// also confirms the (redacted) frame reached the backend.
	secret := redactionE2ESecret()
	akiaConn := dialWS(t, proxyAddr, backendAddr)
	defer akiaConn.Close() //nolint:errcheck // test
	if err := wsutil.WriteClientMessage(akiaConn, ws.OpText, []byte(`{"prompt":"use `+secret+` to deploy"}`)); err != nil {
		t.Fatalf("write AKIA: %v", err)
	}
	reply, _, err := wsutil.ReadServerData(akiaConn)
	if err != nil {
		t.Fatalf("read AKIA reply: %v (exempt host should redact-and-forward)", err)
	}
	replyStr := string(reply)
	if strings.Contains(replyStr, secret) {
		t.Fatalf("echoed reply leaked secret: %q", replyStr)
	}
	if !strings.Contains(replyStr, placeholderAWS) {
		t.Fatalf("echoed reply missing placeholder on exempt host: %q", replyStr)
	}
	deliveriesAfterAKIA := backendDeliveries.Load()

	// Half 2: the unredactable AIDA resource-ID must fail closed. A block closes
	// the connection, so this needs a fresh dial. The client-side close plus zero
	// additional backend deliveries together prove the frame was blocked before
	// reaching the upstream.
	unredactable := unredactableAWSResourceID()
	aidaConn := dialWS(t, proxyAddr, backendAddr)
	defer aidaConn.Close() //nolint:errcheck // test
	if err := wsutil.WriteClientMessage(aidaConn, ws.OpText, []byte(`{"prompt":"use `+unredactable+` to deploy"}`)); err != nil {
		t.Fatalf("write AIDA: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(aidaConn); err == nil {
		t.Fatal("expected proxy to close connection on unredactable AWS ID even on an exempt host")
	}
	if backendDeliveries.Load() != deliveriesAfterAKIA {
		t.Fatal("unredactable AWS ID reached the backend despite surviving the post-redaction re-scan")
	}
}
