// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIssuerBoundCookieStoreFailClosed(t *testing.T) {
	const value = "session-value-1234567890abcd"
	issuedAt := time.Date(2026, time.September, 22, 12, 0, 0, 0, time.UTC)
	issuer, _ := url.Parse("https://app.vendor.example:443/login")
	sameOrigin, _ := url.Parse("https://app.vendor.example:443/account")
	otherHost, _ := url.Parse("https://other.vendor.example:443/account")
	cleartext, _ := url.Parse("http://app.vendor.example:443/account")
	header := http.Header{"Set-Cookie": {"sid=" + value + "; Path=/; Secure; Max-Age=60"}}

	tests := []struct {
		name       string
		origin     *url.URL
		target     *url.URL
		session    string
		seenBefore bool
		delivered  bool
		at         time.Time
		want       bool
	}{
		{name: "same issuer", origin: issuer, target: sameOrigin, session: "agent-one", delivered: true, at: issuedAt.Add(time.Second), want: true},
		{name: "cross host replay", origin: issuer, target: otherHost, session: "agent-one", delivered: true, at: issuedAt.Add(time.Second)},
		{name: "cleartext replay", origin: issuer, target: cleartext, session: "agent-one", delivered: true, at: issuedAt.Add(time.Second)},
		{name: "expired", origin: issuer, target: sameOrigin, session: "agent-one", delivered: true, at: issuedAt.Add(61 * time.Second)},
		{name: "other agent", origin: issuer, target: sameOrigin, session: "agent-two", delivered: true, at: issuedAt.Add(time.Second)},
		{name: "blocked response", origin: issuer, target: sameOrigin, session: "agent-one", at: issuedAt.Add(time.Second)},
		{name: "reflected outbound value", origin: issuer, target: sameOrigin, session: "agent-one", seenBefore: true, delivered: true, at: issuedAt.Add(time.Second)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newIssuerBoundCookieStore()
			store.observeOutbound("agent-one", []byte("GET https://app.vendor.example:443/login"))
			if tc.seenBefore {
				store.observeOutbound("agent-one", []byte("POST https://other.vendor.example/submit\nX-Data: "+value))
			}
			store.observeResponse("agent-one", tc.origin, header, tc.delivered, issuedAt)
			if got := store.allows(tc.session, tc.target, "sid", value, tc.at); got != tc.want {
				t.Fatalf("allows = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestIssuerBoundCookieScopeAndCapacity(t *testing.T) {
	const value = "session-value-1234567890abcd"
	now := time.Date(2026, time.September, 22, 12, 0, 0, 0, time.UTC)
	issuer, _ := url.Parse("https://app.vendor.example:443/login/start")
	allowed, _ := url.Parse("https://app.vendor.example:443/account/settings")
	widerPath, _ := url.Parse("https://app.vendor.example:443/accounts")
	otherPort, _ := url.Parse("https://app.vendor.example:8443/account/settings")
	store := newIssuerBoundCookieStore()
	store.observeOutbound("agent-one", []byte("GET /login/start"))
	store.observeResponse("agent-one", issuer, http.Header{"Set-Cookie": {
		"sid=" + value + "; Domain=vendor.example; Path=/account; Secure; Max-Age=60",
	}}, true, now)
	if !store.allows("agent-one", allowed, "sid", value, now.Add(time.Second)) {
		t.Fatal("valid domain attribute must retain exact issuer host and matching path")
	}
	for _, target := range []*url.URL{widerPath, otherPort} {
		if store.allows("agent-one", target, "sid", value, now.Add(time.Second)) {
			t.Fatalf("out-of-scope target allowed: %s", target)
		}
	}
	for _, domain := range []string{"com", "other.vendor.example"} {
		fresh := newIssuerBoundCookieStore()
		fresh.observeOutbound("agent-one", []byte("GET /login/start"))
		fresh.observeResponse("agent-one", issuer, http.Header{"Set-Cookie": {
			"sid=" + value + "; Domain=" + domain + "; Path=/account; Secure; Max-Age=60",
		}}, true, now)
		if fresh.allows("agent-one", allowed, "sid", value, now.Add(time.Second)) {
			t.Fatalf("illegal domain %q issued an allowance", domain)
		}
	}
	full := newIssuerBoundCookieStore()
	full.observeOutbound("agent-one", []byte("GET /login/start"))
	full.observeOutbound("agent-one", []byte(strings.Repeat("x", issuerCookieMaxRequestBytes+1)))
	full.observeResponse("agent-one", issuer, http.Header{"Set-Cookie": {
		"sid=" + value + "; Path=/; Secure; Max-Age=60",
	}}, true, now)
	if full.allows("agent-one", allowed, "sid", value, now.Add(time.Second)) {
		t.Fatal("unobserved outbound bytes must disable allowances")
	}
}

func TestIssuerBoundCookieGlobalCapacityKeepsHistoryClosed(t *testing.T) {
	const value = "session-value-1234567890abcd"
	now := time.Now()
	issuer, _ := url.Parse("https://app.vendor.example/login")
	store := newIssuerBoundCookieStore()
	store.observeOutbound("original", []byte("POST https://other.vendor.example/submit "+value))
	for i := range issuerCookieMaxSessions {
		store.observeOutbound("session-"+string(rune('a'+i)), []byte("GET /login"))
	}
	store.observeResponse("original", issuer, http.Header{"Set-Cookie": {
		"sid=" + value + "; Path=/; Secure; Max-Age=60",
	}}, true, now)
	if store.allows("original", issuer, "sid", value, now.Add(time.Second)) {
		t.Fatal("global capacity erased outbound history and allowed reflection")
	}
	if !store.disabled {
		t.Fatal("global capacity must disable issuer evidence until reload")
	}
}

func TestIssuerBoundCookieReloadDropsEvidence(t *testing.T) {
	const value = "session-value-1234567890abcd"
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.RequestBodyScanning.IssuerBoundSessionCookies = true
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	now := time.Now()
	url, _ := url.Parse("https://app.vendor.example/account")
	old := p.issuerCookieRuntime.Load()
	old.store.observeOutbound("agent-one", []byte("GET /login"))
	old.store.observeResponse("agent-one", url, http.Header{"Set-Cookie": {
		"sid=" + value + "; Path=/; Secure; Max-Age=60",
	}}, true, now)
	if !old.store.allows("agent-one", url, "sid", value, now.Add(time.Second)) {
		t.Fatal("initial issuance absent")
	}
	newCfg := cfg.Clone()
	newSc := scanner.MustNew(newCfg)
	if !p.Reload(newCfg, newSc) {
		t.Fatal("reload rejected")
	}
	current := p.issuerCookieRuntime.Load()
	if current == old || current.store.allows("agent-one", url, "sid", value, now.Add(time.Second)) {
		t.Fatal("reload retained issuer evidence")
	}
}

func TestIssuerBoundCookieReverseRequestInvalidatesEvidence(t *testing.T) {
	const value = "session-value-1234567890abcd"
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.RequestBodyScanning.IssuerBoundSessionCookies = true
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	now := time.Now()
	issuer, _ := url.Parse("https://app.vendor.example/account")
	key := sessionKeyFor("agent-one", "192.0.2.10", envelope.ActorAuthBound)
	store := p.issuerCookieRuntime.Load().store
	store.observeOutbound(key, []byte("GET /login"))
	store.observeResponse(key, issuer, http.Header{"Set-Cookie": {
		"sid=" + value + "; Path=/; Secure; Max-Age=60",
	}}, true, now)
	if !store.allows(key, issuer, "sid", value, now.Add(time.Second)) {
		t.Fatal("initial issuance absent")
	}
	_, reverse := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	reverse.SetOwnerProxy(p)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://app.vendor.example/", nil)
	req.RemoteAddr = "192.0.2.10:54321"
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAgent, "agent-one"))
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAgentAuth, string(envelope.ActorAuthBound)))
	reverse.ServeHTTP(httptest.NewRecorder(), req)
	if store.allows(key, issuer, "sid", value, now.Add(time.Second)) {
		t.Fatal("reverse request retained issuer evidence")
	}
}

func TestInterceptIssuerBoundCookieDelivery(t *testing.T) {
	const value = "session-value-1234567890abcd"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Set("Set-Cookie", "sid="+value+"; Path=/; Secure; Max-Age=60")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	cache, pool, cfg, _, _, metrics := testInterceptSetup(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	cfg.RequestBodyScanning.IssuerBoundSessionCookies = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: "Session Token", Regex: `session-value-[a-z0-9]+`, Severity: config.SeverityHigh,
	})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	request := func(path, header, value string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			req.Header.Set(header, value)
		}
		return interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
			Logger: logger, Metrics: metrics, Request: req, Proxy: p,
			Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
		})
	}
	unknown := request("/account", "Cookie", "sid=session-value-0000000000000000")
	defer unknown.Body.Close() //nolint:errcheck // test response
	if unknown.StatusCode != http.StatusForbidden {
		t.Fatalf("unissued cookie status = %d, want 403", unknown.StatusCode)
	}
	issued := request("/login", "", "")
	defer issued.Body.Close() //nolint:errcheck // test response
	if issued.StatusCode != http.StatusOK {
		t.Fatalf("issuing response status = %d", issued.StatusCode)
	}
	if _, err := io.Copy(io.Discard, issued.Body); err != nil {
		t.Fatal(err)
	}
	returned := request("/account", "Cookie", "sid="+value)
	defer returned.Body.Close() //nolint:errcheck // test response
	if returned.StatusCode != http.StatusOK {
		t.Fatalf("issuer-bound cookie status = %d, want 200", returned.StatusCode)
	}
	bearer := request("/account", "Authorization", "Bearer "+value)
	defer bearer.Body.Close() //nolint:errcheck // test response
	if bearer.StatusCode != http.StatusForbidden {
		t.Fatalf("bearer status = %d, want 403", bearer.StatusCode)
	}
	mixed := request("/account", "Cookie", "sid="+value+"; other=session-value-0000000000000000")
	defer mixed.Body.Close() //nolint:errcheck // test response
	if mixed.StatusCode != http.StatusForbidden {
		t.Fatalf("mixed cookie status = %d, want 403", mixed.StatusCode)
	}
	multiple := request("/account", "Cookie", "sid="+value+"; theme=light")
	defer multiple.Body.Close() //nolint:errcheck // test response
	if multiple.StatusCode != http.StatusForbidden {
		t.Fatalf("multi-cookie status = %d, want 403", multiple.StatusCode)
	}
	named := request("/account", "Cookie", "session-value-0000000000000000=x; sid="+value)
	defer named.Body.Close() //nolint:errcheck // test response
	if named.StatusCode != http.StatusForbidden {
		t.Fatalf("secret in cookie name status = %d, want 403", named.StatusCode)
	}
	auditBytes, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(auditBytes, []byte(`"event":"dlp_issuer_cookie_allow"`)) || bytes.Contains(auditBytes, []byte(value)) {
		t.Fatal("issuer allowance audit must name the event without exposing the cookie")
	}
	wsReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/account", nil)
	if err != nil {
		t.Fatal(err)
	}
	wsReq.Header.Set("Cookie", "sid="+value)
	wsReq.Header.Set("Upgrade", "websocket")
	wss := interceptAndRequestWithRecorder(t, interceptRequestOptions{
		Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
		Logger: logger, Metrics: metrics, Request: wsReq, Proxy: p,
		Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
	})
	defer wss.Body.Close() //nolint:errcheck // test response
	if wss.StatusCode != http.StatusForbidden {
		t.Fatalf("WSS upgrade status = %d, want 403", wss.StatusCode)
	}
}

func TestInterceptIssuerBoundCookieReflectionBlocked(t *testing.T) {
	const value = "session-value-1234567890abcd"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Set("Set-Cookie", "sid="+value+"; Path=/; Secure; Max-Age=60")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer other.Close()
	cache, pool, cfg, _, logger, metrics := testInterceptSetup(t)
	cfg.RequestBodyScanning.IssuerBoundSessionCookies = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: "Session Token", Regex: `session-value-[a-z0-9]+`, Severity: config.SeverityHigh,
	})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	request := func(server *httptest.Server, path, header, fieldValue string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			req.Header.Set(header, fieldValue)
		}
		return interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: server, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
			Logger: logger, Metrics: metrics, Request: req, Proxy: p,
			Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
		})
	}
	for _, step := range []struct {
		server *httptest.Server
		path   string
		header string
		value  string
		want   int
	}{
		{other, "/submit", "X-Data", value, http.StatusOK},
		{upstream, "/login", "", "", http.StatusOK},
		{upstream, "/account", "Cookie", "sid=" + value, http.StatusForbidden},
	} {
		resp := request(step.server, step.path, step.header, step.value)
		defer resp.Body.Close() //nolint:errcheck // test response
		if resp.StatusCode != step.want {
			t.Fatalf("%s status = %d, want %d", step.path, resp.StatusCode, step.want)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
	}
}
