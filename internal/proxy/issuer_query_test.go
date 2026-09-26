// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type failingIssuerQueryReader struct{}

func (failingIssuerQueryReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestInterceptIssuerQueryEndToEnd(t *testing.T) {
	value := issuedTestToken()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/list" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"next":"/page?%24skiptoken=`+value+`"}`)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	issuerCookieTestConfig(t, cfg)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	do := func(path, agent string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
			Logger: logger, Metrics: m, Request: req, Proxy: p,
			Agent: agent, ActorAuth: envelope.ActorAuthBound,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	page := "/page?%24skiptoken=" + value
	for _, step := range []struct {
		name, path, agent string
		want              int
	}{
		{"before issuance", page, "agent-one", http.StatusForbidden},
		{"delivered JSON", "/list", "agent-one", http.StatusOK},
		{"issued value", page, "agent-one", http.StatusOK},
		{"literal decoded key", "/page?$skiptoken=" + value, "agent-one", http.StatusOK},
		{"different agent", page, "agent-two", http.StatusForbidden},
		{"different path", "/other?%24skiptoken=" + value, "agent-one", http.StatusForbidden},
		{"different parameter", "/page?other=" + value, "agent-one", http.StatusForbidden},
		{"altered value", "/page?%24skiptoken=" + value[:len(value)-1] + "x", "agent-one", http.StatusForbidden},
		{"unissued credential beside issued value", page + "&leak=" + issuerUnissuedSecret(), "agent-one", http.StatusForbidden},
		{"unissued entropy beside issued value", page + "&other=" + strings.Join([]string{"aQ1wE2rT", "3yU4iO5p", "A6sD7fG8", "hJ9kL0zX"}, ""), "agent-one", http.StatusForbidden},
	} {
		t.Run(step.name, func(t *testing.T) {
			if got := do(step.path, step.agent); got != step.want {
				t.Fatalf("status=%d, want %d", got, step.want)
			}
		})
	}
	auditBytes, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(auditBytes), `"event":"entropy_issuer_query_allow"`) {
		t.Fatal("issuer query allowance missing from audit")
	}
}

func TestForwardIssuerQueryResponseIsNotObserved(t *testing.T) {
	value := issuedTestToken()
	var origin string
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/list" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"next":"`+origin+`/page?next=`+value+`"}`)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	origin = upstream.URL
	_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.TLSInterception.Enabled = true
	})
	defer cleanup()
	for _, step := range []struct {
		path string
		want int
	}{
		{"/list", http.StatusOK},
		{"/page?next=" + value, http.StatusForbidden},
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+step.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, req)
		if w.Code != step.want {
			t.Fatalf("%s: status=%d, want %d", step.path, w.Code, step.want)
		}
	}
}

func TestIssuerQueryObservationScope(t *testing.T) {
	value := issuedTestToken()
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "agent-one", ClientIP: "192.0.2.10", ActorAuth: envelope.ActorAuthBound}
	store := ic.issuerQueryStore()
	if store == nil {
		t.Fatal("intercepted trusted session has no query store")
	}
	issuer := mustIssuerQueryURL(t, "https://api.vendor.example/list")
	target := mustIssuerQueryURL(t, "https://api.vendor.example/page?%24skiptoken="+value)
	body, err := json.Marshal(map[string]any{"next": target.String(), "other": "https://other.vendor.example/page?%24skiptoken=" + value})
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{URL: issuer}
	response := &http.Response{Request: request, Header: http.Header{"Content-Type": {"application/json"}}}
	session := sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth)
	check := func(name string, target *url.URL, session, param, value string, want bool) {
		t.Helper()
		if got := store.allows(session, target, param, value); got != want {
			t.Errorf("%s: allowed=%v, want %v", name, got, want)
		}
	}
	check("before observation", target, session, "$skiptoken", value, false)
	recordDeliveredIssuerQuery(ic, response, body, true)
	check("same issuer decoded key", target, session, "$skiptoken", value, true)
	check("different host", mustIssuerQueryURL(t, "https://other.vendor.example/page"), session, "$skiptoken", value, false)
	check("different session", target, "different", "$skiptoken", value, false)
	check("different path", mustIssuerQueryURL(t, "https://api.vendor.example/other"), session, "$skiptoken", value, false)
	check("different parameter", target, session, "other", value, false)
	check("altered value", target, session, "$skiptoken", value[:len(value)-1]+"x", false)
	check("different port", mustIssuerQueryURL(t, "https://api.vendor.example:8443/page"), session, "$skiptoken", value, false)
	if result := sc.Scan(context.Background(), target.String()); result.Allowed || result.Scanner != scanner.ScannerEntropy {
		t.Fatalf("positive block control: %+v", result)
	}
	allowCtx := scanner.WithIssuerQueryAllowance(context.Background(), func(name, decoded string) bool {
		return store.allows(session, target, name, decoded)
	})
	if result := sc.Scan(allowCtx, target.String()); !result.Allowed {
		t.Fatalf("observed value blocked: %+v", result)
	}
	for _, tc := range []struct {
		name, contentType string
		delivered         bool
	}{
		{"non JSON", "text/plain", true},
		{"not delivered", "application/json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := newIssuerQueryStore()
			p.issuerCookieRuntime.Load().query = other
			recordDeliveredIssuerQuery(ic, &http.Response{Request: request, Header: http.Header{"Content-Type": {tc.contentType}}}, body, tc.delivered)
			if other.allows(session, target, "$skiptoken", value) {
				t.Fatal("unavailable response created issuance")
			}
		})
	}
	// An issuer URL for another host never produces evidence for that host.
	other := newIssuerQueryStore()
	p.issuerCookieRuntime.Load().query = other
	foreign, _ := json.Marshal(map[string]string{"next": "https://other.vendor.example/page?%24skiptoken=" + value})
	recordDeliveredIssuerQuery(ic, response, foreign, true)
	if other.allows(session, mustIssuerQueryURL(t, "https://other.vendor.example/page"), "$skiptoken", value) {
		t.Fatal("cross-host URL was observed")
	}
}

func TestIssuerQueryEvictionAndReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, ActorAuth: envelope.ActorAuthBound}
	store := ic.issuerQueryStore()
	target := mustIssuerQueryURL(t, "https://api.vendor.example/page")
	first := issuedTestToken()
	store.remember("session", target, "page", first, time.Unix(0, 0))
	if !store.allows("session", target, "page", first) {
		t.Fatal("positive issuance control missing")
	}
	for i := 1; i <= issuerCookieMaxEntries; i++ {
		store.remember("session", target, "page", strings.Repeat("x", 30)+string(rune('a'+i%26))+time.Unix(int64(i), 0).Format("150405"), time.Unix(int64(i), 0))
	}
	if len(store.sessions["session"]) != issuerCookieMaxEntries {
		t.Fatal("entry cap not enforced")
	}
	if store.allows("session", target, "page", first) {
		t.Fatal("evicted value still allowed")
	}
	blockedURL := target.String() + "?page=" + first
	allowCtx := scanner.WithIssuerQueryAllowance(context.Background(), func(name, value string) bool {
		return store.allows("session", target, name, value)
	})
	if result := sc.Scan(allowCtx, blockedURL); result.Allowed || result.Scanner != scanner.ScannerEntropy {
		t.Fatalf("evicted value did not return to entropy scanning: %+v", result)
	}
	store.remember("session", target, "page", "retained", time.Now())
	same := cfg.Clone()
	if !p.Reload(same, scanner.MustNew(same)) {
		t.Fatal("enabled reload failed")
	}
	if got := (&InterceptContext{Proxy: p, Config: same, ActorAuth: envelope.ActorAuthBound}).issuerQueryStore(); got != store {
		t.Fatal("enabled reload lost in-memory query store")
	}
	off := same.Clone()
	off.TLSInterception.Enabled = false
	if !p.Reload(off, scanner.MustNew(off)) {
		t.Fatal("disabled reload failed")
	}
	if got := (&InterceptContext{Proxy: p, Config: off, ActorAuth: envelope.ActorAuthBound}).issuerQueryStore(); got != nil {
		t.Fatal("interception disabled but query store available")
	}
}

func TestIssuerQueryRelativeLinks(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
	request := &http.Request{URL: mustIssuerQueryURL(t, "https://api.vendor.example/v1/items")}
	response := &http.Response{Request: request, Header: http.Header{"Content-Type": {"application/problem+json"}}}
	session := sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth)
	value := issuedTestToken()
	for _, tc := range []struct {
		name, link, target string
		want               bool
	}{
		{"relative path", "/v1/items?page_token=" + value, "https://api.vendor.example/v1/items", true},
		{"relative query", "?page_token=" + value, "https://api.vendor.example/v1/items", true},
		{"protocol relative foreign", "//other.vendor.example/v1/items?page_token=" + value, "https://other.vendor.example/v1/items", false},
		{"plain text", "next page_token=" + value, "https://api.vendor.example/v1/items", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.issuerCookieRuntime.Load().query = newIssuerQueryStore()
			body, err := json.Marshal(map[string]string{"next": tc.link})
			if err != nil {
				t.Fatal(err)
			}
			recordDeliveredIssuerQuery(ic, response, body, true)
			if got := ic.issuerQueryStore().allows(session, mustIssuerQueryURL(t, tc.target), "page_token", value); got != tc.want {
				t.Fatalf("allowed=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestIssuerQueryStoreBoundaries(t *testing.T) {
	target := mustIssuerQueryURL(t, "https://api.vendor.example/page")
	invalid := mustIssuerQueryURL(t, "file:///page")
	store := newIssuerQueryStore()
	for _, tc := range []struct {
		name string
		s    *issuerQueryStore
		id   string
		u    *url.URL
		key  string
	}{
		{"nil store", nil, "session", target, "page"},
		{"empty session", store, "", target, "page"},
		{"oversize pair", store, "session", target, strings.Repeat("x", issuerCookieMaxPairBytes+1)},
		{"invalid origin", store, "session", invalid, "page"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.s.remember(tc.id, tc.u, tc.key, "value", time.Now())
			if tc.s.allows(tc.id, tc.u, tc.key, "value") {
				t.Fatal("untrusted input was allowed")
			}
		})
	}
	disabled := newIssuerQueryStoreWithReader(failingIssuerQueryReader{})
	if !disabled.disabled {
		t.Fatal("failed randomness did not disable query allowance")
	}
	disabled.remember("session", target, "page", "value", time.Now())
	if disabled.allows("session", target, "page", "value") || len(disabled.sessions) != 0 {
		t.Fatal("disabled store retained or allowed a value")
	}
	root := mustIssuerQueryURL(t, "https://api.vendor.example")
	store.remember("session", root, "page", "value", time.Now())
	if !store.allows("session", mustIssuerQueryURL(t, "https://api.vendor.example/"), "page", "value") {
		t.Fatal("empty path did not normalize to root")
	}
	store.remember("session", root, "page", "value", time.Now().Add(time.Second))
	if len(store.sessions["session"]) != 1 {
		t.Fatal("duplicate evidence created another entry")
	}
	store.used["session"] = time.Unix(0, 0)
	for i := 0; i < issuerCookieMaxSessions; i++ {
		store.remember("other-"+string(rune('A'+i)), target, "page", "value", time.Unix(int64(i+1), 0))
	}
	if len(store.sessions) != issuerCookieMaxSessions || store.allows("session", root, "page", "value") {
		t.Fatal("oldest session was not evicted at cap")
	}
}

func TestIssuerQueryResponseBoundaries(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
	request := &http.Request{URL: mustIssuerQueryURL(t, "https://api.vendor.example/list")}
	value := issuedTestToken()
	target := mustIssuerQueryURL(t, "https://api.vendor.example/page")
	session := sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth)
	for _, tc := range []struct {
		name, media, body string
		responseRequest   *http.Request
		want              bool
	}{
		{"JSON suffix accepted", "application/problem+json", `{"next":"/page?token=` + value + `"}`, request, true},
		{"text JSON rejected", "text/json", `{"next":"/page?token=` + value + `"}`, request, false},
		{"malformed JSON", "application/json", `{`, request, false},
		{"invalid response origin", "application/json", `{"next":"/page?token=` + value + `"}`, &http.Request{URL: mustIssuerQueryURL(t, "file:///list")}, false},
		{"missing response request", "application/json", `{"next":"/page?token=` + value + `"}`, nil, false},
		{"missing query", "application/json", `{"next":"/page"}`, request, false},
		{"malformed link", "application/json", `{"next":"%zz?token=` + value + `"}`, request, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.issuerCookieRuntime.Load().query = newIssuerQueryStore()
			response := &http.Response{Request: tc.responseRequest, Header: http.Header{"Content-Type": {tc.media}}}
			recordDeliveredIssuerQuery(ic, response, []byte(tc.body), true)
			if got := ic.issuerQueryStore().allows(session, target, "token", value); got != tc.want {
				t.Fatalf("allowed=%v, want %v", got, tc.want)
			}
		})
	}
	// A redirected response belongs to its actual responding origin.
	p.issuerCookieRuntime.Load().query = newIssuerQueryStore()
	redirected := &http.Response{Request: &http.Request{URL: mustIssuerQueryURL(t, "https://other.vendor.example/list")}, Header: http.Header{"Content-Type": {"application/json"}}}
	recordDeliveredIssuerQuery(ic, redirected, []byte(`{"next":"/page?token=`+value+`"}`), true)
	if ic.issuerQueryStore().allows(session, target, "token", value) || !ic.issuerQueryStore().allows(session, mustIssuerQueryURL(t, "https://other.vendor.example/page"), "token", value) {
		t.Fatal("redirect response was attributed to the original origin")
	}
}

func TestIssuerQueryStaleRuntimeAndNestedDocument(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
	store := ic.issuerQueryStore()
	if store == nil {
		t.Fatal("missing enabled store")
	}
	stale := *ic
	stale.IssuerRuntime = &issuerCookieRuntime{}
	if stale.issuerQueryStore() != nil {
		t.Fatal("stale request runtime retained query allowance")
	}
	stale = *ic
	stale.Config = cfg.Clone()
	if stale.issuerQueryStore() != nil {
		t.Fatal("stale config retained query allowance")
	}
	response := &http.Response{Request: &http.Request{URL: mustIssuerQueryURL(t, "https://api.vendor.example/list")}, Header: http.Header{"Content-Type": {"application/json"}}}
	value := issuedTestToken()
	body := []byte(`{"data":[{"next":"/page?token=` + value + `"}]}`)
	recordDeliveredIssuerQuery(ic, response, body, true)
	session := sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth)
	target := mustIssuerQueryURL(t, "https://api.vendor.example/page")
	if !store.allows(session, target, "token", value) {
		t.Fatal("nested JSON continuation was not observed")
	}
	for _, tc := range []struct {
		name string
		ic   *InterceptContext
		resp *http.Response
		body []byte
	}{
		{"nil context", nil, response, body},
		{"no proxy", &InterceptContext{Config: cfg, ActorAuth: envelope.ActorAuthBound}, response, body},
		{"untrusted actor", &InterceptContext{Proxy: p, Config: cfg}, response, body},
		{"nil response", ic, nil, body},
		{"empty body", ic, response, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.issuerCookieRuntime.Load().query = newIssuerQueryStore()
			recordDeliveredIssuerQuery(tc.ic, tc.resp, tc.body, true)
			if p.issuerCookieRuntime.Load().query.allows(session, target, "token", value) {
				t.Fatal("unavailable evidence created query allowance")
			}
		})
	}
	p.recordIssuerQueryAllow(audit.LogContext{}, "%zz", "", "", http.MethodGet)
	var nilProxy *Proxy
	nilProxy.recordIssuerQueryAllow(audit.LogContext{}, "https://api.vendor.example/page", "", "", http.MethodGet)

	// Only the first bounded set of links can grant an allowance.
	links := make([]string, issuerCookieMaxSetCookies+1)
	for i := range links {
		links[i] = "/page?token=" + strconv.Itoa(i)
	}
	encoded, err := json.Marshal(links)
	if err != nil {
		t.Fatal(err)
	}
	p.issuerCookieRuntime.Load().query = newIssuerQueryStore()
	recordDeliveredIssuerQuery(ic, response, encoded, true)
	if !ic.issuerQueryStore().allows(session, target, "token", "0") || ic.issuerQueryStore().allows(session, target, "token", strconv.Itoa(issuerCookieMaxSetCookies)) {
		t.Fatal("JSON observation cap was not enforced")
	}
	var deep any = "/page?cursor=deep"
	for i := 0; i < 34; i++ {
		deep = []any{deep}
	}
	encoded, err = json.Marshal(deep)
	if err != nil {
		t.Fatal(err)
	}
	p.issuerCookieRuntime.Load().query = newIssuerQueryStore()
	recordDeliveredIssuerQuery(ic, response, encoded, true)
	if ic.issuerQueryStore().allows(session, target, "cursor", "deep") {
		t.Fatal("over-depth JSON was observed")
	}
}

func mustIssuerQueryURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// issuedTestToken returns a synthetic high-entropy token. It is assembled
// from short pieces so no single source literal reads as a credential.
func issuedTestToken() string {
	return strings.Join([]string{"aB3xK9mZ", "2wQ7rL5y", "N8vC4jF6", "hD1eG0tP", "9sU2qW5z"}, "")
}

// TestIssuerQueryJSONPositions checks which JSON strings issue links: string
// values anywhere, including after nested objects inside arrays, and
// path-relative references, but never object keys.
func TestIssuerQueryJSONPositions(t *testing.T) {
	value := issuedTestToken()
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	issuer := mustIssuerQueryURL(t, "https://api.vendor.example/v1/list")
	link := func(path string) string { return path + "?cursor=" + value }
	for _, tc := range []struct {
		name, body, path string
		want             bool
	}{
		{"object value", `{"next":"` + link("/v1/page") + `"}`, "/v1/page", true},
		{"key only", `{"` + link("/v1/page") + `":1}`, "/v1/page", false},
		{"path-relative value", `{"next":"` + link("page") + `"}`, "/v1/page", true},
		{"array value after a nested object", `[{"a":"b"},"` + link("/v1/page") + `"]`, "/v1/page", true},
		{"value after a nested array in an object", `{"a":[1,2],"next":"` + link("/v1/page") + `"}`, "/v1/page", true},
		{"key after a nested object is not a value", `{"a":{"b":1},"` + link("/v1/page") + `":2}`, "/v1/page", false},
		{"protocol-relative other host", `{"next":"//other.vendor.example` + link("/v1/page") + `"}`, "/v1/page", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "agent-" + tc.name, ClientIP: "192.0.2.10", ActorAuth: envelope.ActorAuthBound}
			store := ic.issuerQueryStore()
			if store == nil {
				t.Fatal("no query store")
			}
			response := &http.Response{Request: &http.Request{URL: issuer}, Header: http.Header{"Content-Type": {"application/json"}}}
			recordDeliveredIssuerQuery(ic, response, []byte(tc.body), true)
			session := sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth)
			target := mustIssuerQueryURL(t, "https://api.vendor.example"+tc.path)
			if got := store.allows(session, target, "cursor", value); got != tc.want {
				t.Fatalf("allowed=%v, want %v for body %s", got, tc.want, tc.body)
			}
		})
	}
}

// TestIssuerQueryDigestIsByteExact guards against a digest that normalizes
// its input: two values differing only in invalid UTF-8 bytes must not share
// an allowance, and moving bytes across a field boundary must change it.
func TestIssuerQueryDigestIsByteExact(t *testing.T) {
	s := &issuerQueryStore{}
	a := s.digest("api.vendor.example", "443", "/page", "cursor", "tok\xff")
	b := s.digest("api.vendor.example", "443", "/page", "cursor", "tok\xfe")
	if a == b {
		t.Fatal("values differing only in invalid UTF-8 bytes share a digest")
	}
	if s.digest("api.vendor.example", "443", "/page", "cursor", "tok\xff") != a {
		t.Fatal("digest is not stable for identical input")
	}
	if s.digest("api.vendor.example", "443", "/page", "cursorx", "y") == s.digest("api.vendor.example", "443", "/page", "cursor", "xy") {
		t.Fatal("moving bytes across the name/value boundary kept the digest")
	}
}
