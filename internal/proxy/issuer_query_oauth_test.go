// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
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

// oauthTestState is a second high-entropy value, distinct from the code, so
// the tests can tell which of the two values a redirect carried.
func oauthTestState() string {
	return strings.Join([]string{"Qz7pW2mK", "x9R4tB6n", "Y1cV8hJ3", "fL5gD0sA"}, "")
}

// An OAuth authorization server returns the code to the client's redirect_uri
// on another host. The callback passes the query entropy gate only after the
// same session sent an authorization request declaring that redirect_uri and
// the authorization server's delivered redirect carried those exact values.
func TestInterceptOAuthCallbackEndToEnd(t *testing.T) {
	code, state := issuedTestToken(), oauthTestState()
	app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer app.Close()
	callback := app.URL + "/cb"
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code="+code+"&state="+state, http.StatusFound)
		case "/redirect":
			// Not an authorization request: it declares nothing.
			http.Redirect(w, r, callback+"?code="+code, http.StatusFound)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer idp.Close()
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
	rph := newReceiptProxyHelper(t)
	p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	do := func(server *httptest.Server, path, agent string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: server, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
			Logger: logger, Metrics: m, Request: req, Proxy: p,
			Agent: agent, ActorAuth: envelope.ActorAuthBound,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	authorize := "/authorize?response_type=code&client_id=client-one&redirect_uri=" + url.QueryEscape(callback)
	cb := "/cb?code=" + code + "&state=" + state
	for _, step := range []struct {
		name   string
		server *httptest.Server
		path   string
		agent  string
		want   int
	}{
		{"callback before authorization", app, cb, "agent-one", http.StatusForbidden},
		{"undeclared cross-host redirect", idp, "/redirect", "agent-one", http.StatusFound},
		{"callback after undeclared redirect", app, "/cb?code=" + code, "agent-one", http.StatusForbidden},
		{"authorization request", idp, authorize, "agent-one", http.StatusFound},
		{"callback", app, cb, "agent-one", http.StatusOK},
		{"callback code only", app, "/cb?code=" + code, "agent-one", http.StatusOK},
		{"different agent", app, cb, "agent-two", http.StatusForbidden},
		{"different path", app, "/other?code=" + code, "agent-one", http.StatusForbidden},
		{"different parameter", app, "/cb?token=" + code, "agent-one", http.StatusForbidden},
		{"altered code", app, "/cb?code=" + code[:len(code)-1] + "x", "agent-one", http.StatusForbidden},
		{"authorization server itself", idp, cb, "agent-one", http.StatusForbidden},
		{"unissued credential beside callback", app, cb + "&leak=" + issuerUnissuedSecret(), "agent-one", http.StatusForbidden},
		{"unissued entropy beside callback", app, cb + "&other=" + strings.Join([]string{"aQ1wE2rT", "3yU4iO5p", "A6sD7fG8", "hJ9kL0zX"}, ""), "agent-one", http.StatusForbidden},
	} {
		t.Run(step.name, func(t *testing.T) {
			if got := do(step.server, step.path, step.agent); got != step.want {
				t.Fatalf("status=%d, want %d", got, step.want)
			}
		})
	}
	auditBytes, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(auditBytes), `"event":"entropy_issuer_query_allow"`) {
		t.Fatal("OAuth callback allowance missing from audit")
	}
	got := rph.requireReceipt(t, issuerQueryReceiptExtensionKey)
	if !strings.Contains(string(got.Ext), string(issuerQueryOAuthRedirect)) {
		t.Fatalf("callback receipt extension = %s, want %s", got.Ext, issuerQueryOAuthRedirect)
	}
}

func oauthTestStore(t *testing.T) (*InterceptContext, string) {
	t.Helper()
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "agent-one", ClientIP: "192.0.2.10", ActorAuth: envelope.ActorAuthBound}
	if ic.issuerQueryStore() == nil {
		t.Fatal("intercepted trusted session has no query store")
	}
	return ic, sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth)
}

func oauthAuthorizeURL(t *testing.T, server, redirect string) *url.URL {
	t.Helper()
	return mustIssuerQueryURL(t, server+"/authorize?response_type=code&client_id=client-one&redirect_uri="+url.QueryEscape(redirect))
}

// Each case changes one thing from the positive control, which runs first:
// a delivered 302 from the authorization server where the authorization
// request was made, to the exact declared redirect_uri.
func TestOAuthRedirectBindingScope(t *testing.T) {
	code := issuedTestToken()
	const (
		server   = "https://login.vendor.example"
		callback = "https://app.vendor.example/auth/callback"
	)
	for _, tc := range []struct {
		name        string
		declaration *url.URL // request that declares; nil declares nothing
		declSession string   // "" means the checked session
		responder   string   // URL of the request whose response redirects
		status      int
		location    string
		undelivered bool
		checkName   string
		checkValue  string
		want        bool
	}{
		{name: "positive control", status: http.StatusFound, location: callback + "?code=" + code, want: true},
		{name: "303", status: http.StatusSeeOther, location: callback + "?code=" + code, want: true},
		{name: "same response declares and redirects", declaration: oauthAuthorizeURL(t, server, callback), responder: "same", status: http.StatusFound, location: callback + "?code=" + code, want: true},
		{name: "no declaration", declaration: &url.URL{}, status: http.StatusFound, location: callback + "?code=" + code, want: false},
		{name: "declared by another session", declSession: "other-session", status: http.StatusFound, location: callback + "?code=" + code, want: false},
		{name: "declared to another server", declaration: oauthAuthorizeURL(t, "https://idp.vendor.example", callback), status: http.StatusFound, location: callback + "?code=" + code, want: false},
		{name: "redirect from another host", responder: "https://other.vendor.example/login", status: http.StatusFound, location: callback + "?code=" + code, want: false},
		{name: "redirect from another port", responder: "https://login.vendor.example:8443/login", status: http.StatusFound, location: callback + "?code=" + code, want: false},
		{name: "different callback path", status: http.StatusFound, location: "https://app.vendor.example/auth/other?code=" + code, want: false},
		{name: "different callback host", status: http.StatusFound, location: "https://evil.vendor.example/auth/callback?code=" + code, want: false},
		{name: "different callback port", status: http.StatusFound, location: "https://app.vendor.example:8443/auth/callback?code=" + code, want: false},
		{name: "cleartext callback", status: http.StatusFound, location: "http://app.vendor.example/auth/callback?code=" + code, want: false},
		{name: "non-redirect status", status: http.StatusOK, location: callback + "?code=" + code, want: false},
		{name: "not delivered", status: http.StatusFound, location: callback + "?code=" + code, undelivered: true, want: false},
		{name: "value not in the redirect", status: http.StatusFound, location: callback + "?code=other", want: false},
		{name: "value over the size cap", status: http.StatusFound, location: callback + "?code=" + strings.Repeat("Z", issuerCookieMaxPairBytes), checkValue: strings.Repeat("Z", issuerCookieMaxPairBytes), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ic, session := oauthTestStore(t)
			store := ic.issuerQueryStore()
			declaration := tc.declaration
			if declaration == nil {
				declaration = oauthAuthorizeURL(t, server, callback)
			}
			declSession := session
			if tc.declSession != "" {
				declSession = tc.declSession
			}
			delivered := !tc.undelivered
			if tc.responder != "same" && declaration.RawQuery != "" {
				if redirect, ok := oauthRedirectDeclaration(declaration); ok {
					store.declareRedirect(declSession, declaration, redirect, time.Now())
				} else {
					t.Fatalf("declaration %s did not parse", declaration)
				}
			}
			responder := tc.responder
			switch responder {
			case "":
				responder = server + "/u/login"
			case "same":
				responder = declaration.String()
			}
			response := &http.Response{
				Request:    &http.Request{URL: mustIssuerQueryURL(t, responder)},
				StatusCode: tc.status,
				Header:     http.Header{"Location": {tc.location}},
			}
			recordDeliveredIssuerQuery(ic, response, nil, delivered)
			name, value := "code", code
			if tc.checkName != "" {
				name = tc.checkName
			}
			if tc.checkValue != "" {
				value = tc.checkValue
			}
			// Check where the redirect would send the value, not only the
			// declared callback, so a mismatched target cannot pass unseen.
			kind, got := store.match(session, mustIssuerQueryURL(t, tc.location), name, value)
			if got != tc.want {
				t.Fatalf("allowed=%v, want %v", got, tc.want)
			}
			if got && kind != issuerQueryOAuthRedirect {
				t.Fatalf("kind=%q, want %q", kind, issuerQueryOAuthRedirect)
			}
		})
	}
}

// A cross-host link in a JSON body issues nothing, even to a declared
// redirect_uri: only the redirect hop carries a callback.
func TestOAuthRedirectBindingIgnoresBodyLinks(t *testing.T) {
	code := issuedTestToken()
	const callback = "https://app.vendor.example/auth/callback"
	ic, session := oauthTestStore(t)
	store := ic.issuerQueryStore()
	declaration := oauthAuthorizeURL(t, "https://login.vendor.example", callback)
	redirect, _ := oauthRedirectDeclaration(declaration)
	store.declareRedirect(session, declaration, redirect, time.Now())
	response := &http.Response{
		Request: &http.Request{URL: mustIssuerQueryURL(t, "https://login.vendor.example/u/login")},
		Header:  http.Header{"Content-Type": {"application/json"}},
	}
	recordDeliveredIssuerQuery(ic, response, []byte(`{"next":"`+callback+`?code=`+code+`"}`), true)
	if store.allows(session, mustIssuerQueryURL(t, callback), "code", code) {
		t.Fatal("cross-host JSON link issued a callback value")
	}
	// Positive control: the same URL as a redirect Location is issued.
	response.StatusCode = http.StatusFound
	response.Header.Set("Location", callback+"?code="+code)
	recordDeliveredIssuerQuery(ic, response, nil, true)
	if !store.allows(session, mustIssuerQueryURL(t, callback), "code", code) {
		t.Fatal("declared redirect was not issued")
	}
}

func TestOAuthRedirectDeclarationParsing(t *testing.T) {
	const redirect = "https://app.vendor.example/cb"
	escaped := url.QueryEscape(redirect)
	for _, tc := range []struct {
		name, query string
		want        bool
	}{
		{"code flow", "response_type=code&client_id=c&redirect_uri=" + escaped, true},
		{"hybrid flow", "response_type=code+id_token&client_id=c&redirect_uri=" + escaped, true},
		{"redirect_uri with its own query", "response_type=code&client_id=c&redirect_uri=" + url.QueryEscape(redirect+"?tenant=a"), true},
		{"implicit flow", "response_type=token&client_id=c&redirect_uri=" + escaped, false},
		{"code as a substring only", "response_type=codex&client_id=c&redirect_uri=" + escaped, false},
		{"missing response_type", "client_id=c&redirect_uri=" + escaped, false},
		{"missing client_id", "response_type=code&redirect_uri=" + escaped, false},
		{"empty client_id", "response_type=code&client_id=&redirect_uri=" + escaped, false},
		{"missing redirect_uri", "response_type=code&client_id=c", false},
		{"duplicate redirect_uri", "response_type=code&client_id=c&redirect_uri=" + escaped + "&redirect_uri=" + escaped, false},
		{"duplicate response_type", "response_type=code&response_type=code&client_id=c&redirect_uri=" + escaped, false},
		{"duplicate client_id", "response_type=code&client_id=c&client_id=d&redirect_uri=" + escaped, false},
		{"cleartext redirect_uri", "response_type=code&client_id=c&redirect_uri=" + url.QueryEscape("http://app.vendor.example/cb"), false},
		{"relative redirect_uri", "response_type=code&client_id=c&redirect_uri=%2Fcb", false},
		{"redirect_uri with fragment", "response_type=code&client_id=c&redirect_uri=" + url.QueryEscape(redirect+"#x"), false},
		{"redirect_uri with empty fragment", "response_type=code&client_id=c&redirect_uri=" + url.QueryEscape(redirect+"#"), false},
		{"redirect_uri with userinfo", "response_type=code&client_id=c&redirect_uri=" + url.QueryEscape("https://u@app.vendor.example/cb"), false},
		{"semicolon separator", "response_type=code;client_id=c&redirect_uri=" + escaped, false},
		{"unparseable redirect_uri", "response_type=code&client_id=c&redirect_uri=%25zz%3A%2F%2F", false},
		{"no query", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &url.URL{Scheme: "https", Host: "login.vendor.example", Path: "/authorize", RawQuery: tc.query}
			if _, got := oauthRedirectDeclaration(u); got != tc.want {
				t.Fatalf("declared=%v, want %v", got, tc.want)
			}
		})
	}
	if _, got := oauthRedirectDeclaration(nil); got {
		t.Fatal("nil URL declared a redirect")
	}
}

func TestOAuthRedirectStoreBounds(t *testing.T) {
	server := mustIssuerQueryURL(t, "https://login.vendor.example/authorize")
	redirectN := func(i int) *url.URL {
		return mustIssuerQueryURL(t, "https://app.vendor.example/cb/"+strconv.Itoa(i))
	}
	store := newIssuerQueryStore()
	now := time.Now()
	for i := 0; i <= issuerQueryMaxRedirects; i++ {
		store.declareRedirect("session", server, redirectN(i), now)
	}
	// Re-declaring an existing pair does not grow the list.
	store.declareRedirect("session", server, redirectN(issuerQueryMaxRedirects), now)
	if store.redirectDeclared("session", server, redirectN(0)) {
		t.Fatal("oldest declaration survived the per-session bound")
	}
	if !store.redirectDeclared("session", server, redirectN(1)) || !store.redirectDeclared("session", server, redirectN(issuerQueryMaxRedirects)) {
		t.Fatal("recent declarations were evicted")
	}
	// Session eviction removes declarations with the rest of the session.
	for i := 0; i < issuerCookieMaxSessions; i++ {
		store.declareRedirect("other-"+strconv.Itoa(i), server, redirectN(0), now.Add(time.Duration(i+1)*time.Second))
	}
	if store.redirectDeclared("session", server, redirectN(1)) {
		t.Fatal("evicted session kept its declarations")
	}
	if !store.redirectDeclared("other-0", server, redirectN(0)) {
		t.Fatal("newer session was evicted")
	}
	for _, tc := range []struct {
		name  string
		store *issuerQueryStore
		sess  string
		srv   *url.URL
	}{
		{"nil store", nil, "session", server},
		{"disabled store", newIssuerQueryStoreWithReader(failingIssuerQueryReader{}), "session", server},
		{"empty session", store, "", server},
		{"invalid server origin", store, "session", mustIssuerQueryURL(t, "http://login.vendor.example/authorize")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.store.declareRedirect(tc.sess, tc.srv, redirectN(7), now)
			if tc.store.redirectDeclared(tc.sess, tc.srv, redirectN(7)) {
				t.Fatal("declaration recorded where it must not be")
			}
		})
	}
	if store.redirectDeclared("other-1", server, mustIssuerQueryURL(t, "file:///cb")) {
		t.Fatal("invalid redirect origin matched")
	}
}

func TestIssuerQueryAllowReceiptKind(t *testing.T) {
	for _, tc := range []struct {
		kind issuerQueryKind
		want string
	}{
		{issuerQueryObserved, string(issuerQueryObserved)},
		{issuerQueryOAuthRedirect, string(issuerQueryOAuthRedirect)},
		{"", string(issuerQueryObserved)},
	} {
		t.Run(tc.want+"/"+string(tc.kind), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			rph := newReceiptProxyHelper(t)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithReceiptEmitter(rph.emitter))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			p.recordIssuerQueryAllow(audit.LogContext{}, "https://app.vendor.example/cb?code=x", "req", "agent-one", http.MethodGet, tc.kind)
			got := rph.requireReceipt(t, issuerQueryReceiptExtensionKey)
			if !strings.Contains(string(got.Ext), `"`+tc.want+`"`) {
				t.Fatalf("extension = %s, want %s", got.Ext, tc.want)
			}
		})
	}
}
