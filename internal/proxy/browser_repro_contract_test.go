// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	browserContractHost    = "browser.fixture.example"
	browserContractLogin   = `<html><body><form id="synthetic-login" action="/session" method="post">Synthetic login</form></body></html>`
	browserContractAccount = `<html><body><p id="synthetic-account">Synthetic account ready</p></body></html>`
	browserContractSession = "fixture_session"
)

// These are HTTP-level oracles for the browser reproduction harness. The
// origins are independent of its Python fixture and JavaScript assertions;
// real response framing, redirects, cookie jars and the proxy transport run.
// They do not claim to test browser rendering, storage persistence or Chromium.
func TestBrowserReproForwardContracts(t *testing.T) {
	t.Run("incomplete_response_is_a_provenanced_403", func(t *testing.T) {
		const partial = `{"message":"synthetic unfinished`
		var originHits atomic.Int32
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/data" {
				t.Errorf("unexpected origin request: %s %s", r.Method, r.URL.Path)
				http.NotFound(w, r)
				return
			}
			originHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "1024")
			w.Header().Set("Connection", "close")
			w.Header().Set("X-Synthetic-Origin", "incomplete")
			_, _ = io.WriteString(w, partial)
		}))
		t.Cleanup(origin.Close)

		// Prove the owned origin actually sends a short 200, rather than
		// fabricating a proxy denial or substituting a failing reader.
		direct := &http.Client{Timeout: 5 * time.Second}
		resp, body, err := browserContractRequest(t, direct, http.MethodGet, origin.URL+"/api/data", "")
		if resp.StatusCode != http.StatusOK || resp.ContentLength != 1024 || body != partial || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("origin framing: status=%d length=%d body=%q error=%v", resp.StatusCode, resp.ContentLength, body, err)
		}

		client, base, redirects, _ := newBrowserContractProxyClient(t, origin.URL)
		resp, body, err = browserContractRequest(t, client, http.MethodGet, base+"/api/data", "")
		if err != nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("proxied incomplete response: status=%d error=%v body=%q", resp.StatusCode, err, body)
		}
		for header, want := range map[string]string{
			blockreason.HeaderReason:   string(blockreason.ParseError),
			blockreason.HeaderVersion:  blockreason.SchemaVersion,
			blockreason.HeaderLayer:    "response_scan",
			blockreason.HeaderSeverity: "warn",
			blockreason.HeaderRetry:    "none",
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
		if !strings.Contains(body, "blocked: response read error") || strings.Contains(body, partial) || resp.Header.Get("X-Synthetic-Origin") != "" {
			t.Errorf("read failure leaked origin data or lost its cause: headers=%v body=%q", resp.Header, body)
		}
		if originHits.Load() != 2 || redirects.Load() != 0 {
			t.Errorf("origin hits=%d client redirects=%d, want 2 and 0", originHits.Load(), redirects.Load())
		}
	})

	t.Run("login_navigation_is_owned_by_client", func(t *testing.T) {
		origin, events := newBrowserContractAuthOrigin(t)
		client, base, redirects, _ := newBrowserContractProxyClient(t, origin.URL)
		resp, body, err := browserContractRequest(t, client, http.MethodGet, base+"/account", "")
		assertBrowserContractRedirect(t, resp, body, err, "/account", "/login")
		assertBrowserContractEvents(t, events, browserContractEvent{http.MethodGet, "/account", false})
		if redirects.Load() != 1 {
			t.Fatalf("client observed %d redirects, want 1", redirects.Load())
		}
		resp, body, err = browserContractRequest(t, client, http.MethodGet, base+"/login", "")
		assertBrowserContractResponse(t, resp, body, err, "/login", browserContractLogin)
		assertBrowserContractEvents(t, events, browserContractEvent{http.MethodGet, "/login", false})
	})

	t.Run("redirect_cookie_establishes_only_clients_session", func(t *testing.T) {
		origin, events := newBrowserContractAuthOrigin(t)
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		// Independent direct control proves the unchanged 303 origin can
		// authenticate a cookie-aware client without any proxy assumptions.
		direct := &http.Client{Jar: jar, Timeout: 5 * time.Second}
		resp, body, err := browserContractRequest(t, direct, http.MethodPost, origin.URL+"/session", "user=fixture&code=fixture-only")
		assertBrowserContractResponse(t, resp, body, err, "/account", browserContractAccount)
		assertBrowserContractEvents(t, events,
			browserContractEvent{http.MethodPost, "/session", false},
			browserContractEvent{http.MethodGet, "/account", true})

		client, base, redirects, p := newBrowserContractProxyClient(t, origin.URL)
		resp, body, err = browserContractRequest(t, client, http.MethodPost, base+"/session", "user=fixture&code=fixture-only")
		assertBrowserContractRedirect(t, resp, body, err, "/session", "/account")
		cookies := resp.Cookies
		if len(cookies) != 1 || cookies[0].Name != browserContractSession || !cookies[0].HttpOnly || cookies[0].MaxAge != 3600 || cookies[0].SameSite != http.SameSiteLaxMode {
			t.Fatalf("redirect did not preserve synthetic session cookie: %v", cookies)
		}
		if got := client.Jar.Cookies(resp.URL); len(got) != 1 || got[0].Name != browserContractSession {
			t.Fatalf("client did not store redirect cookie: %v", got)
		}
		if p.client.Jar != nil {
			t.Fatal("proxy must not share browser cookie state")
		}
		assertBrowserContractEvents(t, events, browserContractEvent{http.MethodPost, "/session", false})

		// A separate client on the same proxy does not inherit the session.
		other := &http.Client{Transport: client.Transport, Timeout: client.Timeout, CheckRedirect: client.CheckRedirect}
		resp, body, err = browserContractRequest(t, other, http.MethodGet, base+"/account", "")
		assertBrowserContractRedirect(t, resp, body, err, "/account", "/login")
		assertBrowserContractEvents(t, events, browserContractEvent{http.MethodGet, "/account", false})

		resp, body, err = browserContractRequest(t, client, http.MethodGet, base+"/account", "")
		assertBrowserContractResponse(t, resp, body, err, "/account", browserContractAccount)
		assertBrowserContractEvents(t, events, browserContractEvent{http.MethodGet, "/account", true})

		// Clear this HTTP fixture's cookie using the same host/path scope.
		client.Jar.SetCookies(resp.URL, []*http.Cookie{{Name: browserContractSession, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}})
		resp, body, err = browserContractRequest(t, client, http.MethodGet, base+"/account", "")
		assertBrowserContractRedirect(t, resp, body, err, "/account", "/login")
		assertBrowserContractEvents(t, events, browserContractEvent{http.MethodGet, "/account", false})
		resp, body, err = browserContractRequest(t, client, http.MethodGet, base+"/login", "")
		assertBrowserContractResponse(t, resp, body, err, "/login", browserContractLogin)
		assertBrowserContractEvents(t, events, browserContractEvent{http.MethodGet, "/login", false})
		if redirects.Load() != 3 {
			t.Fatalf("client redirects=%d, want session, other client, and cleared-session redirects", redirects.Load())
		}
	})
}

func newBrowserContractProxyClient(t *testing.T, originURL string, cfgMods ...func(*config.Config)) (*http.Client, string, *atomic.Int32, *Proxy) {
	t.Helper()
	origin, err := url.Parse(originURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{browserContractHost}
	cfg.TrustedDomains = []string{browserContractHost}
	cfg.DNS.HostOverrides = map[string][]string{browserContractHost: {"127.0.0.1"}}
	cfg.ForwardProxy.Enabled = true
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	for _, modify := range cfgMods {
		modify(cfg)
	}
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	proxyServer := httptest.NewServer(p.buildHandler(http.NewServeMux()))
	t.Cleanup(proxyServer.Close)
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	redirects := new(atomic.Int32)
	client := &http.Client{
		Transport: transport, Jar: jar, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			redirects.Add(1)
			return http.ErrUseLastResponse
		},
	}
	return client, "http://" + net.JoinHostPort(browserContractHost, origin.Port()), redirects, p
}

type browserContractEvent struct {
	method        string
	path          string
	authenticated bool
}

func newBrowserContractAuthOrigin(t *testing.T) (*httptest.Server, <-chan browserContractEvent) {
	t.Helper()
	events := make(chan browserContractEvent, 16)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(browserContractSession)
		authenticated := err == nil && cookie.Value == "synthetic"
		select {
		case events <- browserContractEvent{r.Method, r.URL.Path, authenticated}:
		default:
			t.Error("unexpected extra origin requests exceeded the bounded witness")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			r.Body = http.MaxBytesReader(w, r.Body, 1024)
			if err := r.ParseForm(); err != nil || r.PostForm.Get("user") != "fixture" || r.PostForm.Get("code") != "fixture-only" {
				http.Error(w, "Synthetic login rejected", http.StatusUnauthorized)
				return
			}
			// This owned plain-HTTP fixture cannot use Secure: the oracle
			// must prove that the client actually returns the session cookie.
			http.SetCookie(w, &http.Cookie{Name: browserContractSession, Value: "synthetic", Path: "/", MaxAge: 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/account", http.StatusSeeOther)
		case r.Method == http.MethodGet && r.URL.Path == "/account":
			if !authenticated {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			_, _ = io.WriteString(w, browserContractAccount)
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			_, _ = io.WriteString(w, browserContractLogin)
		default:
			t.Errorf("unexpected origin request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(origin.Close)
	return origin, events
}

// browserContractResponse contains only copied metadata from an already-read,
// closed response. Callers never receive ownership of an HTTP response body.
type browserContractResponse struct {
	StatusCode    int
	Header        http.Header
	URL           *url.URL
	Cookies       []*http.Cookie
	ContentLength int64
}

func browserContractResponseMetadata(resp *http.Response) browserContractResponse {
	requestURL := *resp.Request.URL
	return browserContractResponse{
		StatusCode: resp.StatusCode, Header: resp.Header.Clone(), URL: &requestURL,
		Cookies: resp.Cookies(), ContentLength: resp.ContentLength,
	}
}

func browserContractRequest(t *testing.T, client *http.Client, method, target, form string) (browserContractResponse, string, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return browserContractResponseMetadata(resp), string(body), readErr
}

func assertBrowserContractResponse(t *testing.T, resp browserContractResponse, body string, err error, path, wantBody string) {
	t.Helper()
	if err != nil || resp.StatusCode != http.StatusOK || resp.URL.Path != path || body != wantBody {
		t.Fatalf("response: status=%d path=%q body=%q error=%v; want 200, %q, %q", resp.StatusCode, resp.URL.Path, body, err, path, wantBody)
	}
	if resp.Header.Get("Location") != "" || resp.Header.Get(blockreason.HeaderReason) != "" {
		t.Fatalf("successful final response unexpectedly carried redirect/block headers: %v", resp.Header)
	}
}

func assertBrowserContractEvents(t *testing.T, events <-chan browserContractEvent, want ...browserContractEvent) {
	t.Helper()
	got := make([]browserContractEvent, 0, len(events))
	for len(events) != 0 {
		got = append(got, <-events)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("origin requests = %+v, want %+v", got, want)
	}
}

func assertBrowserContractRedirect(t *testing.T, resp browserContractResponse, body string, err error, path, location string) {
	t.Helper()
	if err != nil || resp.StatusCode != http.StatusSeeOther || resp.URL.Path != path || resp.Header.Get("Location") != location {
		t.Fatalf("redirect: status=%d path=%q location=%q body=%q error=%v", resp.StatusCode, resp.URL.Path, resp.Header.Get("Location"), body, err)
	}
	if resp.Header.Get(blockreason.HeaderReason) != "" {
		t.Fatalf("redirect carried block provenance: %v", resp.Header)
	}
}
