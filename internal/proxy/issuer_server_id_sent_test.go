// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// escapedAgentBlob is agentBlob with its first character written as a JSON
// unicode escape. The escape is capital K (U+004B); a lowercase escape decodes
// to a different string and cannot stand in for this value.
func escapedAgentBlob() string {
	return string([]byte{0x5c}) + "u004B" + agentBlob[1:]
}

func decodedEscapedAgentBlob() string {
	return "K" + agentBlob[1:]
}

func newSentIssuerProxy(t *testing.T) (*Proxy, *config.Config) {
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
	return p, cfg
}

func TestIssuerSentJSONTextOutsideRawBody(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	escaped := escapedAgentBlob()
	if decodedEscapedAgentBlob() != agentBlob {
		t.Fatalf("escape fixture decodes to %q, want %q", decodedEscapedAgentBlob(), agentBlob)
	}
	object := `{"query":"` + escaped + `"}`
	query := url.Values{}
	query.Set("criteria", object)
	withQuery, err := url.Parse("https://api.vendor.example/v1/filters?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	form := "criteria=" + url.QueryEscape(object)

	cases := []struct {
		name   string
		target *url.URL
		header http.Header
		body   string
	}{
		{name: "query", target: withQuery},
		{name: "header", target: origin, header: http.Header{"X-Criteria": {object}}},
		{name: "form field", target: origin, body: form},
		{name: "json body", target: origin, body: object},
		{name: "json key", target: origin, body: `{"` + escaped + `":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerIDStore(t)
			target := tc.target
			if target == nil {
				target = origin
			}
			s.recordSent("a", target, tc.header, []byte(tc.body), true, now)
			s.mintServerID("a", origin, agentBlob, now)
			if s.serverIDIssued("a", origin, agentBlob) {
				t.Fatal("JSON-decoded value was minted")
			}
		})
	}
}

func TestIssuerSentUserinfo(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	withUser, err := url.Parse("https://api.vendor.example/notes/index")
	if err != nil {
		t.Fatal(err)
	}
	withUser.User = url.UserPassword("agent", agentBlob)

	t.Run("store", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", withUser, nil, nil, true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("URL userinfo password was minted")
		}
	})

	t.Run("fetch helper", func(t *testing.T) {
		p, cfg := newSentIssuerProxy(t)
		p.recordIssuerFetchSent(cfg, "mail-agent", "127.0.0.1", envelope.ActorAuthBound, withUser)
		store := p.issuerStoreForUnmediatedSend()
		session := sessionKeyFor(cfg, "mail-agent", "127.0.0.1", envelope.ActorAuthBound)
		store.mintServerID(session, origin, agentBlob, now)
		if store.serverIDIssued(session, origin, agentBlob) {
			t.Fatal("a /fetch userinfo password was minted")
		}
	})

	t.Run("client delivers userinfo as basic auth", func(t *testing.T) {
		var user, pass string
		var ok bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok = r.BasicAuth()
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		u, err := url.Parse(srv.URL + "/notes/index")
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword("agent", agentBlob)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if !ok || user != "agent" || pass != agentBlob {
			t.Fatalf("origin saw user=%q pass=%q ok=%v", user, pass, ok)
		}
	})

	t.Run("top-level userinfo is not blocked by the URL scan", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Internal = nil // no DNS; this checks whether userinfo itself is scored
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		result := sc.Scan(context.Background(), "https://agent:"+agentBlob+"@api.vendor.example/notes/index")
		if !result.Allowed {
			t.Fatalf("userinfo URL blocked: %s", result.Reason)
		}
	})
}

func TestIssuerSentStaleTunnel(t *testing.T) {
	p, cfg := newSentIssuerProxy(t)
	pinned := p.issuerCookieRuntime.Load()
	if pinned == nil || pinned.query == nil {
		t.Fatal("positive control: issuer runtime missing")
	}
	ic := &InterceptContext{
		Proxy:         p,
		Config:        cfg,
		Agent:         "mail-agent",
		ClientIP:      "127.0.0.1",
		ActorAuth:     envelope.ActorAuthBound,
		IssuerRuntime: pinned,
	}
	// An enabled reload keeps the query store and publishes a new runtime
	// pointer. Tunnels admitted before the reload keep the old pointer.
	p.issuerCookieRuntime.Store(&issuerCookieRuntime{cfg: cfg, store: pinned.store, query: pinned.query})
	if ic.issuerQueryStore() != nil {
		t.Fatal("positive control: pinned runtime still matches")
	}
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, origin.String(), strings.NewReader(agentBlob))
	recordIssuerRequestSent(ic, req, []byte(agentBlob))
	session := sessionKeyFor(cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
	live := p.issuerCookieRuntime.Load().query
	now := time.Now()
	live.mintServerID(session, origin, agentBlob, now)
	if live.serverIDIssued(session, origin, agentBlob) {
		t.Fatal("a value sent on a stale tunnel was minted")
	}
	live.mintServerID(session, origin, serverIDListed, now)
	if !live.serverIDIssued(session, origin, serverIDListed) {
		t.Fatal("stale-tunnel recording tainted the session or blocked a value it did not send")
	}
}

// A tunnel admitted while the feature was off keeps forwarding after a reload
// turns it on. Its sends must reach the live store, or a value it carried
// could later mint as an ID.
func TestIssuerSentTunnelOpenedWhileDisabled(t *testing.T) {
	p, cfg := newSentIssuerProxy(t)
	off := *cfg
	off.RequestBodyScanning.IssuerBoundSessionCookies = false
	if issuerCookieEnabled(&off) {
		t.Fatal("positive control: disabling the setting did not disable the feature")
	}
	ic := &InterceptContext{
		Proxy:     p,
		Config:    &off,
		Agent:     "mail-agent",
		ClientIP:  "127.0.0.1",
		ActorAuth: envelope.ActorAuthBound,
	}
	if ic.issuerQueryStore() != nil {
		t.Fatal("positive control: a tunnel with the feature off saw the store")
	}
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, origin.String(), strings.NewReader(agentBlob))
	recordIssuerRequestSent(ic, req, []byte(agentBlob))
	session := sessionKeyFor(cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
	live := p.issuerCookieRuntime.Load().query
	live.mintServerID(session, origin, agentBlob, time.Now())
	if live.serverIDIssued(session, origin, agentBlob) {
		t.Fatal("a value sent on a tunnel opened while the feature was off was minted")
	}
}

func TestIssuerSentMultipartAndChunkedBody(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s := newTestServerIDStore(t)
	multipart := "--bound\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n" + agentBlob + "\r\n--bound--\r\n"
	s.recordSent("a", origin, nil, []byte(multipart), true, now)
	s.mintServerID("a", origin, agentBlob, now)
	if s.serverIDIssued("a", origin, agentBlob) {
		t.Fatal("a multipart field was minted")
	}

	var delivered string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		delivered = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader(agentBlob))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1 // force chunked transfer
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if delivered != agentBlob {
		t.Fatalf("chunked body delivered as %q", delivered)
	}
}
