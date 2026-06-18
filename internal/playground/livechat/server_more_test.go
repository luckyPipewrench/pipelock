// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServer_Message_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteMessage, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET message status = %d, want 405", resp.StatusCode)
	}
}

func TestServer_Stream_RateLimitedBeforeTokenValidation(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{IPRate: RateConfig{RefillPerSec: 1, Burst: 1}})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first stream status = %d, want 401", resp.StatusCode)
	}

	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second stream status = %d, want 429", resp.StatusCode)
	}
}

func TestServer_Message_CodeRateLimited(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good"}}, TokenTTL: time.Minute})
	// Code-rate burst of 1; IP-rate generous so the IP limiter is not the gate.
	ts := newTestServer(t, ServerConfig{
		Gate:     g,
		IPRate:   RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate: RateConfig{RefillPerSec: 1, Burst: 1},
		Limits:   Limits{MaxInputBytes: 100, SessionTTL: time.Minute},
	})
	tok, _, _ := g.Redeem("good", "ghost")

	// First message consumes the single code token; no session -> 404.
	resp := postJSON(t, ts.URL+RouteMessage, messageReq{Token: tok, Message: "hi"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("first message status = %d, want 404", resp.StatusCode)
	}
	// Second message from the same code is rate-limited before lookup.
	resp = postJSON(t, ts.URL+RouteMessage, messageReq{Token: tok, Message: "hi"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second message status = %d, want 429", resp.StatusCode)
	}
}

func TestServer_CORSAndForwardedFor(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{
		AllowOrigin:       "https://pipelab.org",
		TrustForwardedFor: true,
	})

	// A bad-code session POST still runs setCORS and clientIP(XFF) before failing.
	b := `{"code":"nope"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+RouteSession, strings.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://pipelab.org" {
		t.Errorf("ACAO = %q, want https://pipelab.org", got)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestServer_CORSPreflight(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{AllowOrigin: "https://pipelab.org"})

	for _, route := range []string{RouteMessage, RouteHealth} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, ts.URL+route, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s preflight status = %d, want 204", route, resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
			t.Errorf("%s methods = %q, want GET, POST, OPTIONS", route, got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "Content-Type" {
			t.Errorf("%s headers = %q, want Content-Type", route, got)
		}
	}
}

func TestServer_Session_BadJSON(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+RouteSession, strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad-json status = %d, want 400", resp.StatusCode)
	}
}

func TestServer_Session_RejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+RouteSession, strings.NewReader(`{"code":"good"} {}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("trailing-json status = %d, want 400", resp.StatusCode)
	}
}
