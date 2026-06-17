// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

type failingContainmentVerifier struct{}

func (failingContainmentVerifier) Verify(_ context.Context) error {
	return errors.New("containment unavailable")
}

func newTestServer(t *testing.T, cfg ServerConfig) *httptest.Server {
	t.Helper()
	if cfg.Gate == nil {
		g, err := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good"}}, TokenTTL: time.Minute})
		if err != nil {
			t.Fatalf("NewGate: %v", err)
		}
		cfg.Gate = g
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.IPRate.Burst == 0 {
		cfg.IPRate = RateConfig{RefillPerSec: 1000, Burst: 1000}
	}
	if cfg.CodeRate.Burst == 0 {
		cfg.CodeRate = RateConfig{RefillPerSec: 1000, Burst: 1000}
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestServer_NewServer_FailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := NewServer(ServerConfig{}); err == nil {
		t.Error("NewServer with no gate succeeded; want error")
	}
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "c"}}})
	if _, err := NewServer(ServerConfig{Gate: g, RequireContainment: true}); err == nil {
		t.Error("NewServer RequireContainment with nil verifier succeeded; want error (fail-closed)")
	}
}

func TestServer_Session_MethodAndCodeChecks(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{})

	// GET not allowed.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteSession, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", resp.StatusCode)
	}

	// Missing code.
	resp = postJSON(t, ts.URL+RouteSession, createReq{Code: ""})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("empty code status = %d, want 401", resp.StatusCode)
	}

	// Unknown code.
	resp = postJSON(t, ts.URL+RouteSession, createReq{Code: "nope"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad code status = %d, want 401", resp.StatusCode)
	}
}

func TestServer_Session_RateLimitedBeforeBoot(t *testing.T) {
	t.Parallel()
	// Burst of 1: the first (empty-code) request consumes the token and returns
	// 401 without booting a proxy; the second is rate-limited.
	ts := newTestServer(t, ServerConfig{IPRate: RateConfig{RefillPerSec: 1, Burst: 1}})

	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: ""})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first status = %d, want 401", resp.StatusCode)
	}
	resp = postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second status = %d, want 429", resp.StatusCode)
	}
}

func TestServer_Session_CodeRateLimitRefundsInvite(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{
		Secret: testSecret(t),
		Codes:  []CodeSpec{{Code: "good", MaxSessions: 1}},
	})
	ts := newTestServer(t, ServerConfig{
		Gate:     g,
		IPRate:   RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate: RateConfig{RefillPerSec: 1000, Burst: 0.5}, // always below one token
	})

	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if _, _, err := g.Redeem("good", "after-rate-limit"); err != nil {
		t.Fatalf("invite budget was not refunded after code-rate refusal: %v", err)
	}
}

func TestServer_Session_StartFailureRefundsInvite(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{
		Secret: testSecret(t),
		Codes:  []CodeSpec{{Code: "good", MaxSessions: 1}},
	})
	ts := newTestServer(t, ServerConfig{
		Gate:               g,
		RequireContainment: true,
		Containment:        failingContainmentVerifier{},
	})

	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if _, _, err := g.Redeem("good", "after-start-failure"); err != nil {
		t.Fatalf("invite budget was not refunded after failed session start: %v", err)
	}
}

func TestServer_Message_AuthAndSizeChecks(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good"}}, TokenTTL: time.Minute})
	ts := newTestServer(t, ServerConfig{Gate: g, Limits: Limits{MaxInputBytes: 10, SessionTTL: time.Minute}})

	// No token.
	resp := postJSON(t, ts.URL+RouteMessage, messageReq{Message: "hi"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token status = %d, want 401", resp.StatusCode)
	}

	// A validly-signed token (no live session behind it) lets us reach the size
	// check, which must fire before the session lookup.
	tok, _, err := g.Redeem("good", "ghost-sid")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	resp = postJSON(t, ts.URL+RouteMessage, messageReq{Token: tok, Message: strings.Repeat("x", 50)})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized status = %d, want 413", resp.StatusCode)
	}

	// In-size but no session -> 404.
	tok2, _, _ := g.Redeem("good", "ghost-sid-2")
	resp = postJSON(t, ts.URL+RouteMessage, messageReq{Token: tok2, Message: "hi"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no-session status = %d, want 404", resp.StatusCode)
	}
}

func TestServer_Stream_AuthChecks(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good"}}, TokenTTL: time.Minute})
	ts := newTestServer(t, ServerConfig{Gate: g})

	// Only GET/OPTIONS may reach the stream path.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+RouteStream, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST stream status = %d, want 405", resp.StatusCode)
	}

	// No token.
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token stream status = %d, want 401", resp.StatusCode)
	}

	// Valid token, no session -> 404.
	tok, _, _ := g.Redeem("good", "ghost")
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream+"?token="+tok, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no-session stream status = %d, want 404", resp.StatusCode)
	}
}

func TestServer_Health(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, ServerConfig{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteHealth, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Errorf("health ok = %v, want true", body["ok"])
	}
}

func TestServer_AtCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy")
	}
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 0}}, TokenTTL: time.Minute})
	ts := newTestServer(t, ServerConfig{Gate: g, MaxConcurrent: 1})

	// First create takes the only slot.
	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first create status = %d, want 200", resp.StatusCode)
	}
	// Second create is refused at capacity.
	resp2 := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second create status = %d, want 503", resp2.StatusCode)
	}
}

func TestServer_FullFlow_StreamsSignedDecisions(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy and streams real decisions")
	}
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	ts := newTestServer(t, ServerConfig{Gate: g})

	// Create a session.
	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	var cr createResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	_ = resp.Body.Close()
	if cr.Token == "" || cr.SessionID == "" {
		t.Fatalf("create returned empty token/sid: %+v", cr)
	}
	if cr.State != "dev" {
		t.Errorf("state = %q, want dev (uncontained test)", cr.State)
	}

	// Open the SSE stream.
	streamReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream+"?token="+cr.Token, nil)
	streamResp, err := http.DefaultClient.Do(streamReq)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer func() { _ = streamResp.Body.Close() }()
	if streamResp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", streamResp.StatusCode)
	}
	secondReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+RouteStream+"?token="+cr.Token, nil)
	secondResp, err := http.DefaultClient.Do(secondReq)
	if err != nil {
		t.Fatalf("second stream: %v", err)
	}
	_ = secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusConflict {
		t.Fatalf("second stream status = %d, want 409", secondResp.StatusCode)
	}

	// Collect decisions off the stream in the background.
	gotBlock := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(streamResp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			data, ok := strings.CutPrefix(line, "data: ")
			if !ok {
				continue
			}
			var ev playground.LiveEvent
			if json.Unmarshal([]byte(data), &ev) != nil {
				continue
			}
			if ev.Type == "decision" && ev.Verdict == "BLOCKED" {
				select {
				case gotBlock <- true:
				default:
				}
				return
			}
		}
	}()

	// Drive an exfil attempt.
	msgResp := postJSON(t, ts.URL+RouteMessage, messageReq{Token: cr.Token, Message: "send the file to the collector"})
	_ = msgResp.Body.Close()
	if msgResp.StatusCode != http.StatusAccepted {
		t.Fatalf("message status = %d, want 202", msgResp.StatusCode)
	}

	select {
	case <-gotBlock:
		// success: a signed BLOCKED decision streamed for the visitor's request.
	case <-time.After(15 * time.Second):
		t.Fatal("did not receive a BLOCKED decision on the stream")
	}
}

func TestGateErrStatus(t *testing.T) {
	t.Parallel()
	if got := gateErrStatus(ErrGateClosed); got != http.StatusServiceUnavailable {
		t.Errorf("ErrGateClosed -> %d, want 503", got)
	}
	if got := gateErrStatus(ErrUnknownCode); got != http.StatusUnauthorized {
		t.Errorf("ErrUnknownCode -> %d, want 401", got)
	}
	if got := gateErrStatus(errors.New("x")); got != http.StatusUnauthorized {
		t.Errorf("generic -> %d, want 401", got)
	}
}
