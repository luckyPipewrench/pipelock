// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

const (
	brokerTestCode     = "outer-code"
	brokerTestImage    = "registry.example/playground:test"
	brokerTestState    = "contained"
	brokerTestCapacity = 4
)

type serverFakeProvider struct {
	mu          sync.Mutex
	targets     []string
	created     []MachineSpec
	destroyed   []string
	createErr   error
	waitErr     error
	destroyedCh chan string
}

type serverFakeHumanVerifier struct {
	mu     sync.Mutex
	err    error
	tokens []string
	ips    []string
}

func (v *serverFakeHumanVerifier) Verify(_ context.Context, token, remoteIP string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tokens = append(v.tokens, token)
	v.ips = append(v.ips, remoteIP)
	return v.err
}

func (v *serverFakeHumanVerifier) calls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.tokens)
}

func (v *serverFakeHumanVerifier) setErr(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.err = err
}

func (p *serverFakeProvider) CreateMachine(_ context.Context, spec MachineSpec) (*Machine, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.createErr != nil {
		return nil, p.createErr
	}
	if len(p.targets) == 0 {
		return nil, errors.New("no fake VM target")
	}
	target := p.targets[0]
	p.targets = p.targets[1:]
	id := fmt.Sprintf("vm-%d", len(p.created)+1)
	p.created = append(p.created, spec)
	return &Machine{ID: id, State: "started", PrivateIP: target}, nil
}

func (p *serverFakeProvider) WaitReady(_ context.Context, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waitErr
}

func (p *serverFakeProvider) DestroyMachine(_ context.Context, id string) error {
	p.mu.Lock()
	p.destroyed = append(p.destroyed, id)
	ch := p.destroyedCh
	p.mu.Unlock()
	if ch != nil {
		select {
		case ch <- id:
		default:
		}
	}
	return nil
}

func (p *serverFakeProvider) ListManagedMachines(_ context.Context) ([]Machine, error) {
	return nil, nil
}

func (p *serverFakeProvider) createdCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.created)
}

func (p *serverFakeProvider) destroyedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.destroyed)
}

func (p *serverFakeProvider) createdEnv(index int) map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.created[index].Env
}

type fakeVM struct {
	t               *testing.T
	token           string
	sessionID       string
	expiresAt       time.Time
	sessionCodes    chan string
	messages        chan string
	streamStarted   chan struct{}
	streamRelease   chan struct{}
	bundleStatus    int
	rawBundleStatus int
	bundleHits      atomic.Int32
	// bundleHold, when non-nil, blocks a bundle response whose os matches
	// bundleHoldOS until the channel is closed; bundleHeld signals (once) that
	// such a request has reached the block. Used to drive concurrent-download
	// race tests deterministically.
	bundleHoldOS string
	bundleHold   chan struct{}
	bundleHeld   chan struct{}
	server       *httptest.Server
}

func newFakeVM(t *testing.T, token string) *fakeVM {
	t.Helper()
	vm := &fakeVM{
		t:             t,
		token:         token,
		sessionID:     "sid-" + token,
		expiresAt:     time.Now().Add(time.Minute).UTC(),
		sessionCodes:  make(chan string, 4),
		messages:      make(chan string, 4),
		streamStarted: make(chan struct{}),
		streamRelease: make(chan struct{}),
		bundleStatus:  http.StatusOK,
	}
	vm.server = httptest.NewServer(http.HandlerFunc(vm.handle))
	t.Cleanup(vm.server.Close)
	return vm
}

func (vm *fakeVM) targetHost(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(vm.server.URL)
	if err != nil {
		t.Fatalf("parse fake VM URL: %v", err)
	}
	return u.Host
}

func (vm *fakeVM) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case livechat.RouteSession:
		var req sessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBrokerErr(w, http.StatusBadRequest, "bad session request")
			return
		}
		vm.sessionCodes <- req.Code
		writeBrokerJSON(w, http.StatusOK, vmSessionResponse{
			Token:     vm.token,
			SessionID: vm.sessionID,
			ExpiresAt: vm.expiresAt.Format(time.RFC3339Nano),
			State:     brokerTestState,
		})
	case livechat.RouteMessage:
		var req struct {
			Token   string `json:"token"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBrokerErr(w, http.StatusBadRequest, "bad message")
			return
		}
		if req.Token != vm.token {
			writeBrokerErr(w, http.StatusForbidden, "wrong VM")
			return
		}
		vm.messages <- req.Message
		writeBrokerJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	case livechat.RouteStream:
		if r.URL.Query().Get("token") != vm.token {
			writeBrokerErr(w, http.StatusForbidden, "wrong VM")
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeBrokerErr(w, http.StatusInternalServerError, "streaming unsupported")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "data: {\"phase\":\"first\"}\n\n")
		flusher.Flush()
		close(vm.streamStarted)
		select {
		case <-vm.streamRelease:
		case <-r.Context().Done():
		}
		_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
		flusher.Flush()
	case livechat.RouteBundle:
		if r.URL.Query().Get("token") != vm.token {
			writeBrokerErr(w, http.StatusForbidden, "wrong VM")
			return
		}
		vm.bundleHits.Add(1)
		osParam := r.URL.Query().Get("os")
		if vm.bundleHold != nil && osParam == vm.bundleHoldOS {
			if vm.bundleHeld != nil {
				select {
				case vm.bundleHeld <- struct{}{}:
				default:
				}
			}
			<-vm.bundleHold
		}
		status := vm.bundleStatus
		if osParam == "" && vm.rawBundleStatus != 0 {
			status = vm.rawBundleStatus
		}
		if osParam != "" {
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "kit-"+osParam+".zip"))
			w.WriteHeader(status)
			_, _ = w.Write([]byte("kit-" + osParam + "-" + vm.token))
		} else {
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "bundle.tar.gz"))
			w.WriteHeader(status)
			_, _ = w.Write([]byte("bundle-" + vm.token))
		}
	default:
		writeBrokerErr(w, http.StatusNotFound, "not found")
	}
}

func newBrokerTestServer(t *testing.T, provider *serverFakeProvider, cfg ServerConfig) (*Server, *httptest.Server) {
	t.Helper()
	gate, err := livechat.NewGate(livechat.GateConfig{
		Secret:   testBrokerSecret(),
		Codes:    []livechat.CodeSpec{{Code: brokerTestCode}},
		TokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    provider,
		Concurrency: livechat.NewConcurrencyLimiter(brokerTestCapacity),
		Image:       brokerTestImage,
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}
	cfg.Leases = lm
	cfg.Gate = gate
	if cfg.IPRate.Burst == 0 {
		cfg.IPRate = livechat.RateConfig{RefillPerSec: 1000, Burst: 1000}
	}
	if cfg.CodeRate.Burst == 0 {
		cfg.CodeRate = livechat.RateConfig{RefillPerSec: 1000, Burst: 1000}
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})
	return srv, ts
}

func testBrokerSecret() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func testBrokerGate(t *testing.T) *livechat.Gate {
	t.Helper()
	gate, err := livechat.NewGate(livechat.GateConfig{
		Secret:   testBrokerSecret(),
		Codes:    []livechat.CodeSpec{{Code: brokerTestCode}},
		TokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return gate
}

func testLeaseManager(t *testing.T, provider MachineProvider) *LeaseManager {
	t.Helper()
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    provider,
		Concurrency: livechat.NewConcurrencyLimiter(brokerTestCapacity),
		Image:       brokerTestImage,
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}
	return lm
}

func postBrokerSession(t *testing.T, ts *httptest.Server) (int, vmSessionResponse) {
	t.Helper()
	resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{Code: brokerTestCode})
	defer func() { _ = resp.Body.Close() }()
	var body vmSessionResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode session response: %v", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode, body
}

func postBrokerMessage(t *testing.T, ts *httptest.Server, token, msg string) *http.Response {
	t.Helper()
	return postBrokerJSON(t, ts.URL+livechat.RouteMessage, map[string]string{"token": token, "message": msg})
}

func postBrokerJSON(t *testing.T, rawURL string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func getBroker(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func expectDestroyed(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fake VM destroy")
	}
}

func TestNewServerValidationDefaultsAndClose(t *testing.T) {
	provider := &serverFakeProvider{}
	lm := testLeaseManager(t, provider)
	gate := testBrokerGate(t)
	if _, err := NewServer(ServerConfig{Gate: gate}); err == nil {
		t.Fatal("missing lease manager should error")
	}
	if _, err := NewServer(ServerConfig{Leases: lm}); err == nil {
		t.Fatal("missing gate should error")
	}
	if _, err := NewServer(ServerConfig{Leases: lm, Gate: gate, DeadlineGrace: -1}); err == nil {
		t.Fatal("negative deadline grace should error")
	}
	if _, err := NewServer(ServerConfig{Leases: lm, Gate: gate, PerIPDailyBudget: -1}); err == nil {
		t.Fatal("negative daily budget should error")
	}

	customClient := &http.Client{}
	srv, err := NewServer(ServerConfig{Leases: lm, Gate: gate, HTTPClient: customClient})
	if err != nil {
		t.Fatalf("NewServer defaults: %v", err)
	}
	if srv.cfg.InternalPort != defaultInternalPort {
		t.Fatalf("InternalPort = %d, want default %d", srv.cfg.InternalPort, defaultInternalPort)
	}
	if srv.cfg.ReapInterval != defaultReapInterval {
		t.Fatalf("ReapInterval = %s, want %s", srv.cfg.ReapInterval, defaultReapInterval)
	}
	if srv.client != customClient {
		t.Fatal("custom HTTP client was not preserved")
	}
	if srv.vmReadyTimeout != defaultVMReadyTimeout {
		t.Fatalf("vmReadyTimeout = %s, want %s", srv.vmReadyTimeout, defaultVMReadyTimeout)
	}
	srv.Close()
	srv.Close()
}

func TestServerHealthCORSKillAndResume(t *testing.T) {
	vm := newFakeVM(t, "health-token")
	destroyed := make(chan string, 1)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{
		AllowOrigin:        "https://playground.pipelab.org",
		TrustForwardedFor:  true,
		GlobalDailyBudget:  3,
		PerIPDailyBudget:   3,
		PerCodeDailyBudget: 3,
		DeadlineGrace:      time.Second,
		VMReadyTimeout:     time.Second,
	})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions, ts.URL+livechat.RouteHealth, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("health OPTIONS: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("health OPTIONS = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://playground.pipelab.org" {
		t.Fatalf("CORS origin = %q", got)
	}

	req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+livechat.RouteHealth, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("health POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("health POST = %d, want 405", resp.StatusCode)
	}
	health := getBrokerHealth(t, ts)
	if got := health["session_starts_last_minute"]; got != float64(0) {
		t.Fatalf("session_starts_last_minute before session = %v, want 0", got)
	}

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}
	health = getBrokerHealth(t, ts)
	if got := health["session_starts_last_minute"]; got != float64(1) {
		t.Fatalf("session_starts_last_minute after session = %v, want 1", got)
	}
	if got := srv.clientIP(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)); got == "" {
		t.Fatal("clientIP should fall back to RemoteAddr")
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.4")
	if got := srv.clientIP(req); got != "203.0.113.7" {
		t.Fatalf("clientIP forwarded = %q", got)
	}

	srv.Kill()
	if !srv.Killed() {
		t.Fatal("Kill did not set killed state")
	}
	expectDestroyed(t, destroyed)
	resp = postBrokerMessage(t, ts, session.Token, "after kill")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("message after kill = %d, want fail-closed", resp.StatusCode)
	}
	status, _ = postBrokerSession(t, ts)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("session while killed = %d, want 503", status)
	}
	srv.Resume()
	if srv.Killed() {
		t.Fatal("Resume did not clear killed state")
	}
}

func getBrokerHealth(t *testing.T, ts *httptest.Server) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+livechat.RouteHealth, nil)
	if err != nil {
		t.Fatalf("new health request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("health GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health GET status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	return body
}

// TestServer_DefaultCodeFallback proves the human-gated code-optional path:
// with a DefaultCode configured, a session request carrying NO invite code falls
// back to the default and succeeds (the human gate is the authorization), and
// health advertises code_required=false. Without a DefaultCode an empty code is
// still rejected.
func TestServer_DefaultCodeFallback(t *testing.T) {
	t.Run("empty code uses default when configured", func(t *testing.T) {
		vm := newFakeVM(t, "vm-default-token")
		provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{DefaultCode: brokerTestCode})

		resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{Code: ""})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("empty code with DefaultCode = %d, want 200", resp.StatusCode)
		}
		if health := getBrokerHealth(t, ts); health["code_required"] != false {
			t.Fatalf("code_required = %v, want false when DefaultCode set", health["code_required"])
		}
	})
	t.Run("empty code rejected without default", func(t *testing.T) {
		provider := &serverFakeProvider{}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{})
		resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{Code: ""})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("empty code without DefaultCode = %d, want 401", resp.StatusCode)
		}
		if health := getBrokerHealth(t, ts); health["code_required"] != true {
			t.Fatalf("code_required = %v, want true", health["code_required"])
		}
	})
	t.Run("default code still requires human verifier before lease", func(t *testing.T) {
		vm := newFakeVM(t, "vm-default-human-token")
		provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
		verifier := &serverFakeHumanVerifier{err: errors.New("missing human proof")}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{
			DefaultCode:       brokerTestCode,
			HumanVerifier:     verifier,
			GlobalDailyBudget: 1,
		})

		resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{Code: ""})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("empty code without human proof = %d, want 403", resp.StatusCode)
		}
		if got := verifier.calls(); got != 1 {
			t.Fatalf("verifier calls = %d, want 1", got)
		}
		if got := provider.createdCount(); got != 0 {
			t.Fatalf("created machines = %d, want 0 before human proof", got)
		}

		verifier.setErr(nil)
		resp = postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{
			Code:           "",
			TurnstileToken: "human-token",
		})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("empty code with human proof after failed attempt = %d, want 200", resp.StatusCode)
		}
		if got := provider.createdCount(); got != 1 {
			t.Fatalf("created machines = %d, want 1 after human proof", got)
		}
	})
}

func TestServer_EndToEndProxyAndRelease(t *testing.T) {
	vm := newFakeVM(t, "vm-token-a")
	destroyed := make(chan string, 4)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{
		SessionEnv: map[string]string{"PLAYGROUND_MODEL_" + "KEY": "model-test-key"},
	})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}
	if session.Token != vm.token || session.SessionID != vm.sessionID {
		t.Fatalf("unexpected session response: %+v", session)
	}
	select {
	case code := <-vm.sessionCodes:
		if code == "" || code == brokerTestCode {
			t.Fatalf("VM code = %q, want fresh code distinct from public invite", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VM did not receive session create")
	}
	env := provider.createdEnv(0)
	if env[envVMInviteCode] == "" || env[envVMInviteCode] == brokerTestCode {
		t.Fatalf("lease env did not carry fresh VM invite: %q", env[envVMInviteCode])
	}
	if env["PLAYGROUND_MODEL_"+"KEY"] != "model-test-key" {
		t.Fatal("session model key env was not passed to the lease")
	}

	msgResp := postBrokerMessage(t, ts, session.Token, "hello")
	_ = msgResp.Body.Close()
	if msgResp.StatusCode != http.StatusAccepted {
		t.Fatalf("message status = %d, want 202", msgResp.StatusCode)
	}
	select {
	case got := <-vm.messages:
		if got != "hello" {
			t.Fatalf("VM message = %q, want hello", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VM did not receive message")
	}

	streamResp := getBroker(t, ts.URL+livechat.RouteStream+"?token="+url.QueryEscape(session.Token))
	defer func() { _ = streamResp.Body.Close() }()
	if streamResp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", streamResp.StatusCode)
	}
	lineCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(streamResp.Body).ReadString('\n')
		lineCh <- line
	}()
	select {
	case line := <-lineCh:
		if !strings.HasPrefix(line, "data: ") {
			t.Fatalf("first stream line = %q, want data event", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream event was buffered until close")
	}
	select {
	case <-vm.streamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("VM stream did not start")
	}
	close(vm.streamRelease)

	bundleResp := getBroker(t, ts.URL+livechat.RouteBundle+"?token="+url.QueryEscape(session.Token))
	body, err := io.ReadAll(bundleResp.Body)
	_ = bundleResp.Body.Close()
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if bundleResp.StatusCode != http.StatusOK || string(body) != "bundle-"+vm.token {
		t.Fatalf("bundle status/body = %d %q, want 200 bundle", bundleResp.StatusCode, body)
	}
	expectDestroyed(t, destroyed)
	if got := srv.cfg.Leases.ActiveLeases(); got != 0 {
		t.Fatalf("active leases = %d, want 0 after bundle", got)
	}

	unknown := postBrokerMessage(t, ts, "forged", "nope")
	_ = unknown.Body.Close()
	if unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token status = %d, want 404", unknown.StatusCode)
	}
}

func TestServerRouteRejectionsAndTokenHelpers(t *testing.T) {
	vm := newFakeVM(t, "route-token")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	for _, path := range []string{livechat.RouteSession, livechat.RouteStream, livechat.RouteMessage, livechat.RouteBundle} {
		t.Run("options_"+path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions, ts.URL+path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("OPTIONS %s = %d, want 204", path, resp.StatusCode)
			}
		})
	}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: livechat.RouteSession},
		{method: http.MethodPost, path: livechat.RouteStream},
		{method: http.MethodGet, path: livechat.RouteMessage},
		{method: http.MethodPost, path: livechat.RouteBundle},
	} {
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tc.method, ts.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s = %d, want 405", tc.method, tc.path, resp.StatusCode)
			}
		})
	}

	resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, map[string]string{"code": brokerTestCode, "extra": "nope"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("session with unknown field = %d, want 400", resp.StatusCode)
	}
	resp = postBrokerJSON(t, ts.URL+livechat.RouteMessage, map[string]string{"token": "missing", "message": "x", "extra": "nope"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("message with unknown field = %d, want 400", resp.StatusCode)
	}
	missingTokenQuery := url.Values{}
	missingTokenQuery.Set("tok"+"en", "missing")
	resp = getBroker(t, ts.URL+livechat.RouteStream+"?"+missingTokenQuery.Encode())
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown stream token = %d, want 404", resp.StatusCode)
	}
	resp = getBroker(t, ts.URL+livechat.RouteBundle+"?"+missingTokenQuery.Encode())
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown bundle token = %d, want 404", resp.StatusCode)
	}

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}
	if !srv.registerToken("manual", &tokenLease{token: "manual", sessionKey: "manual-session", lease: &Lease{Machine: &Machine{ID: "m", PrivateIP: vm.targetHost(t)}}, deadline: time.Now().Add(time.Minute)}) {
		t.Fatal("manual token registration failed")
	}
	if srv.registerToken("manual", &tokenLease{}) {
		t.Fatal("duplicate token registration should fail")
	}
	srv.releaseToken(context.Background(), "does-not-exist")
	srv.Close()
	if srv.registerToken("after-close", &tokenLease{}) {
		t.Fatal("registerToken after Close should fail")
	}
	_ = session
}

func TestServer_FailClosedBadVMSessionResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp vmSessionResponse
	}{
		{
			name: "missing_token",
			resp: vmSessionResponse{SessionID: "sid", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)},
		},
		{
			name: "already_expired",
			resp: vmSessionResponse{Token: "expired", SessionID: "sid", ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vmsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != livechat.RouteSession {
					writeBrokerErr(w, http.StatusNotFound, "not found")
					return
				}
				writeBrokerJSON(w, http.StatusOK, tc.resp)
			}))
			t.Cleanup(vmsrv.Close)
			u, err := url.Parse(vmsrv.URL)
			if err != nil {
				t.Fatalf("parse vm url: %v", err)
			}
			destroyed := make(chan string, 1)
			provider := &serverFakeProvider{targets: []string{u.Host}, destroyedCh: destroyed}
			_, ts := newBrokerTestServer(t, provider, ServerConfig{})
			status, _ := postBrokerSession(t, ts)
			if status != http.StatusServiceUnavailable {
				t.Fatalf("session status = %d, want 503", status)
			}
			expectDestroyed(t, destroyed)
		})
	}
}

func TestServer_DuplicateVMTokenFailsClosed(t *testing.T) {
	const dupToken = "duplicate-token"
	var calls atomic.Int32
	vmsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != livechat.RouteSession {
			writeBrokerErr(w, http.StatusNotFound, "not found")
			return
		}
		call := calls.Add(1)
		writeBrokerJSON(w, http.StatusOK, vmSessionResponse{
			Token:     dupToken,
			SessionID: fmt.Sprintf("sid-%d", call),
			ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(vmsrv.Close)
	u, err := url.Parse(vmsrv.URL)
	if err != nil {
		t.Fatalf("parse vm url: %v", err)
	}
	destroyed := make(chan string, 2)
	provider := &serverFakeProvider{targets: []string{u.Host, u.Host}, destroyedCh: destroyed}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, first := postBrokerSession(t, ts)
	if status != http.StatusOK || first.Token != dupToken {
		t.Fatalf("first session = %d %+v, want duplicate token accepted once", status, first)
	}
	status, _ = postBrokerSession(t, ts)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("second duplicate-token session = %d, want 503", status)
	}
	expectDestroyed(t, destroyed)
}

func TestServer_BundlePartialContentDoesNotReleaseLease(t *testing.T) {
	vm := newFakeVM(t, "vm-token-partial")
	vm.bundleStatus = http.StatusPartialContent
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}
	resp := getBroker(t, ts.URL+livechat.RouteBundle+"?token="+url.QueryEscape(session.Token))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("bundle status = %d, want 206", resp.StatusCode)
	}
	if got := srv.cfg.Leases.ActiveLeases(); got != 1 {
		t.Fatalf("active leases = %d, want lease retained after partial bundle", got)
	}
}

func TestServer_TokenIsolation(t *testing.T) {
	vmA := newFakeVM(t, "vm-token-a")
	vmB := newFakeVM(t, "vm-token-b")
	provider := &serverFakeProvider{targets: []string{vmA.targetHost(t), vmB.targetHost(t)}}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{})

	_, sessionA := postBrokerSession(t, ts)
	_, sessionB := postBrokerSession(t, ts)
	if sessionA.Token == sessionB.Token {
		t.Fatal("fake VMs returned duplicate tokens")
	}

	resp := postBrokerMessage(t, ts, sessionA.Token, "for A only")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("message status = %d, want 202", resp.StatusCode)
	}
	select {
	case got := <-vmA.messages:
		if got != "for A only" {
			t.Fatalf("VM A got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VM A did not receive its token-routed message")
	}
	select {
	case got := <-vmB.messages:
		t.Fatalf("VM B received another session's message: %q", got)
	default:
	}
}

func TestServer_FailClosedCapacityAndLeaseErrors(t *testing.T) {
	t.Run("at_capacity", func(t *testing.T) {
		vm := newFakeVM(t, "cap-token")
		provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
		gate, err := livechat.NewGate(livechat.GateConfig{
			Secret:   testBrokerSecret(),
			Codes:    []livechat.CodeSpec{{Code: brokerTestCode}},
			TokenTTL: time.Minute,
		})
		if err != nil {
			t.Fatalf("NewGate: %v", err)
		}
		lm, err := NewLeaseManager(LeaseConfig{
			Provider:    provider,
			Concurrency: livechat.NewConcurrencyLimiter(1),
			Image:       brokerTestImage,
		})
		if err != nil {
			t.Fatalf("NewLeaseManager: %v", err)
		}
		srv, err := NewServer(ServerConfig{
			Leases:   lm,
			Gate:     gate,
			IPRate:   livechat.RateConfig{RefillPerSec: 1000, Burst: 1000},
			CodeRate: livechat.RateConfig{RefillPerSec: 1000, Burst: 1000},
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(func() {
			ts.Close()
			srv.Close()
		})
		status, _ := postBrokerSession(t, ts)
		if status != http.StatusOK {
			t.Fatalf("first session status = %d, want 200", status)
		}
		status, _ = postBrokerSession(t, ts)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("second session status = %d, want 503 at capacity", status)
		}
	})

	t.Run("create_failure_refunds_gate_and_budgets", func(t *testing.T) {
		vm := newFakeVM(t, "after-failure")
		provider := &serverFakeProvider{
			targets:   []string{vm.targetHost(t)},
			createErr: errors.New("create failed"),
		}
		gate, err := livechat.NewGate(livechat.GateConfig{
			Secret:   testBrokerSecret(),
			Codes:    []livechat.CodeSpec{{Code: brokerTestCode, MaxSessions: 1}},
			TokenTTL: time.Minute,
		})
		if err != nil {
			t.Fatalf("NewGate: %v", err)
		}
		lm, err := NewLeaseManager(LeaseConfig{
			Provider:    provider,
			Concurrency: livechat.NewConcurrencyLimiter(1),
			Image:       brokerTestImage,
		})
		if err != nil {
			t.Fatalf("NewLeaseManager: %v", err)
		}
		srv, err := NewServer(ServerConfig{
			Leases:             lm,
			Gate:               gate,
			IPRate:             livechat.RateConfig{RefillPerSec: 1000, Burst: 1000},
			CodeRate:           livechat.RateConfig{RefillPerSec: 1000, Burst: 1000},
			PerIPDailyBudget:   1,
			PerCodeDailyBudget: 1,
			GlobalDailyBudget:  1,
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(func() {
			ts.Close()
			srv.Close()
		})

		status, _ := postBrokerSession(t, ts)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("create failure status = %d, want 503", status)
		}
		if got := lm.ActiveLeases(); got != 0 {
			t.Fatalf("active leases after create failure = %d, want 0", got)
		}
		if got := provider.createdCount(); got != 0 {
			t.Fatalf("created machines = %d, want 0 after create error", got)
		}

		provider.mu.Lock()
		provider.createErr = nil
		provider.mu.Unlock()
		status, _ = postBrokerSession(t, ts)
		if status != http.StatusOK {
			t.Fatalf("retry after refunded failure status = %d, want 200", status)
		}
	})

	t.Run("wait_failure_destroys_machine", func(t *testing.T) {
		vm := newFakeVM(t, "wait-fails")
		destroyed := make(chan string, 1)
		provider := &serverFakeProvider{
			targets:     []string{vm.targetHost(t)},
			waitErr:     errors.New("not ready"),
			destroyedCh: destroyed,
		}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{})
		status, _ := postBrokerSession(t, ts)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("wait failure status = %d, want 503", status)
		}
		expectDestroyed(t, destroyed)
		if got := provider.destroyedCount(); got != 1 {
			t.Fatalf("destroyed count = %d, want 1", got)
		}
	})
}

func TestServer_AbuseControlsReject(t *testing.T) {
	t.Run("per_ip_rate", func(t *testing.T) {
		vm := newFakeVM(t, "ip-rate-a")
		provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{
			IPRate: livechat.RateConfig{RefillPerSec: 1, Burst: 1},
		})
		status, _ := postBrokerSession(t, ts)
		if status != http.StatusOK {
			t.Fatalf("first status = %d, want 200", status)
		}
		status, _ = postBrokerSession(t, ts)
		if status != http.StatusTooManyRequests {
			t.Fatalf("second status = %d, want 429", status)
		}
	})

	t.Run("per_code_rate", func(t *testing.T) {
		vm := newFakeVM(t, "code-rate-a")
		provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{
			CodeRate: livechat.RateConfig{RefillPerSec: 1, Burst: 1},
		})
		status, _ := postBrokerSession(t, ts)
		if status != http.StatusOK {
			t.Fatalf("first status = %d, want 200", status)
		}
		status, _ = postBrokerSession(t, ts)
		if status != http.StatusTooManyRequests {
			t.Fatalf("second status = %d, want 429", status)
		}
	})

	t.Run("empty_code_does_not_consume_code_rate", func(t *testing.T) {
		vm := newFakeVM(t, "empty-code-rate")
		provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{
			CodeRate: livechat.RateConfig{RefillPerSec: 1, Burst: 1},
		})
		resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{Code: ""})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("empty-code status = %d, want 401", resp.StatusCode)
		}
		status, _ := postBrokerSession(t, ts)
		if status != http.StatusOK {
			t.Fatalf("valid code after empty-code rejection = %d, want 200", status)
		}
	})

	t.Run("unknown_code_spray_does_not_fill_code_rate_keys", func(t *testing.T) {
		vm := newFakeVM(t, "unknown-code-rate")
		provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
		_, ts := newBrokerTestServer(t, provider, ServerConfig{
			DefaultCode: brokerTestCode,
			CodeRate:    livechat.RateConfig{RefillPerSec: 1000, Burst: 1000, MaxKeys: 1},
		})
		resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{Code: "attacker-random-code"})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unknown-code status = %d, want 401", resp.StatusCode)
		}
		resp = postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{Code: ""})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("default code after unknown-code spray = %d, want 200", resp.StatusCode)
		}
		if got := provider.createdCount(); got != 1 {
			t.Fatalf("created machines = %d, want only the default-code session", got)
		}
	})

	tests := []struct {
		name       string
		cfg        ServerConfig
		wantStatus int
	}{
		{name: "per_ip_budget", cfg: ServerConfig{PerIPDailyBudget: 1}, wantStatus: http.StatusTooManyRequests},
		{name: "per_code_budget", cfg: ServerConfig{PerCodeDailyBudget: 1}, wantStatus: http.StatusTooManyRequests},
		{name: "global_budget", cfg: ServerConfig{GlobalDailyBudget: 1}, wantStatus: http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vmA := newFakeVM(t, tc.name+"-a")
			vmB := newFakeVM(t, tc.name+"-b")
			provider := &serverFakeProvider{targets: []string{vmA.targetHost(t), vmB.targetHost(t)}}
			_, ts := newBrokerTestServer(t, provider, tc.cfg)
			status, _ := postBrokerSession(t, ts)
			if status != http.StatusOK {
				t.Fatalf("first status = %d, want 200", status)
			}
			status, _ = postBrokerSession(t, ts)
			if status != tc.wantStatus {
				t.Fatalf("second status = %d, want %d", status, tc.wantStatus)
			}
			if got := provider.createdCount(); got != 1 {
				t.Fatalf("budget rejection created %d machines, want only the first", got)
			}
		})
	}
}

func TestServer_RejectsURLShapedMachinePrivateIP(t *testing.T) {
	destroyed := make(chan string, 1)
	provider := &serverFakeProvider{
		targets:     []string{"http://169.254.169.254"},
		destroyedCh: destroyed,
	}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{})
	status, _ := postBrokerSession(t, ts)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("session status = %d, want 503", status)
	}
	expectDestroyed(t, destroyed)
	if got := provider.createdCount(); got != 1 {
		t.Fatalf("created machines = %d, want 1 failed lease", got)
	}
}

func TestServer_ReaperReleasesExpiredLease(t *testing.T) {
	vm := newFakeVM(t, "reap-token")
	vm.expiresAt = time.Now().Add(100 * time.Millisecond).UTC()
	destroyed := make(chan string, 1)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{ReapInterval: 10 * time.Millisecond})
	status, _ := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}
	expectDestroyed(t, destroyed)
	if got := srv.cfg.Leases.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after reaper = %d, want 0", got)
	}
}

func TestServerDirectHelpers(t *testing.T) {
	host, err := targetHost("fdaa:0:1::3", 9090)
	if err != nil {
		t.Fatalf("targetHost IPv6: %v", err)
	}
	if host != "[fdaa:0:1::3]:9090" {
		t.Fatalf("targetHost IPv6 = %q", host)
	}
	if host, err := targetHost("10.0.0.2:8081", 0); err != nil || host != "10.0.0.2:8081" {
		t.Fatalf("targetHost hostport = %q err=%v", host, err)
	}
	if _, err := targetHost("", 8080); err == nil {
		t.Fatal("empty private IP should error")
	}
	if got := gateStatus(livechat.ErrGateClosed); got != http.StatusServiceUnavailable {
		t.Fatalf("gateStatus closed = %d", got)
	}
	if got := gateStatus(errors.New("bad code")); got != http.StatusUnauthorized {
		t.Fatalf("gateStatus other = %d", got)
	}
	if got := codeKey("same"); got != codeKey("same") || got == codeKey("different") {
		t.Fatalf("codeKey should be stable and code-specific")
	}
	if key, err := newBrokerSessionKey(); err != nil || len(key) != 32 {
		t.Fatalf("newBrokerSessionKey = %q err=%v", key, err)
	}

	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, err := rec.Write([]byte("hello")); err != nil {
		t.Fatalf("statusRecorder Write: %v", err)
	}
	if rec.status != http.StatusOK {
		t.Fatalf("statusRecorder status = %d, want 200", rec.status)
	}
	rec.Flush()
	if rec.Unwrap() == nil {
		t.Fatal("statusRecorder unwrap is nil")
	}
}

// flakyRoundTripper fails the first failFirst round trips with a pre-response
// transport error (modelling a VM that has booted but is not yet accepting
// connections while it completes its fail-closed containment proof), then
// delegates to base. It exercises the broker's VM session-create readiness
// retry.
type flakyRoundTripper struct {
	base      http.RoundTripper
	failFirst int

	mu    sync.Mutex
	calls int
}

func (f *flakyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls++
	failNow := f.calls <= f.failFirst
	f.mu.Unlock()
	if failNow {
		return nil, errors.New("dial tcp: connect: connection refused")
	}
	return f.base.RoundTrip(req)
}

func (f *flakyRoundTripper) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// TestServer_CreateVMSession_RetriesWhileVMBooting proves the broker retries the
// VM session-create across the boot window — a leased VM reports "started"
// before its server listens, because the fail-closed boot gate proves
// containment first. Without the retry every session 503s.
func TestServer_CreateVMSession_RetriesWhileVMBooting(t *testing.T) {
	vm := newFakeVM(t, "boot-token")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	rt := &flakyRoundTripper{base: http.DefaultTransport, failFirst: 2}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{
		HTTPClient:     &http.Client{Transport: rt},
		VMReadyTimeout: 10 * time.Second,
	})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200 (broker must retry across the VM boot window)", status)
	}
	if session.Token != vm.token {
		t.Fatalf("session token = %q, want %q", session.Token, vm.token)
	}
	if got := rt.callCount(); got < 3 {
		t.Fatalf("round trips = %d, want >= 3 (2 connection-refused + 1 success)", got)
	}
	if got := provider.createdCount(); got != 1 {
		t.Fatalf("machines created = %d, want 1", got)
	}
	if got := provider.destroyedCount(); got != 0 {
		t.Fatalf("machines destroyed = %d, want 0 (the session is live)", got)
	}
}

// TestServer_CreateVMSession_HTTPErrorNotRetried proves the broker does NOT
// retry once the VM server returns an HTTP response, even an error status. The
// VM invite code is single-use, so retrying a request the server already
// processed could double-spend it or mask a real rejection.
func TestServer_CreateVMSession_HTTPErrorNotRetried(t *testing.T) {
	var calls atomic.Int32
	vmsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == livechat.RouteSession {
			calls.Add(1)
			writeBrokerErr(w, http.StatusInternalServerError, "boom")
			return
		}
		writeBrokerErr(w, http.StatusNotFound, "not found")
	}))
	t.Cleanup(vmsrv.Close)
	u, err := url.Parse(vmsrv.URL)
	if err != nil {
		t.Fatalf("parse vm url: %v", err)
	}
	destroyed := make(chan string, 1)
	provider := &serverFakeProvider{targets: []string{u.Host}, destroyedCh: destroyed}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{VMReadyTimeout: 5 * time.Second})

	status, _ := postBrokerSession(t, ts)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("session status = %d, want 503", status)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("VM session-create calls = %d, want 1 (an HTTP error must not be retried)", got)
	}
	select {
	case <-destroyed:
	case <-time.After(2 * time.Second):
		t.Fatal("VM was not destroyed after a failed session create (must fail closed)")
	}
}

// TestServer_CreateVMSession_ReadyTimeoutFailsClosed proves a VM that never
// starts listening is bounded by VMReadyTimeout and torn down: the broker gives
// up, returns 503, and destroys the leased machine rather than leaking it.
func TestServer_CreateVMSession_ReadyTimeoutFailsClosed(t *testing.T) {
	vm := newFakeVM(t, "never-ready")
	rt := &flakyRoundTripper{base: http.DefaultTransport, failFirst: 1 << 30}
	destroyed := make(chan string, 1)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{
		HTTPClient:     &http.Client{Transport: rt},
		VMReadyTimeout: 700 * time.Millisecond,
	})

	start := time.Now()
	status, _ := postBrokerSession(t, ts)
	elapsed := time.Since(start)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("session status = %d, want 503", status)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("session create took %s, want bounded by VMReadyTimeout", elapsed)
	}
	select {
	case <-destroyed:
	case <-time.After(2 * time.Second):
		t.Fatal("VM was not destroyed after readiness timeout (must fail closed)")
	}
}

func TestServer_AttemptVMSessionResponseErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "bad_json",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`not-json`))
			},
		},
		{
			name: "bad_expiry",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeBrokerJSON(w, http.StatusOK, vmSessionResponse{Token: "t", SessionID: "s", ExpiresAt: "tomorrow"})
			},
		},
		{
			name: "duplicate_token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				expires := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
				_, _ = fmt.Fprintf(w, `{"token":"first","token":"second","session_id":"s","expires_at":%q}`, expires)
			},
		},
		{
			name: "oversized_valid_prefix",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				expires := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
				_, _ = fmt.Fprintf(w, `{"token":"t","session_id":"s","expires_at":%q}`, expires)
				_, _ = io.WriteString(w, strings.Repeat(" ", maxBrokerBodyBytes)+`X`)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vmsrv := httptest.NewServer(tc.handler)
			t.Cleanup(vmsrv.Close)
			srv, err := NewServer(ServerConfig{Leases: testLeaseManager(t, &serverFakeProvider{}), Gate: testBrokerGate(t)})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			t.Cleanup(srv.Close)
			_, _, retryable, err := srv.attemptVMSession(context.Background(), vmsrv.URL, []byte(`{"code":"x"}`))
			if err == nil {
				t.Fatal("attemptVMSession should error")
			}
			if retryable {
				t.Fatal("HTTP response errors must not be retryable")
			}
		})
	}
}

func TestServer_HumanVerifierBeforeLease(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "turnstile-ok")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	verifier := &serverFakeHumanVerifier{}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{HumanVerifier: verifier})

	resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{
		Code:           brokerTestCode,
		TurnstileToken: "human-token",
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status = %d, want 200", resp.StatusCode)
	}
	if got := verifier.calls(); got != 1 {
		t.Fatalf("verifier calls = %d, want 1", got)
	}
	if got := provider.createdCount(); got != 1 {
		t.Fatalf("created machines = %d, want 1", got)
	}
}

func TestServer_HumanVerifierRejectsBeforeLease(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "turnstile-reject")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	verifier := &serverFakeHumanVerifier{err: errors.New("not human")}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{HumanVerifier: verifier})

	resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{
		Code:           brokerTestCode,
		TurnstileToken: "bad-token",
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("session status = %d, want 403", resp.StatusCode)
	}
	if got := provider.createdCount(); got != 0 {
		t.Fatalf("created machines = %d, want 0", got)
	}
}

func TestServer_GlobalBudgetClosedBeforeHumanVerifier(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "global-before-human-a")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	verifier := &serverFakeHumanVerifier{}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{
		HumanVerifier:     verifier,
		GlobalDailyBudget: 1,
	})

	status, _ := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("first status = %d, want 200", status)
	}
	if got := verifier.calls(); got != 1 {
		t.Fatalf("human verifier calls after first session = %d, want 1", got)
	}

	resp := postBrokerJSON(t, ts.URL+livechat.RouteSession, sessionRequest{
		Code:           brokerTestCode,
		TurnstileToken: "second-token",
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d, want 503", resp.StatusCode)
	}
	if got := verifier.calls(); got != 1 {
		t.Fatalf("human verifier calls after exhausted global budget = %d, want 1", got)
	}
	if got := provider.createdCount(); got != 1 {
		t.Fatalf("created machines = %d, want 1", got)
	}
}

func TestServer_RegisterTokenRefusedAfterKill(t *testing.T) {
	t.Parallel()
	provider := &serverFakeProvider{}
	srv, _ := newBrokerTestServer(t, provider, ServerConfig{})

	// A session-create that registers its token AFTER a pause must be refused, or
	// its VM survives the kill switch (fail-open emergency stop).
	srv.Kill()
	if srv.registerToken("late-token", &tokenLease{token: "late-token", sessionKey: "sk"}) {
		t.Fatal("registerToken succeeded after Kill: in-flight session would survive the pause")
	}

	// Resume must restore normal registration.
	srv.Resume()
	if !srv.registerToken("ok-token", &tokenLease{token: "ok-token", sessionKey: "sk2"}) {
		t.Fatal("registerToken refused after Resume")
	}
}

func TestServer_OversizeMessageReturns413(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "oversize-token")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	// Send a message body larger than maxBrokerBodyBytes (64 KiB).
	oversizePayload := `{"token":"` + session.Token + `","message":"` + strings.Repeat("x", maxBrokerBodyBytes+1) + `"}`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+livechat.RouteMessage, strings.NewReader(oversizePayload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize message status = %d, want 413", resp.StatusCode)
	}
}

func TestServer_HealthDoesNotOverclaimContainment(t *testing.T) {
	t.Parallel()
	provider := &serverFakeProvider{}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+livechat.RouteHealth, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if _, present := body["contained"]; present {
		t.Fatal("health must not report a constant 'contained' field the broker cannot prove")
	}
}

// --- Artifact cache tests ---

func TestArtifactCache_GetPutEvictTTL(t *testing.T) {
	t.Parallel()
	c := newArtifactCache(50 * time.Millisecond)

	key := artifactCacheKey{token: "t1", os: ""}
	if got := c.get(key); got != nil {
		t.Fatal("get on empty cache should return nil")
	}

	entry := &artifactCacheEntry{
		body:               []byte("hello"),
		contentType:        "application/gzip",
		contentDisposition: "attachment",
		insertedAt:         time.Now(),
	}
	c.put(key, entry)
	if got := c.get(key); got == nil || string(got.body) != "hello" {
		t.Fatalf("get after put = %v, want hello", got)
	}

	// Wait for TTL to expire, then verify eviction on read.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.get(key) == nil {
			return // evicted as expected
		}
	}
	t.Fatal("entry did not expire after TTL")
}

func TestArtifactCache_CapEvictsOldest(t *testing.T) {
	t.Parallel()
	c := newArtifactCache(time.Minute)

	// Fill to capacity.
	for i := range maxArtifactCacheEntries {
		k := artifactCacheKey{token: fmt.Sprintf("t%d", i), os: ""}
		c.put(k, &artifactCacheEntry{
			body:       []byte(fmt.Sprintf("body%d", i)),
			insertedAt: time.Now(),
		})
	}
	if c.len() != maxArtifactCacheEntries {
		t.Fatalf("cache len = %d, want %d", c.len(), maxArtifactCacheEntries)
	}

	// One more should evict the oldest (t0).
	c.put(artifactCacheKey{token: "overflow", os: ""}, &artifactCacheEntry{
		body:       []byte("new"),
		insertedAt: time.Now(),
	})
	if c.len() != maxArtifactCacheEntries {
		t.Fatalf("cache len after overflow = %d, want %d", c.len(), maxArtifactCacheEntries)
	}
	// The oldest entry should be gone.
	if got := c.get(artifactCacheKey{token: "t0", os: ""}); got != nil {
		t.Fatal("oldest entry should have been evicted")
	}
}

// TestServer_BundleRedownloadAfterVMTeardown proves the core durability fix:
// after the first successful bundle download releases the VM, a second download
// (browser retry, double-click) succeeds from the broker's artifact cache.
func TestServer_BundleRedownloadAfterVMTeardown(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "redownload-token")
	destroyed := make(chan string, 4)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	// First download: fetches from VM, caches, releases VM.
	bundleURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token)
	resp1 := getBroker(t, bundleURL)
	body1, err := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if err != nil {
		t.Fatalf("read first bundle: %v", err)
	}
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first bundle status = %d, want 200", resp1.StatusCode)
	}
	if string(body1) != "bundle-"+vm.token {
		t.Fatalf("first bundle body = %q, want %q", body1, "bundle-"+vm.token)
	}

	// VM should be destroyed after first download.
	expectDestroyed(t, destroyed)
	if got := srv.cfg.Leases.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after first download = %d, want 0", got)
	}

	// Second download: VM is gone, but the cache serves it.
	resp2 := getBroker(t, bundleURL)
	body2, err := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if err != nil {
		t.Fatalf("read second bundle: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second bundle status = %d, want 200 (cache hit after VM teardown)", resp2.StatusCode)
	}
	if string(body2) != string(body1) {
		t.Fatalf("second bundle body differs from first: %q vs %q", body2, body1)
	}

	// The VM should have been hit exactly once (not on the second download).
	if got := vm.bundleHits.Load(); got != 1 {
		t.Fatalf("VM bundle hits = %d, want 1 (second download should be a cache hit)", got)
	}
}

// TestServer_BundleKitThenRawBothSucceed proves the prefetch-raw behavior:
// downloading a verify-kit (os=linux) also prefetches the raw bundle into the
// cache, so a subsequent raw download succeeds even after VM teardown.
func TestServer_BundleKitThenRawBothSucceed(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "kit-raw-token")
	destroyed := make(chan string, 4)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	// Download the verify kit (os=linux).
	kitURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token) + "&os=linux"
	kitResp := getBroker(t, kitURL)
	kitBody, err := io.ReadAll(kitResp.Body)
	_ = kitResp.Body.Close()
	if err != nil {
		t.Fatalf("read kit: %v", err)
	}
	if kitResp.StatusCode != http.StatusOK {
		t.Fatalf("kit status = %d, want 200", kitResp.StatusCode)
	}
	if !strings.HasPrefix(string(kitBody), "kit-linux-") {
		t.Fatalf("kit body = %q, want kit-linux-* prefix", kitBody)
	}

	// VM should be destroyed.
	expectDestroyed(t, destroyed)

	// Now download the raw bundle. VM is gone, but prefetch should have cached it.
	rawURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token)
	rawResp := getBroker(t, rawURL)
	rawBody, err := io.ReadAll(rawResp.Body)
	_ = rawResp.Body.Close()
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if rawResp.StatusCode != http.StatusOK {
		t.Fatalf("raw bundle status = %d, want 200 (prefetched into cache)", rawResp.StatusCode)
	}
	if string(rawBody) != "bundle-"+vm.token {
		t.Fatalf("raw bundle body = %q, want %q", rawBody, "bundle-"+vm.token)
	}

	// The VM should have been hit exactly twice: once for the kit, once for
	// the raw prefetch.
	if got := vm.bundleHits.Load(); got != 2 {
		t.Fatalf("VM bundle hits = %d, want 2 (kit + raw prefetch)", got)
	}

	srv.mu.Lock()
	fetchMuLen := len(srv.fetchMu)
	srv.mu.Unlock()
	if fetchMuLen != 0 {
		t.Fatalf("fetch mutex entries after bundle downloads = %d, want 0", fetchMuLen)
	}
}

func TestServer_BundleKitRawPrefetchFailureRetainsVM(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "raw-prefetch-fail-token")
	vm.rawBundleStatus = http.StatusServiceUnavailable
	destroyed := make(chan string, 4)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	kitURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token) + "&os=linux"
	kitResp := getBroker(t, kitURL)
	_, _ = io.ReadAll(kitResp.Body)
	_ = kitResp.Body.Close()
	if kitResp.StatusCode != http.StatusOK {
		t.Fatalf("kit status = %d, want 200", kitResp.StatusCode)
	}

	select {
	case id := <-destroyed:
		t.Fatalf("VM %s was destroyed even though raw prefetch failed", id)
	default:
	}
	if got := srv.cfg.Leases.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after raw prefetch failure = %d, want 1", got)
	}

	// Once the raw bundle can be fetched, the token seals and the VM releases.
	vm.rawBundleStatus = 0
	rawURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token)
	rawResp := getBroker(t, rawURL)
	_, _ = io.ReadAll(rawResp.Body)
	_ = rawResp.Body.Close()
	if rawResp.StatusCode != http.StatusOK {
		t.Fatalf("raw bundle status after retry = %d, want 200", rawResp.StatusCode)
	}
	expectDestroyed(t, destroyed)
}

func TestServer_BundleRejectsInvalidOSBeforeVMFetch(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "bad-os-token")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	badURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token) + "&os=plan9"
	resp := getBroker(t, badURL)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad os bundle status = %d, want 400", resp.StatusCode)
	}
	if got := vm.bundleHits.Load(); got != 0 {
		t.Fatalf("VM bundle hits after bad os = %d, want 0", got)
	}

	srv.mu.Lock()
	fetchMuLen := len(srv.fetchMu)
	srv.mu.Unlock()
	if fetchMuLen != 0 {
		t.Fatalf("fetch mutex entries after bad os = %d, want 0", fetchMuLen)
	}
	if got := srv.cfg.Leases.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after bad os = %d, want 1", got)
	}
}

// TestServer_BundleConcurrentVariantsHoldVMUntilAllDone proves the per-token
// in-flight refcount: a fast variant (the raw bundle) completing while a slow
// variant (an OS kit) is still being fetched must NOT release/destroy the VM.
// Pre-fix, the fast download's eager releaseToken destroyed the VM mid-fetch of
// the kit, reproducing the intermittent "download failed" bug under
// double-clicks, two tabs, or raw+kit clicked together.
func TestServer_BundleConcurrentVariantsHoldVMUntilAllDone(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "concurrent-token")
	vm.bundleHoldOS = "linux"
	vm.bundleHold = make(chan struct{})
	vm.bundleHeld = make(chan struct{}, 1)
	var releaseOnce sync.Once
	releaseHold := func() { releaseOnce.Do(func() { close(vm.bundleHold) }) }
	// Always release the held VM handler, even if the test fails early, so
	// httptest.Server.Close() (which waits for outstanding requests) cannot hang.
	t.Cleanup(releaseHold)
	destroyed := make(chan string, 4)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}, destroyedCh: destroyed}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	kitURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token) + "&os=linux"
	rawURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token)

	// Start the slow kit download; it blocks inside the VM fetch. Read+close the
	// body inside the goroutine so the response is consumed (and bodyclose-clean).
	type kitResult struct {
		status int
		body   string
	}
	kitDone := make(chan kitResult, 1)
	go func() {
		resp := getBroker(t, kitURL)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		kitDone <- kitResult{status: resp.StatusCode, body: string(b)}
	}()

	// Wait until the kit fetch has actually reached the VM (in-flight).
	select {
	case <-vm.bundleHeld:
	case <-time.After(2 * time.Second):
		t.Fatal("kit fetch never reached the VM")
	}

	// While the kit is still in-flight, the fast raw download completes.
	rawResp := getBroker(t, rawURL)
	rawBody, _ := io.ReadAll(rawResp.Body)
	_ = rawResp.Body.Close()
	if rawResp.StatusCode != http.StatusOK {
		t.Fatalf("raw status = %d, want 200", rawResp.StatusCode)
	}
	if string(rawBody) != "bundle-"+vm.token {
		t.Fatalf("raw body = %q, want %q", rawBody, "bundle-"+vm.token)
	}

	// The VM must STILL be leased: the kit download is in-flight, so the fast
	// raw download must not have released it.
	if got := srv.cfg.Leases.ActiveLeases(); got != 1 {
		t.Fatalf("active leases while kit in-flight = %d, want 1 (VM must be held)", got)
	}

	// Release the kit fetch; as the last in-flight request it releases the VM.
	releaseHold()
	kit := <-kitDone
	if kit.status != http.StatusOK {
		t.Fatalf("kit status = %d, want 200", kit.status)
	}
	if !strings.HasPrefix(kit.body, "kit-linux-") {
		t.Fatalf("kit body = %q, want kit-linux-* prefix", kit.body)
	}

	// Now the VM is released exactly once, after both downloads finished.
	expectDestroyed(t, destroyed)
	if got := srv.cfg.Leases.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after both downloads = %d, want 0", got)
	}
}

func TestServer_BundleFailedConcurrentWaveRetainsVMForRetry(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	const token = "retry-token"

	srv.bundleEnter(token)
	srv.bundleEnter(token)
	srv.bundleSeal(token)
	srv.bundleMarkFailed(token)

	if srv.bundleLeave(token) {
		t.Fatal("first leave released VM while another artifact fetch was in-flight")
	}
	if srv.bundleLeave(token) {
		t.Fatal("failed concurrent artifact wave released VM; want retained for retry")
	}

	srv.bundleEnter(token)
	srv.bundleSeal(token)
	if !srv.bundleLeave(token) {
		t.Fatal("successful retry after failed wave did not release VM")
	}
}

// TestServer_BundleConcurrentIdenticalCoalesced proves the per-(token, os) fetch
// lock: two concurrent identical kit downloads result in exactly ONE VM fetch of
// that variant (the follower reads the cache the leader populated), so N
// concurrent identical downloads cannot each pull a full kit into memory.
func TestServer_BundleConcurrentIdenticalCoalesced(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "coalesce-token")
	vm.bundleHoldOS = "linux"
	vm.bundleHold = make(chan struct{})
	vm.bundleHeld = make(chan struct{}, 1)
	var releaseOnce sync.Once
	releaseHold := func() { releaseOnce.Do(func() { close(vm.bundleHold) }) }
	t.Cleanup(releaseHold)
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}
	kitURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token) + "&os=linux"

	type res struct {
		status int
		body   string
	}
	run := func() res {
		resp := getBroker(t, kitURL)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return res{resp.StatusCode, string(b)}
	}
	r1 := make(chan res, 1)
	r2 := make(chan res, 1)
	go func() { r1 <- run() }() // leader: blocks at the VM, holding the fetch lock
	select {
	case <-vm.bundleHeld:
	case <-time.After(2 * time.Second):
		t.Fatal("first kit fetch never reached the VM")
	}
	go func() { r2 <- run() }() // follower: blocks on the per-variant fetch lock
	releaseHold()
	for _, rr := range []res{<-r1, <-r2} {
		if rr.status != http.StatusOK {
			t.Fatalf("kit status = %d, want 200", rr.status)
		}
		if !strings.HasPrefix(rr.body, "kit-linux-") {
			t.Fatalf("kit body = %q, want kit-linux-* prefix", rr.body)
		}
	}
	// The kit was fetched from the VM exactly once; the extra hit is the raw
	// prefetch. Pre-fix (no coalescing) the follower would fetch a second kit.
	if got := vm.bundleHits.Load(); got != 2 {
		t.Fatalf("VM bundle hits = %d, want 2 (1 kit + 1 raw prefetch; coalesced)", got)
	}
}

// TestArtifactCache_ByteAccounting proves the cache tracks total bytes across
// put/overwrite/expire so the byte budget can bound worst-case memory.
func TestArtifactCache_ByteAccounting(t *testing.T) {
	t.Parallel()
	c := newArtifactCache(time.Minute)
	k1 := artifactCacheKey{token: "t", os: "linux"}
	k2 := artifactCacheKey{token: "t", os: ""}
	c.put(k1, &artifactCacheEntry{body: make([]byte, 100), insertedAt: time.Now()})
	c.put(k2, &artifactCacheEntry{body: make([]byte, 50), insertedAt: time.Now()})
	if got := c.bytesLen(); got != 150 {
		t.Fatalf("curBytes = %d, want 150", got)
	}
	// Overwriting a key adjusts the byte total, not double-counts.
	c.put(k1, &artifactCacheEntry{body: make([]byte, 300), insertedAt: time.Now()})
	if got := c.bytesLen(); got != 350 {
		t.Fatalf("curBytes after overwrite = %d, want 350", got)
	}
	// Evicting an expired entry on get decrements the total.
	exp := newArtifactCache(time.Nanosecond)
	exp.put(k1, &artifactCacheEntry{body: make([]byte, 200), insertedAt: time.Now().Add(-time.Hour)})
	if exp.get(k1) != nil {
		t.Fatal("expired entry should be evicted on get")
	}
	if got := exp.bytesLen(); got != 0 {
		t.Fatalf("curBytes after expired-get = %d, want 0", got)
	}
}

// TestServer_BundleVM503DoesNotReleaseVM proves that a 503 from the VM (seal
// failure) is propagated to the client and the VM is NOT released, so the
// client can retry while the VM still lives.
func TestServer_BundleVM503DoesNotReleaseVM(t *testing.T) {
	t.Parallel()
	vm := newFakeVM(t, "vm-503-token")
	vm.bundleStatus = http.StatusServiceUnavailable
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	bundleURL := ts.URL + livechat.RouteBundle + "?token=" + url.QueryEscape(session.Token)
	resp := getBroker(t, bundleURL)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// The non-200 should be propagated and the lease should be retained.
	if got := srv.cfg.Leases.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after VM 503 = %d, want 1 (VM not released)", got)
	}
	if got := srv.bundleCache.len(); got != 0 {
		t.Fatalf("cache len after VM 503 = %d, want 0 (failed fetch must not cache)", got)
	}
}

// TestServer_BundleOversizedDoesNotCache proves that an oversized artifact
// body does not poison the cache and does not release the VM.
func TestServer_BundleOversizedDoesNotCache(t *testing.T) {
	t.Parallel()
	// Create a VM that returns a body exceeding maxArtifactBytes.
	oversizeBody := strings.Repeat("x", maxArtifactBytes+1)
	vmsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case livechat.RouteSession:
			writeBrokerJSON(w, http.StatusOK, vmSessionResponse{
				Token:     "oversize-tok",
				SessionID: "sid-oversize",
				ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
			})
		case livechat.RouteBundle:
			w.Header().Set("Content-Type", "application/gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, oversizeBody)
		default:
			writeBrokerErr(w, http.StatusNotFound, "not found")
		}
	}))
	t.Cleanup(vmsrv.Close)
	u, err := url.Parse(vmsrv.URL)
	if err != nil {
		t.Fatalf("parse vm url: %v", err)
	}
	provider := &serverFakeProvider{targets: []string{u.Host}}
	srv, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, _ := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	resp := getBroker(t, ts.URL+livechat.RouteBundle+"?token="+url.QueryEscape("oversize-tok"))
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// The oversize body should result in a 502 error (fetch failure).
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("oversize bundle status = %d, want 502", resp.StatusCode)
	}
	if got := srv.bundleCache.len(); got != 0 {
		t.Fatalf("cache len after oversize = %d, want 0", got)
	}
	if got := srv.cfg.Leases.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after oversize = %d, want 1 (VM not released on fetch error)", got)
	}
}
