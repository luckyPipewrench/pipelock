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
	t             *testing.T
	token         string
	sessionID     string
	expiresAt     time.Time
	sessionCodes  chan string
	messages      chan string
	streamStarted chan struct{}
	streamRelease chan struct{}
	bundleStatus  int
	server        *httptest.Server
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
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(vm.bundleStatus)
		_, _ = w.Write([]byte("bundle-" + vm.token))
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
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("empty-code status = %d, want 403", resp.StatusCode)
		}
		status, _ := postBrokerSession(t, ts)
		if status != http.StatusOK {
			t.Fatalf("valid code after empty-code rejection = %d, want 200", status)
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
