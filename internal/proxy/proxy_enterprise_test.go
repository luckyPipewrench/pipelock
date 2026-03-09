// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: ELv2

//go:build enterprise

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"

	_ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
)

const (
	testAgentPermissive  = "permissive-agent"
	testAgentRestrictive = "restrictive-agent"
)

// --- Agent Identification Tests (Enterprise) ---
//
// These tests require the enterprise edition because agent name extraction
// from headers/query params requires the enterprise ResolveAgent.

func TestFetchEndpoint_AgentHeader(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
	req.Header.Set(AgentHeader, "test-bot")
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if resp.Agent != "test-bot" {
		t.Errorf("expected agent=test-bot, got %q", resp.Agent)
	}
}

func TestFetchEndpoint_AgentQueryParam(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text&agent=query-agent", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if resp.Agent != "query-agent" {
		t.Errorf("expected agent=query-agent, got %q", resp.Agent)
	}
}

func TestFetchEndpoint_AgentOnBlocked(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest(http.MethodGet, "/fetch?url=https://pastebin.com/raw/abc", nil)
	req.Header.Set(AgentHeader, "blocked-agent")
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if resp.Agent != "blocked-agent" {
		t.Errorf("expected agent=blocked-agent on blocked response, got %q", resp.Agent)
	}
	if !resp.Blocked {
		t.Error("expected blocked=true")
	}
}

// --- Agent Registry Integration Tests (Enterprise) ---
//
// These tests require the enterprise edition (per-agent configs, budgets,
// listeners) and are gated behind the "enterprise" build tag.

// TestFetchEndpoint_PerAgentScanner verifies that requests with different
// X-Pipelock-Agent headers use per-agent config and scanner. The permissive
// agent's config allowlists the test backend, while the restrictive agent's
// strict-mode config does not, causing its requests to be blocked.
func TestFetchEndpoint_PerAgentScanner(t *testing.T) {
	// Create a backend that returns plain text.
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	defer backend.Close()

	// Extract backend hostname (IP only, no port) for allowlisting.
	// The scanner checks parsed.Hostname() which strips the port.
	backendHostPort := strings.TrimPrefix(backend.URL, "http://")
	backendHost, _, _ := net.SplitHostPort(backendHostPort)

	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Internal = nil // disable SSRF for test backend on 127.0.0.1
	cfg.APIAllowlist = nil
	// Base mode is balanced (permissive by default).
	cfg.Mode = config.ModeBalanced

	// Configure two agent profiles with different modes:
	// - permissive-agent: strict mode BUT allowlists the backend host
	// - restrictive-agent: strict mode with NO allowlist (blocks everything)
	cfg.Agents = map[string]config.AgentProfile{
		testAgentPermissive: {
			Mode:         config.ModeStrict,
			APIAllowlist: []string{backendHost},
		},
		testAgentRestrictive: {
			Mode:         config.ModeStrict,
			APIAllowlist: []string{"only-this-domain.example.com"},
		},
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	handler := p.Handler()

	tests := []struct {
		name       string
		agentHdr   string
		wantStatus int
		wantBlock  bool
	}{
		{
			name:       "permissive agent allows backend",
			agentHdr:   testAgentPermissive,
			wantStatus: http.StatusOK,
			wantBlock:  false,
		},
		{
			name:       "restrictive agent blocks backend",
			agentHdr:   testAgentRestrictive,
			wantStatus: http.StatusForbidden,
			wantBlock:  true,
		},
		{
			name:       "anonymous uses base config (balanced, allows)",
			agentHdr:   "",
			wantStatus: http.StatusOK,
			wantBlock:  false,
		},
		{
			name:       "unknown agent falls back to base config",
			agentHdr:   "unknown-agent",
			wantStatus: http.StatusOK,
			wantBlock:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
			if tt.agentHdr != "" {
				req.Header.Set(AgentHeader, tt.agentHdr)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}

			var resp FetchResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("invalid JSON response: %v", err)
			}
			if resp.Blocked != tt.wantBlock {
				t.Errorf("blocked = %v, want %v (reason: %s)", resp.Blocked, tt.wantBlock, resp.BlockReason)
			}
		})
	}
}

// TestFetchEndpoint_PerAgentScanner_AgentInResponse verifies the agent name
// appears in the fetch response JSON when per-agent resolution is active.
func TestFetchEndpoint_PerAgentScanner_AgentInResponse(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Internal = nil
	cfg.APIAllowlist = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	handler := p.Handler()

	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
	req.Header.Set(AgentHeader, "my-test-agent")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Agent != "my-test-agent" {
		t.Errorf("agent = %q, want %q", resp.Agent, "my-test-agent")
	}
}

// TestProxy_Reload_RebuildRegistry verifies that Reload rebuilds the agent
// registry so that per-agent config changes take effect.
func TestProxy_Reload_RebuildRegistry(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	backendHostPort := strings.TrimPrefix(backend.URL, "http://")
	backendHost, _, _ := net.SplitHostPort(backendHostPort)

	// Start with no agent profiles.
	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Internal = nil
	cfg.APIAllowlist = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	handler := p.Handler()

	// Before reload: request from "strict-bot" should succeed (no profiles, fallback is balanced).
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
	req.Header.Set(AgentHeader, "strict-bot")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("before reload: expected 200, got %d", w.Code)
	}

	// Reload with a strict profile that blocks the backend.
	cfg2 := config.Defaults()
	cfg2.FetchProxy.TimeoutSeconds = 5
	cfg2.Internal = nil
	cfg2.APIAllowlist = nil
	cfg2.Agents = map[string]config.AgentProfile{
		"strict-bot": {
			Mode:         config.ModeStrict,
			APIAllowlist: []string{"other.example.com"},
		},
	}
	// Also allowlist the backend in base so anonymous still works.
	cfg2.APIAllowlist = []string{backendHost}

	sc2 := scanner.New(cfg2)
	p.Reload(cfg2, sc2)

	// After reload: "strict-bot" should be blocked (strict + no backend in allowlist).
	req2 := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
	req2.Header.Set(AgentHeader, "strict-bot")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("after reload: expected 403 for strict-bot, got %d (body: %s)", w2.Code, w2.Body.String())
	}
}

// TestProxy_KnownProfiles verifies the knownProfiles helper returns the
// correct set of profile names.
func TestProxy_KnownProfiles(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {Mode: config.ModeStrict},
		"agent-b": {Mode: config.ModeAudit},
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	profiles := p.knownProfiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(profiles), profiles)
	}
	if !profiles["agent-a"] {
		t.Error("expected agent-a in knownProfiles")
	}
	if !profiles["agent-b"] {
		t.Error("expected agent-b in knownProfiles")
	}
}

// TestAgentIdentityEndToEnd exercises per-agent scanner behavior through the
// fetch proxy. Two agent profiles are configured: "strict-agent" (mode=strict,
// enforce=true) and "audit-agent" (mode=audit, enforce=false). A request to a
// blocklisted domain is sent with each agent header. The strict agent should
// block (403), the audit agent should allow (200), and an unknown agent should
// fall back to _default behavior (balanced, enforce=true = block).
func TestAgentIdentityEndToEnd(t *testing.T) {
	const (
		testStrictAgent  = "strict-agent"
		testAuditAgent   = "audit-agent"
		testUnknownAgent = "unknown-agent"
	)

	// Backend that always responds with plain text.
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	t.Cleanup(func() { backend.Close() })

	enforceTrue := true
	enforceFalse := false

	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF for test backend on 127.0.0.1
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Agents = map[string]config.AgentProfile{
		testStrictAgent: {
			Mode:         config.ModeStrict,
			Enforce:      &enforceTrue,
			APIAllowlist: []string{"127.0.0.1"}, // only allow test backend
		},
		testAuditAgent: {
			Mode:    config.ModeAudit,
			Enforce: &enforceFalse,
		},
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)

	// blocklisted URL (*.pastebin.com is in the default blocklist).
	blockedURL := "https://pastebin.com/raw/abc"
	// allowed URL (the test backend, which is not blocklisted).
	allowedURL := backend.URL + "/text"

	tests := []struct {
		name       string
		agent      string
		url        string
		wantStatus int
		wantBlock  bool
		wantAgent  string // expected agent name in response
	}{
		{
			name:       "strict agent blocks blocklisted domain",
			agent:      testStrictAgent,
			url:        blockedURL,
			wantStatus: http.StatusForbidden,
			wantBlock:  true,
			wantAgent:  testStrictAgent,
		},
		{
			name:       "audit agent allows blocklisted domain",
			agent:      testAuditAgent,
			url:        blockedURL,
			wantStatus: http.StatusOK,
			wantBlock:  false,
			wantAgent:  testAuditAgent,
		},
		{
			name:       "strict agent allows clean URL",
			agent:      testStrictAgent,
			url:        allowedURL,
			wantStatus: http.StatusOK,
			wantBlock:  false,
			wantAgent:  testStrictAgent,
		},
		{
			name:       "unknown agent falls back to _default and blocks",
			agent:      testUnknownAgent,
			url:        blockedURL,
			wantStatus: http.StatusForbidden,
			wantBlock:  true,
			wantAgent:  testUnknownAgent,
		},
		{
			name:       "no agent header falls back to _default and blocks",
			agent:      "",
			url:        blockedURL,
			wantStatus: http.StatusForbidden,
			wantBlock:  true,
			wantAgent:  agentAnonymous,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/fetch?url="+tt.url, nil)
			if tt.agent != "" {
				req.Header.Set(AgentHeader, tt.agent)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			var resp FetchResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("invalid JSON response: %v", err)
			}

			if resp.Blocked != tt.wantBlock {
				t.Errorf("blocked = %v, want %v", resp.Blocked, tt.wantBlock)
			}
			if resp.Agent != tt.wantAgent {
				t.Errorf("agent = %q, want %q", resp.Agent, tt.wantAgent)
			}
		})
	}
}

// TestBudgetEnforcementFetch verifies that a per-agent budget limit causes the
// fetch handler to return 429 after the request budget is exhausted.
func TestBudgetEnforcementFetch(t *testing.T) {
	const testBudgetAgent = "budget-agent"

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(func() { backend.Close() })

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Agents = map[string]config.AgentProfile{
		testBudgetAgent: {
			Budget: config.BudgetConfig{
				MaxRequestsPerSession: 1,
				WindowMinutes:         60,
			},
		},
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)

	targetURL := backend.URL + "/text"

	// First request: should succeed.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+targetURL, nil)
	req.Header.Set(AgentHeader, testBudgetAgent)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", w.Code, http.StatusOK)
	}

	// Second request: should be rate-limited (429).
	req = httptest.NewRequest(http.MethodGet, "/fetch?url="+targetURL, nil)
	req.Header.Set(AgentHeader, testBudgetAgent)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if !resp.Blocked {
		t.Error("expected blocked=true in budget-exceeded response")
	}
	if resp.BlockReason == "" {
		t.Error("expected non-empty block_reason in budget-exceeded response")
	}
}

// TestMetricLabelBoundsUnknownAgent verifies that an unknown agent name
// resolves to the _default profile for metrics purposes, preventing
// unbounded cardinality from arbitrary X-Pipelock-Agent header values.
func TestMetricLabelBoundsUnknownAgent(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(func() { backend.Close() })

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)

	// Send request with arbitrary agent name not in any profile.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
	req.Header.Set(AgentHeader, "arbitrary-attacker-chosen-name")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// The request should succeed (falls back to _default).
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	// The agent in the response is the raw header (for logging), but the
	// resolved profile used for metrics should be _default.
	if resp.Agent != "arbitrary-attacker-chosen-name" {
		t.Errorf("agent = %q, want raw header value", resp.Agent)
	}

	// Verify the Prometheus metric uses the bounded fallback label, not the
	// raw attacker-chosen header value. This prevents unbounded cardinality.
	gathering, gatherErr := p.metrics.Registry().Gather()
	if gatherErr != nil {
		t.Fatalf("gather metrics: %v", gatherErr)
	}
	for _, mf := range gathering {
		if mf.GetName() != "pipelock_requests_total" {
			continue
		}
		for _, metric := range mf.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "agent" && label.GetValue() == "arbitrary-attacker-chosen-name" {
					t.Error("attacker-chosen agent name leaked into Prometheus label; expected bounded fallback")
				}
			}
		}
	}
}

// TestByteBudgetBlocksFetchResponse verifies that a fetch response whose body
// exceeds the per-agent byte budget is blocked with 429 at read time, rather
// than being delivered and only tracked after the fact.
func TestByteBudgetBlocksFetchResponse(t *testing.T) {
	const testByteBudgetAgent = "byte-budget-agent"

	// Backend returns a 500-byte response body.
	body500 := strings.Repeat("x", 500)
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, body500)
	}))
	t.Cleanup(func() { backend.Close() })

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Agents = map[string]config.AgentProfile{
		testByteBudgetAgent: {
			Budget: config.BudgetConfig{
				MaxBytesPerSession: 100, // 100 bytes, backend returns 500
				WindowMinutes:      60,
			},
		},
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)

	// First request: response body (500 bytes) exceeds byte budget (100).
	// Should be blocked with 429 at read time.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/text", nil)
	req.Header.Set(AgentHeader, testByteBudgetAgent)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d (byte budget should block oversize response)", w.Code, http.StatusTooManyRequests)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !resp.Blocked {
		t.Error("expected blocked=true")
	}
	if resp.BlockReason == "" {
		t.Error("expected non-empty block_reason")
	}
}

// TestAgentListenerBinding verifies that per-agent listeners inject the
// correct agent identity via context override (spoof-proof path).
// Requests to the agent listener port should resolve to that agent's
// profile regardless of the X-Pipelock-Agent header.
func TestAgentListenerBinding(t *testing.T) {
	const testListenerAgent = "listener-agent"

	// Backend that returns plain text.
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	t.Cleanup(func() { backend.Close() })

	// Bind free ports for the agent and main listeners.
	lc := net.ListenConfig{}
	agentLn, listenErr := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("failed to get free port: %v", listenErr)
	}
	agentAddr := agentLn.Addr().String()
	_ = agentLn.Close() // free the port for the proxy to bind

	enforceFalse := false

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5
	mainLn, mainErr := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if mainErr != nil {
		t.Fatalf("failed to get free port for main: %v", mainErr)
	}
	cfg.FetchProxy.Listen = mainLn.Addr().String()
	_ = mainLn.Close()

	cfg.Agents = map[string]config.AgentProfile{
		testListenerAgent: {
			Mode:      config.ModeAudit,
			Enforce:   &enforceFalse,
			Listeners: []string{agentAddr},
		},
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { p.Close() })

	// Start agent listener manually (proxy.Start() no longer manages these;
	// the CLI layer owns agent listener lifecycle).
	handler := p.Handler()
	agentLn2, agentLnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", agentAddr)
	if agentLnErr != nil {
		t.Fatalf("bind agent listener: %v", agentLnErr)
	}
	agentSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(edition.WithAgentOverride(r.Context(), testListenerAgent))
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second, // Slowloris protection
	}
	p.RegisterAgentServer(agentSrv)
	go func() {
		if srvErr := agentSrv.Serve(agentLn2); srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			t.Logf("agent listener error: %v", srvErr)
		}
	}()

	// Start proxy in background (Start() blocks).
	startErr := make(chan error, 1)
	go func() { startErr <- p.Start(ctx) }()

	// Wait for both listeners to be ready.
	waitForListener(t, cfg.FetchProxy.Listen)
	waitForListener(t, agentAddr)

	// Request to the agent listener: should get listener-agent identity
	// even without X-Pipelock-Agent header. The agent is in audit mode
	// (enforce=false), so a blocklisted domain should be allowed.
	blockedURL := "https://pastebin.com/raw/abc"
	fetchReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+agentAddr+"/fetch?url="+blockedURL, nil)
	resp, respErr := http.DefaultClient.Do(fetchReq)
	if respErr != nil {
		t.Fatalf("GET agent listener: %v", respErr)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var fetchResp FetchResponse
	if jsonErr := json.Unmarshal(body, &fetchResp); jsonErr != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", jsonErr, string(body))
	}

	// Audit mode + enforce=false: blocklisted domain should NOT be blocked.
	if fetchResp.Blocked {
		t.Errorf("expected blocked=false (audit mode), got blocked=true: %s", fetchResp.BlockReason)
	}
	if fetchResp.Agent != testListenerAgent {
		t.Errorf("agent = %q, want %q", fetchResp.Agent, testListenerAgent)
	}

	// Request to the same agent listener WITH a spoofed header: context
	// override should take priority over the header.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+agentAddr+"/fetch?url="+backend.URL+"/text", nil)
	req.Header.Set(AgentHeader, "spoofed-name")
	spoofResp, spoofErr := http.DefaultClient.Do(req)
	if spoofErr != nil {
		t.Fatalf("GET with spoofed header: %v", spoofErr)
	}
	defer func() { _ = spoofResp.Body.Close() }()

	spoofBody, _ := io.ReadAll(spoofResp.Body)
	var spoofFetch FetchResponse
	if jsonErr := json.Unmarshal(spoofBody, &spoofFetch); jsonErr != nil {
		t.Fatalf("invalid JSON: %v", jsonErr)
	}

	// Context override is priority #1: agent should be listener-agent, not spoofed-name.
	if spoofFetch.Agent != testListenerAgent {
		t.Errorf("spoofed request: agent = %q, want %q (context override should win)", spoofFetch.Agent, testListenerAgent)
	}

	// Request to main listener: should NOT have listener-agent identity.
	mainReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.FetchProxy.Listen+"/fetch?url="+blockedURL, nil)
	mainResp, mainRespErr := http.DefaultClient.Do(mainReq)
	if mainRespErr != nil {
		t.Fatalf("GET main listener: %v", mainRespErr)
	}
	defer func() { _ = mainResp.Body.Close() }()

	mainBody, _ := io.ReadAll(mainResp.Body)
	var mainFetch FetchResponse
	if jsonErr := json.Unmarshal(mainBody, &mainFetch); jsonErr != nil {
		t.Fatalf("invalid JSON: %v", jsonErr)
	}

	// Main listener with no header should fall back to _default (which enforces),
	// so blocklisted domain should be blocked.
	if !mainFetch.Blocked {
		t.Errorf("main listener: expected blocked=true for blocklisted domain")
	}
	if mainFetch.Agent != agentAnonymous {
		t.Errorf("main listener: agent = %q, want %q", mainFetch.Agent, agentAnonymous)
	}

	cancel() // shutdown

	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("proxy.Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy.Start did not exit within 5s")
	}
}

// waitForListener polls a TCP address until it accepts connections.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	d := net.Dialer{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := d.DialContext(context.Background(), "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s did not start within 3s", addr)
}
