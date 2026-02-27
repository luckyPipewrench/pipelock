package proxy

import (
	"context"
	"encoding/json"
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
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// doReq is a test helper that creates and executes an HTTP request with context.
func doReq(t *testing.T, client *http.Client, method, url string, body string, headers map[string]string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// TestKillSwitchPortIsolation_APIOnSeparatePort verifies that when
// api_listen is configured, the main proxy port does NOT register API
// routes (returns 404) and the separate API port serves them normally.
func TestKillSwitchPortIsolation_APIOnSeparatePort(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF for tests
	cfg.ApplyDefaults()

	// Allocate a free port for the API server.
	apiLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind API listener: %v", err)
	}
	apiAddr := apiLn.Addr().String()
	cfg.KillSwitch.APIListen = apiAddr
	cfg.KillSwitch.APIToken = "test-token-integration" //nolint:gosec // test value

	logger, _ := audit.New("json", "stdout", "", false, false)
	defer logger.Close()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()

	ks := killswitch.New(cfg)
	ks.SetSeparateAPIPort(true)
	ksAPI := killswitch.NewAPIHandler(ks)

	// Build proxy WITHOUT kill switch API routes (simulates api_listen set).
	p := New(cfg, logger, sc, m, WithKillSwitch(ks))

	// Start the main proxy on a free port.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind proxy listener: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

	// Override the config listen address to match.
	cfg.FetchProxy.Listen = proxyAddr

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.HandleFunc("/health", p.handleHealth)
	mux.Handle("/metrics", m.PrometheusHandler())
	// Intentionally NOT registering /api/v1/* routes here.
	proxySrv := &http.Server{
		Handler:           p.buildHandler(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = proxySrv.Serve(proxyLn) }()
	defer func() { _ = proxySrv.Shutdown(context.Background()) }()

	// Start the separate API server.
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/v1/killswitch", ksAPI.HandleToggle)
	apiMux.HandleFunc("/api/v1/killswitch/status", ksAPI.HandleStatus)
	apiSrv := &http.Server{
		Handler:           apiMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = apiSrv.Serve(apiLn) }()
	defer func() { _ = apiSrv.Shutdown(context.Background()) }()

	client := &http.Client{Timeout: 5 * time.Second}
	authHeader := map[string]string{"Authorization": "Bearer test-token-integration"} //nolint:gosec // test value

	// 1. Main port: /api/v1/killswitch should return 404 (not registered).
	resp := doReq(t, client, http.MethodPost,
		fmt.Sprintf("http://%s/api/v1/killswitch", proxyAddr),
		`{"active": true}`, nil)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 on main port for /api/v1/killswitch, got %d", resp.StatusCode)
	}

	// 2. API port: activate kill switch via proper auth.
	resp = doReq(t, client, http.MethodPost,
		fmt.Sprintf("http://%s/api/v1/killswitch", apiAddr),
		`{"active": true}`, authHeader)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on API port activation, got %d", resp.StatusCode)
	}

	// 2b. Main port: /fetch should be denied (503) — core security property.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/fetch?url=http://example.com", proxyAddr), "", nil)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 on main port /fetch when kill switch active, got %d", resp.StatusCode)
	}

	// 3. Main port: /health should still work (exempt) and report kill switch active.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/health", proxyAddr), "", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /health, got %d", resp.StatusCode)
	}
	var health healthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("unmarshal /health: %v", err)
	}
	if !health.KillSwitchActive {
		t.Error("expected kill_switch_active=true in /health response after activation")
	}

	// 4. API port: status should show api source active.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/api/v1/killswitch/status", apiAddr),
		"", authHeader)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on API status, got %d", resp.StatusCode)
	}
	var status struct {
		Active  bool            `json:"active"`
		Sources map[string]bool `json:"sources"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if !status.Active {
		t.Error("expected active=true in status response")
	}
	if !status.Sources["api"] {
		t.Error("expected sources.api=true in status response")
	}

	// 5. Deactivate via API port.
	resp = doReq(t, client, http.MethodPost,
		fmt.Sprintf("http://%s/api/v1/killswitch", apiAddr),
		`{"active": false}`, authHeader)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on deactivation, got %d", resp.StatusCode)
	}

	// 6. Health should now show kill switch inactive.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/health", proxyAddr), "", nil)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	var health2 healthResponse
	if err := json.Unmarshal(body, &health2); err != nil {
		t.Fatalf("unmarshal /health: %v", err)
	}
	if health2.KillSwitchActive {
		t.Error("expected kill_switch_active=false in /health response after deactivation")
	}
}

// TestKillSwitchPortIsolation_DefaultBehavior verifies that when
// api_listen is empty (default), the API routes are registered on the
// main proxy port as before.
func TestKillSwitchPortIsolation_DefaultBehavior(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ApplyDefaults()
	cfg.KillSwitch.APIToken = "test-token-default" //nolint:gosec // test value

	logger, _ := audit.New("json", "stdout", "", false, false)
	defer logger.Close()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()

	ks := killswitch.New(cfg)
	ksAPI := killswitch.NewAPIHandler(ks)

	// Build proxy WITH kill switch API routes (default behavior).
	p := New(cfg, logger, sc, m, WithKillSwitch(ks), WithKillSwitchAPI(ksAPI))

	// Allocate a free port by binding and immediately closing.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cfg.FetchProxy.Listen = addr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = p.Start(ctx) }()
	// Wait for the server to start by polling /health.
	// Use raw client.Get (not doReq) because connection refused is expected during startup.
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
			fmt.Sprintf("http://%s/health", addr), nil)
		resp, reqErr := client.Do(req)
		if reqErr == nil {
			resp.Body.Close() //nolint:errcheck,gosec // test
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// API route should be reachable on the main port.
	resp := doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/api/v1/killswitch/status", addr),
		"", map[string]string{"Authorization": "Bearer test-token-default"})
	resp.Body.Close() //nolint:errcheck,gosec // test
	// Should NOT be 404 — route is registered.
	if resp.StatusCode == http.StatusNotFound {
		t.Error("expected API route to be registered on main port when api_listen is empty")
	}

	cancel() // shut down
}

// TestKillSwitchHealthReportsActive verifies the /health endpoint includes
// kill_switch_active status without requiring authentication.
func TestKillSwitchHealthReportsActive(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ApplyDefaults()

	logger, _ := audit.New("json", "stdout", "", false, false)
	defer logger.Close()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()

	ks := killswitch.New(cfg)
	p := New(cfg, logger, sc, m, WithKillSwitch(ks))

	// Health with kill switch inactive.
	w := httptest.NewRecorder()
	p.handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	var h1 healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &h1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h1.KillSwitchActive {
		t.Error("expected kill_switch_active=false when inactive")
	}

	// Activate via API source.
	ks.SetAPI(true)
	w = httptest.NewRecorder()
	p.handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	var h2 healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &h2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !h2.KillSwitchActive {
		t.Error("expected kill_switch_active=true when active")
	}
}
