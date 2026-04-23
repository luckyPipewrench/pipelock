// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	plsentry "github.com/luckyPipewrench/pipelock/internal/sentry"
)

// syncBuffer is defined in helpers_test.go (no build constraint).

// testRootCmd builds a minimal root command with RunCmd attached for testing.
func testRootCmd() *cobra.Command {
	root := &cobra.Command{Use: "pipelock", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(RunCmd())
	return root
}

func TestReloadPanicHandler_LogsError(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}

	ReloadPanicHandler("test panic value", nil, logger, "/tmp/test.yaml")
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	logOutput := string(data)
	if !strings.Contains(logOutput, "scanner construction panic") {
		t.Errorf("expected panic logged, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "test panic value") {
		t.Errorf("expected panic value in log, got: %q", logOutput)
	}
}

func TestReloadPanicHandler_NilLogger(t *testing.T) {
	ReloadPanicHandler("test panic value", nil, nil, "/tmp/test.yaml")
}

func TestReloadPanicHandler_NilRecovery(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}

	// nil recovery value should be a no-op.
	ReloadPanicHandler(nil, nil, logger, "/tmp/test.yaml")
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	if strings.Contains(string(data), "panic") {
		t.Error("expected no log output for nil recovery")
	}
}

func TestReloadPanicHandler_WithSentryClient(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}

	// Use a disabled sentry client -- verifies the nil-check branch
	// (sentryClient != nil) is exercised without actually sending.
	sentryClient := &plsentry.Client{}
	ReloadPanicHandler("boom", sentryClient, logger, "/tmp/test.yaml")
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	if !strings.Contains(string(data), "boom") {
		t.Error("expected panic value in log")
	}
}

func TestReloadPanicHandler_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}

	// Simulate the exact pattern used in RunCmd: a deferred recover
	// calling ReloadPanicHandler after a panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				ReloadPanicHandler(r, nil, logger, "/tmp/test.yaml")
			}
		}()
		panic("simulated scanner panic")
	}()
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	logOutput := string(data)
	if !strings.Contains(logOutput, "simulated scanner panic") {
		t.Errorf("expected panic message in log, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "scanner construction panic") {
		t.Errorf("expected error context in log, got: %q", logOutput)
	}
}

func listenUDP(t *testing.T) net.PacketConn {
	t.Helper()
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestRedactEndpoint(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "webhook with query param",
			raw:  "https://hooks.example.com:8088/services/collector?session=abc123",
			want: "https://hooks.example.com:8088/services/collector",
		},
		{
			name: "webhook with userinfo",
			raw:  "https://" + "user:pass" + "@hooks.example.com/webhook",
			want: "https://hooks.example.com/webhook",
		},
		{
			name: "webhook with fragment",
			raw:  "https://hooks.example.com/webhook#section",
			want: "https://hooks.example.com/webhook",
		},
		{
			name: "webhook with all sensitive parts",
			raw:  "https://" + "admin:secret" + "@example.com:8080/path?token=xyz&key=abc#frag",
			want: "https://example.com:8080/path",
		},
		{
			name: "syslog udp address",
			raw:  "udp://syslog.example.com:514",
			want: "udp://syslog.example.com:514",
		},
		{
			name: "syslog tcp address",
			raw:  "tcp://syslog.example.com:514",
			want: "tcp://syslog.example.com:514",
		},
		{
			name: "plain https URL",
			raw:  "https://example.com/webhook",
			want: "https://example.com/webhook",
		},
		{
			name: "empty string",
			raw:  "",
			want: "",
		},
		{
			name: "invalid URL returns sentinel",
			raw:  "%invalid",
			want: "<invalid>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactEndpoint(tt.raw)
			if got != tt.want {
				t.Errorf("RedactEndpoint(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func testConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return cfg
}

func TestBuildEmitSinks_NoConfig(t *testing.T) {
	cfg := testConfig()
	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 0 {
		t.Errorf("expected 0 sinks, got %d", len(sinks))
	}
}

func TestBuildEmitSinks_WebhookOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = config.SeverityWarn

	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_WebhookWithAllOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = config.SeverityInfo
	cfg.Emit.Webhook.AuthToken = "test-" + "token"
	cfg.Emit.Webhook.QueueSize = 32
	cfg.Emit.Webhook.TimeoutSecs = 10

	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_SyslogOnly(t *testing.T) {
	conn := listenUDP(t)

	cfg := testConfig()
	cfg.Emit.Syslog.Address = "udp://" + conn.LocalAddr().String()
	cfg.Emit.Syslog.MinSeverity = config.SeverityWarn
	cfg.Emit.Syslog.Facility = "local3"
	cfg.Emit.Syslog.Tag = "test"

	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_BothSinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conn := listenUDP(t)

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = config.SeverityInfo
	cfg.Emit.Syslog.Address = "udp://" + conn.LocalAddr().String()
	cfg.Emit.Syslog.MinSeverity = config.SeverityWarn

	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 2 {
		t.Errorf("expected 2 sinks, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_SyslogError_CleansUpWebhook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = config.SeverityInfo
	// Invalid syslog address triggers error after webhook is created
	cfg.Emit.Syslog.Address = "tcp://127.0.0.1:notaport" // deterministic parse failure

	sinks, err := BuildEmitSinks(cfg)
	if err == nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		t.Fatal("expected error for unreachable syslog")
	}
	// Webhook sink should have been cleaned up (no goroutine leak)
	if sinks != nil {
		t.Errorf("expected nil sinks on error, got %d", len(sinks))
	}
}

func TestBuildEmitSinks_OTLPOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.OTLP.Endpoint = srv.URL
	cfg.Emit.OTLP.MinSeverity = config.SeverityWarn
	cfg.Emit.OTLP.TimeoutSeconds = 5
	cfg.Emit.OTLP.QueueSize = 32

	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink (otlp), got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_OTLPWithHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.OTLP.Endpoint = srv.URL
	cfg.Emit.OTLP.Headers = map[string]string{"X-Tenant": "test"}
	cfg.Emit.OTLP.Gzip = true

	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_OTLPWithInstanceID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.InstanceID = "custom-instance"
	cfg.Emit.OTLP.Endpoint = srv.URL

	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_AllThreeSinks(t *testing.T) {
	wSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer wSrv.Close()

	oSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer oSrv.Close()

	conn, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cfg := testConfig()
	cfg.Emit.Webhook.URL = wSrv.URL
	cfg.Emit.Syslog.Address = "udp://" + conn.LocalAddr().String()
	cfg.Emit.OTLP.Endpoint = oSrv.URL

	sinks, sinkErr := BuildEmitSinks(cfg)
	if sinkErr != nil {
		t.Fatalf("unexpected error: %v", sinkErr)
	}
	if len(sinks) != 3 {
		t.Errorf("expected 3 sinks (webhook+syslog+otlp), got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

// freePort returns a free TCP port on localhost.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitForPort polls a TCP address until it accepts connections or times out.
func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	dialer := &net.Dialer{Timeout: 50 * time.Millisecond}
	for time.Now().Before(deadline) {
		conn, err := dialer.DialContext(context.Background(), "tcp4", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("port %s not ready within 5s", addr)
}

// doGet issues a context-aware GET and fails the test on error.
func doGet(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func TestRunCmd_MetricsPortIsolation(t *testing.T) {
	mainAddr := freePort(t)
	metricsAddr := freePort(t)

	cfgYAML := fmt.Sprintf(`version: 1
mode: balanced
metrics_listen: %q
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
logging:
  format: json
  output: stdout
`, metricsAddr, mainAddr)

	tmpFile, err := os.CreateTemp(t.TempDir(), "pipelock-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := tmpFile.WriteString(cfgYAML); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_ = tmpFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := RunCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", tmpFile.Name()})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	// Wait for both ports.
	waitForPort(t, mainAddr)
	waitForPort(t, metricsAddr)

	client := &http.Client{Timeout: 2 * time.Second}

	// Main port: /health should work.
	resp := doGet(t, client, "http://"+mainAddr+"/health")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health: want 200, got %d", resp.StatusCode)
	}

	// Main port: /metrics should 404 (isolated to metrics port).
	resp = doGet(t, client, "http://"+mainAddr+"/metrics")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/metrics on main port: want 404, got %d", resp.StatusCode)
	}

	// Main port: /stats should 404.
	resp = doGet(t, client, "http://"+mainAddr+"/stats")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/stats on main port: want 404, got %d", resp.StatusCode)
	}

	// Metrics port: /metrics should 200.
	resp = doGet(t, client, "http://"+metricsAddr+"/metrics")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics on metrics port: want 200, got %d", resp.StatusCode)
	}

	// Metrics port: /stats should 200.
	resp = doGet(t, client, "http://"+metricsAddr+"/stats")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/stats on metrics port: want 200, got %d", resp.StatusCode)
	}

	// Shut down.
	cancel()
	select {
	case err := <-cmdErr:
		if err != nil {
			t.Errorf("RunCmd returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunCmd did not exit within 5s")
	}
}

func TestRunCmd_RedactionWiresMCPListenerAndReverseProxy(t *testing.T) {
	mainAddr := freePort(t)
	reverseAddr := freePort(t)
	mcpAddr := freePort(t)
	secret := "AKIA" + "IOSFODNN7EXAMPLE"

	var reverseBody atomic.Value
	reverseUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		reverseBody.Store(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer reverseUpstream.Close()

	var mcpBody atomic.Value
	mcpUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mcpBody.Store(string(body))

		var request struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"jsonrpc": "2.0",
			"id":      request.ID,
			"result": map[string]any{
				"content": []map[string]any{{
					"type": "text",
					"text": "ok",
				}},
			},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatalf("Encode(response): %v", err)
		}
	}))
	defer mcpUpstream.Close()

	cfgYAML := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
request_body_scanning:
  enabled: true
  action: warn
reverse_proxy:
  enabled: true
  listen: %q
  upstream: %q
redaction:
  enabled: true
  default_profile: code
  profiles:
    code:
      classes:
        - aws-access-key
logging:
  format: json
  output: stdout
`, mainAddr, reverseAddr, reverseUpstream.URL)

	tmpFile, err := os.CreateTemp(t.TempDir(), "pipelock-redaction-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := tmpFile.WriteString(cfgYAML); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_ = tmpFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := RunCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{
		"--config", tmpFile.Name(),
		"--mcp-listen", mcpAddr,
		"--mcp-upstream", mcpUpstream.URL,
	})
	var stderr syncBuffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	waitForPort(t, mainAddr)
	waitForPort(t, reverseAddr)
	waitForPort(t, mcpAddr)

	reverseReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+reverseAddr+"/api",
		strings.NewReader(`{"prompt":"use `+secret+` to deploy"}`))
	if err != nil {
		t.Fatalf("new reverse request: %v", err)
	}
	reverseReq.Header.Set("Content-Type", "application/json")
	reverseResp, err := http.DefaultClient.Do(reverseReq)
	if err != nil {
		t.Fatalf("reverse proxy POST: %v", err)
	}
	_ = reverseResp.Body.Close()
	if reverseResp.StatusCode != http.StatusOK {
		t.Fatalf("reverse proxy status = %d, want 200", reverseResp.StatusCode)
	}

	mcpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+mcpAddr+"/",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"prompt":"use `+secret+` to deploy"}}}`))
	if err != nil {
		t.Fatalf("new mcp request: %v", err)
	}
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpResp, err := http.DefaultClient.Do(mcpReq)
	if err != nil {
		t.Fatalf("mcp listener POST: %v", err)
	}
	_ = mcpResp.Body.Close()
	if mcpResp.StatusCode != http.StatusOK {
		t.Fatalf("mcp listener status = %d, want 200", mcpResp.StatusCode)
	}

	gotReverse, _ := reverseBody.Load().(string)
	if strings.Contains(gotReverse, secret) {
		t.Fatalf("reverse upstream leaked secret: %s", gotReverse)
	}
	if !strings.Contains(gotReverse, "<pl:aws-access-key:1>") {
		t.Fatalf("reverse upstream missing placeholder: %s", gotReverse)
	}

	gotMCP, _ := mcpBody.Load().(string)
	if strings.Contains(gotMCP, secret) {
		t.Fatalf("mcp upstream leaked secret: %s", gotMCP)
	}
	if !strings.Contains(gotMCP, "<pl:aws-access-key:1>") {
		t.Fatalf("mcp upstream missing placeholder: %s", gotMCP)
	}

	cancel()
	select {
	case err := <-cmdErr:
		if err != nil {
			t.Errorf("RunCmd returned error: %v\nstderr:\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunCmd did not exit within 5s")
	}
}

func TestAgentHandler(t *testing.T) {
	// Unit test for AgentHandler context injection.
	// Uses edition.ResolveAgentIdentity to verify the context override round-trips.
	const testProfile = "my-agent"
	var resolved edition.AgentIdentity

	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = edition.ResolveAgentIdentity(r, map[string]bool{testProfile: true}, "", false)
	})

	handler := AgentHandler(testProfile, inner)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	handler.ServeHTTP(nil, req)

	if resolved.Profile != testProfile {
		t.Errorf("resolved profile = %q, want %q", resolved.Profile, testProfile)
	}
	if resolved.Name != testProfile {
		t.Errorf("resolved name = %q, want %q", resolved.Name, testProfile)
	}
}

func TestAgentListenersChanged(t *testing.T) {
	tests := []struct {
		name string
		old  map[string]config.AgentProfile
		new  map[string]config.AgentProfile
		want bool
	}{
		{
			"no agents",
			nil, nil, false,
		},
		{
			"same listeners",
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			false,
		},
		{
			"listener changed",
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			map[string]config.AgentProfile{"a": {Listeners: []string{":9002"}}},
			true,
		},
		{
			"listener added to existing agent",
			map[string]config.AgentProfile{"a": {}},
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			true,
		},
		{
			"listener removed from agent",
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			map[string]config.AgentProfile{"a": {}},
			true,
		},
		{
			"new agent with listener",
			map[string]config.AgentProfile{"a": {}},
			map[string]config.AgentProfile{"a": {}, "b": {Listeners: []string{":9002"}}},
			true,
		},
		{
			"agent removed with listener",
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			map[string]config.AgentProfile{},
			true,
		},
		{
			"agent added without listener",
			map[string]config.AgentProfile{},
			map[string]config.AgentProfile{"a": {Mode: config.ModeStrict}},
			false,
		},
		{
			"non-listener config change",
			map[string]config.AgentProfile{"a": {Mode: config.ModeBalanced, Listeners: []string{":9001"}}},
			map[string]config.AgentProfile{"a": {Mode: config.ModeStrict, Listeners: []string{":9001"}}},
			false,
		},
		{
			"renamed agent with listener same count",
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			map[string]config.AgentProfile{"b": {Listeners: []string{":9001"}}},
			true,
		},
		{
			"renamed agent without listener same count",
			map[string]config.AgentProfile{"a": {Mode: config.ModeBalanced}},
			map[string]config.AgentProfile{"b": {Mode: config.ModeStrict}},
			false,
		},
		{
			"renamed agent old has listener new does not",
			map[string]config.AgentProfile{"a": {Listeners: []string{":9001"}}},
			map[string]config.AgentProfile{"b": {}},
			true,
		},
		{
			"renamed agent old no listener new has listener",
			map[string]config.AgentProfile{"a": {}},
			map[string]config.AgentProfile{"b": {Listeners: []string{":9001"}}},
			true,
		},
		{
			"different count neither has listeners",
			map[string]config.AgentProfile{"a": {Mode: config.ModeBalanced}},
			map[string]config.AgentProfile{"a": {}, "b": {}},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := config.Defaults()
			old.Internal = nil
			old.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			old.Agents = tt.old

			newCfg := config.Defaults()
			newCfg.Internal = nil
			newCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			newCfg.Agents = tt.new

			got := AgentListenersChanged(old, newCfg)
			if got != tt.want {
				t.Errorf("AgentListenersChanged = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPreserveAgentListeners(t *testing.T) {
	t.Run("both configs have same agents", func(t *testing.T) {
		old := config.Defaults()
		old.Internal = nil
		old.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		old.Agents = map[string]config.AgentProfile{
			"a": {Listeners: []string{":9001"}, Mode: config.ModeBalanced},
			"b": {Listeners: []string{":9002"}},
		}

		newCfg := config.Defaults()
		newCfg.Internal = nil
		newCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		newCfg.Agents = map[string]config.AgentProfile{
			"a": {Listeners: []string{":9999"}, Mode: config.ModeStrict},
			"b": {Listeners: []string{":8888"}},
		}

		PreserveAgentListeners(old, newCfg)

		if newCfg.Agents["a"].Listeners[0] != ":9001" {
			t.Errorf("agent a listener = %q, want :9001", newCfg.Agents["a"].Listeners[0])
		}
		if newCfg.Agents["b"].Listeners[0] != ":9002" {
			t.Errorf("agent b listener = %q, want :9002", newCfg.Agents["b"].Listeners[0])
		}
		if newCfg.Agents["a"].Mode != config.ModeStrict {
			t.Errorf("agent a mode = %q, want %s", newCfg.Agents["a"].Mode, config.ModeStrict)
		}
	})

	t.Run("listener-bearing agent removed re-added", func(t *testing.T) {
		old := config.Defaults()
		old.Internal = nil
		old.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		old.Agents = map[string]config.AgentProfile{
			"a": {Listeners: []string{":9001"}, Mode: config.ModeBalanced},
		}

		newCfg := config.Defaults()
		newCfg.Internal = nil
		newCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		newCfg.Agents = map[string]config.AgentProfile{}

		PreserveAgentListeners(old, newCfg)

		// Removed listener-bearing agent must be re-added to prevent
		// policy downgrade on the still-bound socket.
		restored, ok := newCfg.Agents["a"]
		if !ok {
			t.Fatal("agent a should be re-added when removed with active listeners")
		}
		if restored.Listeners[0] != ":9001" {
			t.Errorf("restored listener = %q, want :9001", restored.Listeners[0])
		}
		if restored.Mode != config.ModeBalanced {
			t.Errorf("restored mode = %q, want %s", restored.Mode, config.ModeBalanced)
		}
	})

	t.Run("non-listener agent removed stays removed", func(t *testing.T) {
		old := config.Defaults()
		old.Internal = nil
		old.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		old.Agents = map[string]config.AgentProfile{
			"a": {Mode: config.ModeBalanced}, // no listeners
		}

		newCfg := config.Defaults()
		newCfg.Internal = nil
		newCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		newCfg.Agents = map[string]config.AgentProfile{}

		PreserveAgentListeners(old, newCfg)

		if _, ok := newCfg.Agents["a"]; ok {
			t.Error("agent a without listeners should not be re-added")
		}
	})

	t.Run("new agent listeners stripped", func(t *testing.T) {
		old := config.Defaults()
		old.Internal = nil
		old.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		old.Agents = map[string]config.AgentProfile{}

		newCfg := config.Defaults()
		newCfg.Internal = nil
		newCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		newCfg.Agents = map[string]config.AgentProfile{
			"b": {Listeners: []string{":9002"}, Mode: config.ModeStrict},
		}

		PreserveAgentListeners(old, newCfg)

		// New agent's listeners should be stripped (can't bind without
		// restart), but non-listener config should remain.
		p := newCfg.Agents["b"]
		if len(p.Listeners) > 0 {
			t.Errorf("new agent listeners should be stripped, got %v", p.Listeners)
		}
		if p.Mode != config.ModeStrict {
			t.Errorf("new agent mode = %q, want %s", p.Mode, config.ModeStrict)
		}
	})

	t.Run("nil new agents map initialized", func(t *testing.T) {
		old := config.Defaults()
		old.Internal = nil
		old.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		old.Agents = map[string]config.AgentProfile{
			"a": {Listeners: []string{":9001"}},
		}

		newCfg := config.Defaults()
		newCfg.Internal = nil
		newCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		newCfg.Agents = nil

		PreserveAgentListeners(old, newCfg)

		if newCfg.Agents == nil {
			t.Fatal("newCfg.Agents should be initialized")
		}
		if _, ok := newCfg.Agents["a"]; !ok {
			t.Error("agent a should be re-added")
		}
	})
}

// ---------------------------------------------------------------------------
// Flag validation tests for runCmd (reverse proxy flags)
// ---------------------------------------------------------------------------

func TestRunCmd_RejectsPositionalArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "without dash",
			args: []string{"run", "agent-cmd"},
			want: "unexpected arguments",
		},
		{
			name: "before dash",
			args: []string{"run", "agent-cmd", "--", "--flag"},
			want: "unexpected arguments before --",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := testRootCmd()
			cmd.SetArgs(tt.args)
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})

			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected positional argument validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestRunCmd_AcceptsAgentArgsAfterDash(t *testing.T) {
	gotAgentArgs := agentArgsAfterDash([]string{"some-agent", "--flag"}, 0)
	if strings.Join(gotAgentArgs, " ") != "some-agent --flag" {
		t.Fatalf("agent args = %v, want %v", gotAgentArgs, []string{"some-agent", "--flag"})
	}
	if got := agentArgsAfterDash(nil, 0); got != nil {
		t.Fatalf("empty trailing args = %v, want nil", got)
	}
}

func TestRunCmd_ReverseProxyWithoutUpstream(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"run", "--reverse-proxy"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for --reverse-proxy without --reverse-upstream")
	}
	if !strings.Contains(err.Error(), "--reverse-proxy requires --reverse-upstream") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunCmd_ReverseUpstreamWithoutProxy(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"run", "--reverse-upstream", "http://localhost:8080"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for --reverse-upstream without --reverse-proxy")
	}
	if !strings.Contains(err.Error(), "--reverse-upstream requires --reverse-proxy") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunCmd_ReverseUpstreamInvalidURL(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"run", "--reverse-proxy", "--reverse-upstream", "not-a-url"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid --reverse-upstream URL")
	}
	if !strings.Contains(err.Error(), "invalid --reverse-upstream") {
		t.Errorf("unexpected error: %v", err)
	}
}
