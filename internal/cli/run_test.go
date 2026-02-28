package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

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
			raw:  "https://" + "user:pass" + "@hooks.example.com/webhook", //nolint:goconst // test value
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
			got := redactEndpoint(tt.raw)
			if got != tt.want {
				t.Errorf("redactEndpoint(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func testConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	return cfg
}

func TestBuildEmitSinks_NoConfig(t *testing.T) {
	cfg := testConfig()
	sinks, err := buildEmitSinks(cfg)
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
	cfg.Emit.Webhook.MinSeverity = "warn" //nolint:goconst // test value

	sinks, err := buildEmitSinks(cfg)
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
	cfg.Emit.Webhook.MinSeverity = "info"          //nolint:goconst // test value
	cfg.Emit.Webhook.AuthToken = "test-" + "token" //nolint:goconst // test value
	cfg.Emit.Webhook.QueueSize = 32
	cfg.Emit.Webhook.TimeoutSecs = 10

	sinks, err := buildEmitSinks(cfg)
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
	cfg.Emit.Syslog.MinSeverity = "warn" //nolint:goconst // test value
	cfg.Emit.Syslog.Facility = "local3"
	cfg.Emit.Syslog.Tag = "test"

	sinks, err := buildEmitSinks(cfg)
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
	cfg.Emit.Webhook.MinSeverity = "info" //nolint:goconst // test value
	cfg.Emit.Syslog.Address = "udp://" + conn.LocalAddr().String()
	cfg.Emit.Syslog.MinSeverity = "warn" //nolint:goconst // test value

	sinks, err := buildEmitSinks(cfg)
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
	cfg.Emit.Webhook.MinSeverity = "info"
	// Invalid syslog address triggers error after webhook is created
	cfg.Emit.Syslog.Address = "tcp://127.0.0.1:notaport" // deterministic parse failure

	sinks, err := buildEmitSinks(cfg)
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

	cmd := runCmd()
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
			t.Errorf("runCmd returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not exit within 5s")
	}
}

func TestRunCmd_MetricsDisplayMessage(t *testing.T) {
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

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", tmpFile.Name()})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	waitForPort(t, mainAddr)

	cancel()
	select {
	case <-cmdErr:
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not exit")
	}

	output := stderr.String()
	// Verify the separate-port stats message appears.
	if !bytes.Contains([]byte(output), []byte("separate port")) {
		t.Errorf("expected 'separate port' in output, got:\n%s", output)
	}
	// Verify metrics listening message appears.
	if !bytes.Contains([]byte(output), []byte("metrics listening on")) {
		t.Errorf("expected 'metrics listening on' in output, got:\n%s", output)
	}
}

func TestRunCmd_NoMetricsListen(t *testing.T) {
	mainAddr := freePort(t)

	cfgYAML := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
logging:
  format: json
  output: stdout
`, mainAddr)

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

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", tmpFile.Name()})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	// Give it a moment to start or fail.
	time.Sleep(200 * time.Millisecond)

	// Check if command already exited with an error.
	select {
	case err := <-cmdErr:
		t.Fatalf("runCmd exited early: err=%v\nstderr:\n%s", err, stderr.String())
	default:
	}

	waitForPort(t, mainAddr)

	client := &http.Client{Timeout: 2 * time.Second}

	// Without metrics_listen: /metrics should be available on main port.
	resp := doGet(t, client, "http://"+mainAddr+"/metrics")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics on main port: want 200, got %d", resp.StatusCode)
	}

	// /stats should be available on main port.
	resp = doGet(t, client, "http://"+mainAddr+"/stats")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/stats on main port: want 200, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case <-cmdErr:
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not exit")
	}
}
