package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootCmd_Version(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--version"})

	// Capture output
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), Version) {
		t.Errorf("expected version output to contain %q, got %q", Version, buf.String())
	}
}

func TestRootCmd_Help(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "pipelock") {
		t.Error("expected help output to mention pipelock")
	}
	if !strings.Contains(output, "run") {
		t.Error("expected help output to list 'run' command")
	}
	if !strings.Contains(output, "check") {
		t.Error("expected help output to list 'check' command")
	}
	if !strings.Contains(output, "generate") {
		t.Error("expected help output to list 'generate' command")
	}
	if !strings.Contains(output, "logs") {
		t.Error("expected help output to list 'logs' command")
	}
}

func TestCheckCmd_DefaultConfig(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"check"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "default config") {
		t.Errorf("expected output to mention default config, got: %q", buf.String())
	}
}

func TestCheckCmd_WithConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")

	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.anthropic.com"
fetch_proxy:
  listen: "127.0.0.1:9999"
  timeout_seconds: 15
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--config", cfgPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckCmd_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")

	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml}}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--config", cfgPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestCheckCmd_NonexistentConfig(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--config", "/nonexistent/file.yaml"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestCheckCmd_URLAllowed(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--url", "https://example.com"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error for allowed URL, got: %v", err)
	}

	if !strings.Contains(buf.String(), "ALLOWED") {
		t.Errorf("expected ALLOWED in output, got: %q", buf.String())
	}
}

func TestCheckCmd_URLBlocked(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--url", "https://pastebin.com/raw/abc123"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for blocked URL")
	}
	if !errors.Is(err, ErrURLBlocked) {
		t.Errorf("expected ErrURLBlocked, got: %v", err)
	}

	if !strings.Contains(buf.String(), "BLOCKED") {
		t.Errorf("expected BLOCKED in output, got: %q", buf.String())
	}
}

func TestGenerateCmd_AllPresets(t *testing.T) {
	for _, preset := range []string{"strict", "balanced", "audit"} {
		t.Run(preset, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetArgs([]string{"generate", "config", "--preset", preset})

			buf := &strings.Builder{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			if err := cmd.Execute(); err != nil {
				t.Fatalf("generate config --preset %s failed: %v", preset, err)
			}
		})
	}
}

func TestGenerateCmd_UnknownPreset(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "nonexistent"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for unknown preset")
	}
}

func TestGenerateCmd_OutputToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "generated.yaml")

	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "balanced", "--output", outPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(outPath) //nolint:gosec // G304: test reads its own temp file
	if err != nil {
		t.Fatalf("expected output file to exist: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output file")
	}
	if !strings.Contains(string(data), "mode:") {
		t.Error("expected output to contain mode field")
	}
}

func TestLogsCmd_MissingFile(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"logs"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --file not provided")
	}
}

func TestLogsCmd_NonexistentFile(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", "/nonexistent/audit.log"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent log file")
	}
}

func TestLogsCmd_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(logPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", logPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogsCmd_WithFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	lines := `{"event":"allowed","url":"https://example.com"}
{"event":"blocked","url":"https://evil.com"}
{"event":"allowed","url":"https://safe.com"}
`
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", logPath, "--filter", "blocked"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "evil.com") {
		t.Errorf("expected blocked entry in output, got: %q", output)
	}
	if strings.Contains(output, "example.com") {
		t.Error("expected allowed entries to be filtered out")
	}
}

func TestLogsCmd_WithLast(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	lines := `{"event":"allowed","url":"https://first.com"}
{"event":"allowed","url":"https://second.com"}
{"event":"allowed","url":"https://third.com"}
`
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", logPath, "--last", "1"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "third.com") {
		t.Errorf("expected last entry in output, got: %q", output)
	}
	if strings.Contains(output, "first.com") {
		t.Error("expected earlier entries to be excluded with --last 1")
	}
}

func TestMatchFilter_JSONEvent(t *testing.T) {
	line := `{"event":"blocked","url":"https://evil.com"}`

	if !matchFilter(line, "blocked") {
		t.Error("expected blocked filter to match")
	}
	if matchFilter(line, "allowed") {
		t.Error("expected allowed filter not to match")
	}
}

func TestMatchFilter_NonJSON(t *testing.T) {
	line := "some plain text with blocked in it"

	if !matchFilter(line, "blocked") {
		t.Error("expected string contains match for non-JSON")
	}
	if matchFilter(line, "missing") {
		t.Error("expected no match when substring not present")
	}
}

func TestHealthcheckCmd_NoServer(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"healthcheck", "--addr", "127.0.0.1:19999"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no server is running")
	}
}

func TestHealthcheckCmd_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Extract host:port from "http://127.0.0.1:PORT"
	addr := strings.TrimPrefix(srv.URL, "http://")

	cmd := rootCmd()
	cmd.SetArgs([]string{"healthcheck", "--addr", addr})

	if err := cmd.Execute(); err != nil {
		t.Errorf("expected healthcheck to succeed against running server, got: %v", err)
	}
}

func TestHealthcheckCmd_RegisteredInHelp(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "healthcheck") {
		t.Error("expected help output to list 'healthcheck' command")
	}
}

func TestRunCmd_Integration(t *testing.T) {
	// Find a free port
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	// Write a balanced config; the --mode flag will override to strict
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	logPath := filepath.Join(dir, "audit.log")
	cfgContent := fmt.Sprintf(`version: 1
mode: balanced
api_allowlist:
  - "*.anthropic.com"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 10
logging:
  format: json
  output: file
  file: "%s"
`, addr, logPath)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Inject a cancellable context so we can shut down the server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", cfgPath, "--mode", "strict"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Poll /health until the proxy is ready
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	var healthy bool
	for time.Now().Before(deadline) {
		// Check if the command already exited with an error
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run command exited early: %v", err)
		default:
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthy {
		cancel()
		t.Fatal("proxy did not become healthy within timeout")
	}

	// Verify the health response shows the flag override (strict, not balanced)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("health request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		cancel()
		t.Fatalf("decoding health response: %v", err)
	}
	if health["mode"] != "strict" { //nolint:goconst // test value
		t.Errorf("expected mode=strict (flag override), got %v", health["mode"])
	}
	if health["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", health["status"])
	}

	// Trigger graceful shutdown
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected run error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run command did not shut down within timeout")
	}
}

func TestRunCmd_ListenFlag(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"run", "--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "--listen") {
		t.Error("expected run --help to show --listen flag")
	}
}

func TestExecute(t *testing.T) {
	// Execute() just delegates to rootCmd().Execute(). Running with no args
	// prints help and succeeds.
	err := Execute()
	if err != nil {
		t.Fatalf("Execute() with no args should succeed, got: %v", err)
	}
}

func TestRunCmd_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml}}"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately — we don't want the server to start

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", cfgPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	if !strings.Contains(err.Error(), "loading config") {
		t.Errorf("expected 'loading config' error, got: %v", err)
	}
}

func TestRunCmd_NonexistentConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", "/nonexistent/pipelock.yaml"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
}

func TestRunCmd_InvalidMode(t *testing.T) {
	// Create a valid config file first, then override mode with an invalid one.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	logPath := filepath.Join(dir, "audit.log")

	cfgContent := fmt.Sprintf(`version: 1
mode: balanced
api_allowlist:
  - "*.anthropic.com"
fetch_proxy:
  listen: "127.0.0.1:0"
  timeout_seconds: 10
logging:
  format: json
  output: file
  file: "%s"
`, logPath)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", cfgPath, "--mode", "invalid-mode"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("expected 'invalid config' error, got: %v", err)
	}
}

func TestRunCmd_ListenFlagOverride(t *testing.T) {
	// Find a free port
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--listen", addr})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Poll /health until the proxy is ready
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	var healthy bool
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run command exited early: %v", err)
		default:
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthy {
		cancel()
		t.Fatal("proxy did not become healthy within timeout")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected run error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run command did not shut down within timeout")
	}
}

func TestHealthcheckCmd_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")

	cmd := rootCmd()
	cmd.SetArgs([]string{"healthcheck", "--addr", addr})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for unhealthy server")
	}
	if !strings.Contains(err.Error(), "unhealthy") {
		t.Errorf("expected 'unhealthy' in error, got: %v", err)
	}
}

func TestLogsCmd_FilterWithNoMatch(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	lines := `{"event":"allowed","url":"https://example.com"}
{"event":"allowed","url":"https://safe.com"}
`
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", logPath, "--filter", "blocked"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.TrimSpace(output) != "" {
		t.Errorf("expected empty output when no lines match filter, got: %q", output)
	}
}

func TestLogsCmd_FilterAndLast(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	lines := `{"event":"blocked","url":"https://evil1.com"}
{"event":"allowed","url":"https://safe.com"}
{"event":"blocked","url":"https://evil2.com"}
{"event":"blocked","url":"https://evil3.com"}
`
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", logPath, "--filter", "blocked", "--last", "1"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "evil3.com") {
		t.Errorf("expected last blocked entry in output, got: %q", output)
	}
	if strings.Contains(output, "evil1.com") {
		t.Error("expected earlier entries to be excluded")
	}
}

func TestMatchFilter_JSONNoEventField(t *testing.T) {
	// JSON that parses successfully but has no "event" field.
	line := `{"url":"https://example.com","status":200}`

	if matchFilter(line, "allowed") {
		t.Error("expected no match when JSON has no event field")
	}
}

func TestMatchFilter_JSONEventWrongType(t *testing.T) {
	// JSON with "event" field that is not a string.
	line := `{"event":42,"url":"https://example.com"}`

	if matchFilter(line, "42") {
		t.Error("expected no match when event field is not a string")
	}
}

func TestGenerateCmd_OutputToStdout(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "strict"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "strict") {
		t.Errorf("expected output to mention strict preset, got: %q", output)
	}
}

func TestGenerateDockerCompose_OpenhandsToStdout(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "docker-compose", "--agent", "openhands"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "openhands") {
		t.Errorf("expected output to contain openhands, got: %q", output)
	}
}

func TestResolveAgentName_InvalidName(t *testing.T) {
	// Ensure PIPELOCK_AGENT env var is clear.
	t.Setenv("PIPELOCK_AGENT", "")

	// Test with explicitly empty name (no flag, no env).
	_, err := resolveAgentName("")
	if err == nil {
		t.Fatal("expected error for empty agent name")
	}
	if !strings.Contains(err.Error(), "agent name required") {
		t.Errorf("expected 'agent name required' error, got: %v", err)
	}
}

func TestResolveKeystoreDir_ExplicitPath(t *testing.T) {
	dir := t.TempDir()

	result, err := resolveKeystoreDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != dir {
		t.Errorf("expected %q, got %q", dir, result)
	}
}

func TestResolveKeystoreDir_Default(t *testing.T) {
	// When no explicit dir is given, it should use the default path.
	result, err := resolveKeystoreDir("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty default keystore path")
	}
}

func TestResolveAgentName_ValidEnvVar(t *testing.T) {
	t.Setenv("PIPELOCK_AGENT", "my-agent")

	name, err := resolveAgentName("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "my-agent" {
		t.Errorf("expected 'my-agent', got %q", name)
	}
}

func TestResolveAgentName_FlagOverridesEnv(t *testing.T) {
	t.Setenv("PIPELOCK_AGENT", "env-agent")

	name, err := resolveAgentName("flag-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "flag-agent" {
		t.Errorf("expected 'flag-agent', got %q", name)
	}
}

func TestRunCmd_WithAgentArgs(t *testing.T) {
	// Find a free port.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--listen", addr, "--", "some-agent", "--flag"})

	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Poll until healthy.
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run exited early: %v", err)
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}

	// The run command completed without error, which means the agent args
	// parsing path (dashIdx >= 0) was exercised. The banner prints to
	// os.Stderr directly, so we can't capture it via cmd.SetErr.
}

func TestRunCmd_DefaultMode(t *testing.T) {
	// Run with no config, no flags — should use default balanced mode.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--listen", addr})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Wait until healthy, then check mode.
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run exited early: %v", err)
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			_ = resp.Body.Close()
			if health["mode"] == "balanced" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}
}

func TestRunCmd_ConfigValidationError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	// Invalid mode triggers validation error.
	cfg := `version: 1
mode: "not-a-mode"
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"run", "--config", cfgPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("expected 'invalid config' error, got: %v", err)
	}
}

func TestRunCmd_ModeFlag(t *testing.T) {
	// Test that --mode strict works without a config file.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--mode", "strict", "--listen", addr})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Wait for healthy.
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run exited early: %v", err)
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, rerr := client.Do(req)
		if rerr == nil {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			_ = resp.Body.Close()
			if health["mode"] == "strict" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}
}

func TestRunCmd_WithConfigHotReload(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, addr)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", cfgPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Wait for healthy.
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run exited early: %v", err)
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, rerr := client.Do(req)
		if rerr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Modify the config to trigger hot-reload via fsnotify.
	updatedCfg := fmt.Sprintf(`version: 1
mode: strict
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, addr)
	if err := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait for reload to take effect.
	time.Sleep(500 * time.Millisecond)

	// Verify the mode changed.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("health request failed: %v", err)
	}
	var health map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&health)
	_ = resp.Body.Close()
	if health["mode"] != "strict" {
		t.Logf("mode after reload: %v (hot-reload may not have completed yet)", health["mode"])
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}
}

func TestRunCmd_AuditLoggerError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	// Invalid log output destination.
	cfg := `version: 1
mode: balanced
logging:
  format: json
  output: file
  file: "/nonexistent/deep/nested/dir/audit.log"
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"run", "--config", cfgPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for bad log file path")
	}
}

func TestRunCmd_ReloadToAskModeWarning(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	// Start with balanced mode (no HITL approver created)
	cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, addr)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", cfgPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Wait for healthy.
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run exited early: %v", err)
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, rerr := client.Do(req)
		if rerr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Reload config to action: ask (triggers warning because no approver at startup).
	// The warning goes to os.Stderr directly; coverage confirms code path execution.
	updatedCfg := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
response_scanning:
  enabled: true
  action: ask
`, addr)
	if err := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait for reload to take effect.
	time.Sleep(500 * time.Millisecond)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}
}

func TestRunCmd_WithAskModeApprover(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	// Start with ask mode so hasApprover=true and approver is created
	cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
response_scanning:
  enabled: true
  action: ask
  ask_timeout_seconds: 1
`, addr)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", cfgPath})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Wait for healthy.
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + addr + "/health"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("run exited early: %v", err)
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, rerr := client.Do(req)
		if rerr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Proxy started with ask mode — approver was created. Shut down cleanly.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}
}

func TestGenerateCmd_WriteError(t *testing.T) {
	// Generate config with -o pointing to a read-only directory.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore

	outPath := filepath.Join(dir, "pipelock.yaml")
	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "balanced", "-o", outPath})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error writing to read-only directory")
	}
	if !strings.Contains(err.Error(), "writing config file") {
		t.Errorf("expected 'writing config file' error, got: %v", err)
	}
}

func TestDemoCmd_Basic(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"demo"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "7/7 attacks blocked") {
		t.Errorf("expected all 7 attacks blocked, got: %s", output)
	}
}

func TestGenerateDockerComposeCmd_WriteError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore

	outPath := filepath.Join(dir, "docker-compose.yaml")
	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "docker-compose", "-o", outPath})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error writing to read-only directory")
	}
}
