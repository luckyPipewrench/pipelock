package cli

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd := rootCmd()
	cmd.SetArgs([]string{"check"})

	err := cmd.Execute()
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out, _ := io.ReadAll(r)
	output := string(out)
	if !strings.Contains(output, "default config") {
		t.Errorf("expected output to mention default config, got: %q", output)
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
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
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

	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml}}"), 0644); err != nil {
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
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--url", "https://example.com"})

	err := cmd.Execute()
	_ = w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("expected no error for allowed URL, got: %v", err)
	}

	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "ALLOWED") {
		t.Errorf("expected ALLOWED in output, got: %q", string(out))
	}
}

func TestCheckCmd_URLBlocked(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--url", "https://pastebin.com/raw/abc123"})

	err := cmd.Execute()
	_ = w.Close()
	os.Stdout = old

	if err == nil {
		t.Fatal("expected error for blocked URL")
	}
	if !errors.Is(err, ErrURLBlocked) {
		t.Errorf("expected ErrURLBlocked, got: %v", err)
	}

	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "BLOCKED") {
		t.Errorf("expected BLOCKED in output, got: %q", string(out))
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

	data, err := os.ReadFile(outPath)
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
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
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
	if err := os.WriteFile(logPath, []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}

	// Commands print to os.Stdout via fmt.Println, so capture it
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", logPath, "--filter", "blocked"})
	cmd.SetErr(os.Stderr)

	err := cmd.Execute()
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out, _ := io.ReadAll(r)
	output := string(out)

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
	if err := os.WriteFile(logPath, []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd := rootCmd()
	cmd.SetArgs([]string{"logs", "--file", logPath, "--last", "1"})
	cmd.SetErr(os.Stderr)

	err := cmd.Execute()
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out, _ := io.ReadAll(r)
	output := string(out)

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
