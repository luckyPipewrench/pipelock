// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/cli/presets"
	"github.com/luckyPipewrench/pipelock/internal/cli/runtime"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type cliTestBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *cliTestBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *cliTestBuffer) contains(s string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Contains(b.buf.Bytes(), []byte(s))
}

func (b *cliTestBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForCLIOutput(t *testing.T, buf *cliTestBuffer, errCh <-chan error, cancel context.CancelFunc, want string) {
	t.Helper()
	testwait.For(t, 5*time.Second, func() bool {
		if buf.contains(want) {
			return true
		}
		select {
		case cmdErr := <-errCh:
			cancel()
			t.Fatalf("run exited before output %q: %v\nstderr:\n%s", want, cmdErr, buf.String())
		default:
		}
		return false
	}, "CLI output %q\nstderr:\n%s", want, buf.String())
}

// reloadWaitBackstop is a generous safety deadline for waitForReloadCycle. It is
// NOT the gating mechanism (the reload-completed signal fires as soon as the
// cycle runs); it only guards a genuinely broken fsnotify watcher, so it is set
// far above any realistic CI reload latency. This is the fix for the
// reload-test-family flakiness: the old 5s stderr poll made fsnotify delivery
// latency the failure threshold; an event signal plus a large backstop removes
// the guess.
const reloadWaitBackstop = 30 * time.Second

// installReloadWaiter registers a process-global reload-completion hook and
// returns a channel that receives once per completed config reload cycle. Call
// it BEFORE writing the config under test. Cleared via t.Cleanup. Not for
// t.Parallel reload tests (the hook is process global).
func installReloadWaiter(t *testing.T) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{}, 16)
	restore := runtime.SetReloadCompletedHookForTest(func() {
		select {
		case ch <- struct{}{}:
		default:
		}
	})
	t.Cleanup(restore)
	return ch
}

// awaitReloadCycle blocks until one config reload cycle completes, the run
// command exits, or the backstop elapses. Use when the post-reload assertion is
// an HTTP effect rather than a stderr message.
func awaitReloadCycle(t *testing.T, reloaded <-chan struct{}, buf *cliTestBuffer, errCh <-chan error, cancel context.CancelFunc) {
	t.Helper()
	if err := awaitReloadCycleResult(reloaded, buf, errCh); err != nil {
		cancel()
		t.Fatal(err)
	}
}

func awaitReloadCycleResult(reloaded <-chan struct{}, buf *cliTestBuffer, errCh <-chan error) error {
	dump := ""
	if buf != nil {
		dump = "\nstderr:\n" + buf.String()
	}
	select {
	case <-reloaded:
		return nil
	case cmdErr := <-errCh:
		if cmdErr == nil {
			return fmt.Errorf("run exited before reload completed%s", dump)
		}
		return fmt.Errorf("run exited before reload completed: %w%s", cmdErr, dump)
	case <-time.After(reloadWaitBackstop):
		return fmt.Errorf("timed out waiting for config reload cycle%s", dump)
	}
}

// requireCLIOutputAfterReload blocks until one config reload cycle completes,
// then asserts want was emitted. The reload warning is always written before the
// cycle-complete signal fires, so the assertion is deterministic — no polling
// against a wall-clock deadline.
func requireCLIOutputAfterReload(t *testing.T, reloaded <-chan struct{}, buf *cliTestBuffer, errCh <-chan error, cancel context.CancelFunc, want string) {
	t.Helper()
	if err := requireCLIOutputAfterReloadResult(reloaded, buf, errCh, want); err != nil {
		cancel()
		t.Fatal(err)
	}
}

func requireCLIOutputAfterReloadResult(reloaded <-chan struct{}, buf *cliTestBuffer, errCh <-chan error, want string) error {
	if err := awaitReloadCycleResult(reloaded, buf, errCh); err != nil {
		return err
	}
	if !buf.contains(want) {
		return fmt.Errorf("expected %q in stderr after reload, got:\n%s", want, buf.String())
	}
	return nil
}

func waitForRunHTTP(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	errCh <-chan error,
	cancel context.CancelFunc,
	url string,
	check func(*http.Response) bool,
	label string,
) {
	t.Helper()
	if err := waitForRunHTTPResult(ctx, client, errCh, url, check, label); err != nil {
		cancel()
		t.Fatalf("run did not become ready: %v", err)
	}
}

func waitForRunHTTPResult(
	ctx context.Context,
	client *http.Client,
	errCh <-chan error,
	url string,
	check func(*http.Response) bool,
	label string,
) error {
	return waitForRunHTTPWithinResult(5*time.Second, ctx, client, errCh, url, check, "%s", label)
}

func waitForRunHTTPWithin(
	t *testing.T,
	timeout time.Duration,
	ctx context.Context,
	client *http.Client,
	errCh <-chan error,
	cancel context.CancelFunc,
	url string,
	check func(*http.Response) bool,
	format string,
	args ...any,
) {
	t.Helper()
	err := waitForRunHTTPWithinResult(timeout, ctx, client, errCh, url, check, format, args...)
	if err != nil {
		cancel()
		t.Fatalf("run did not become ready: %v", err)
	}
}

func waitForRunHTTPWithinResult(
	timeout time.Duration,
	ctx context.Context,
	client *http.Client,
	errCh <-chan error,
	url string,
	check func(*http.Response) bool,
	format string,
	args ...any,
) error {
	return waitForRunRequestWithinResult(ctx, timeout, errCh, func(reqCtx context.Context) *http.Request {
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		return req
	}, client, check, format, args...)
}

func waitForRunRequestWithin(
	t *testing.T,
	ctx context.Context,
	timeout time.Duration,
	errCh <-chan error,
	cancel context.CancelFunc,
	newReq func(context.Context) *http.Request,
	client *http.Client,
	check func(*http.Response) bool,
	format string,
	args ...any,
) {
	t.Helper()
	err := waitForRunRequestWithinResult(ctx, timeout, errCh, newReq, client, check, format, args...)
	if err != nil {
		cancel()
		t.Fatalf("run did not become ready: %v", err)
	}
}

func waitForRunRequestWithinResult(
	parentCtx context.Context,
	timeout time.Duration,
	errCh <-chan error,
	newReq func(context.Context) *http.Request,
	client *http.Client,
	check func(*http.Response) bool,
	format string,
	args ...any,
) error {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	detail := fmt.Sprintf(format, args...)
	for {
		select {
		case cmdErr := <-errCh:
			return fmt.Errorf("run exited early while waiting for %s: %w", detail, cmdErr)
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s: %w", detail, ctx.Err())
		default:
		}
		req := newReq(ctx)
		resp, err := client.Do(req) //nolint:gosec // G704: test-only URL built from loopback listener.
		if err == nil {
			ok := check(resp)
			_ = resp.Body.Close()
			if ok {
				return nil
			}
		}

		select {
		case cmdErr := <-errCh:
			return fmt.Errorf("run exited early while waiting for %s: %w", detail, cmdErr)
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s: %w", detail, ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestRootCmd_Version(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--version"})

	// Capture output
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), cliutil.Version) {
		t.Errorf("expected version output to contain %q, got %q", cliutil.Version, buf.String())
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

// TestCheckCmd_MediationEnvelopeSignRequiresKey proves that an operator
// who ships a config with mediation_envelope.sign=true but no
// signing_key_path gets a loud failure from `pipelock check` before
// the binary ever starts serving traffic. This is the first line of
// defence against "signing silently disabled because the key path was
// a typo" regressions.
func TestCheckCmd_MediationEnvelopeSignRequiresKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sign-no-key.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
mode: balanced
mediation_envelope:
  enabled: true
  sign: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--config", cfgPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected pipelock check to fail when sign:true is set without signing_key_path")
	}
	if !strings.Contains(err.Error(), "signing_key_path is required") {
		t.Errorf("error = %q, want a signing_key_path message", err.Error())
	}
}

// TestCheckCmd_MediationEnvelopeSignUnreadableKey proves that a
// config pointing at a missing key file also fails loud at `check`
// time. Mirrors the common "Kubernetes Secret did not mount yet"
// misconfiguration.
func TestCheckCmd_MediationEnvelopeSignUnreadableKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sign-missing-key.yaml")
	keyPath := filepath.Join(dir, "does-not-exist.key")
	yaml := `
mode: balanced
mediation_envelope:
  enabled: true
  sign: true
  signing_key_path: ` + keyPath + `
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--config", cfgPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected pipelock check to fail when signing_key_path points at a missing file")
	}
	if !strings.Contains(err.Error(), "signing_key_path") {
		t.Errorf("error = %q, want a signing_key_path message", err.Error())
	}
}

// TestCheckCmd_MediationEnvelopeSignUnsupportedComponent proves that
// a config listing a component outside the signer's supported set
// (e.g. "host" or "authorization") is rejected at check time. Without
// this, typos in signed_components would silently widen or weaken
// coverage based on what the signer happened to support on that day.
func TestCheckCmd_MediationEnvelopeSignUnsupportedComponent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sign-bad-component.yaml")
	keyPath := filepath.Join(dir, "key")

	// Need a real key for the file load to pass and the component
	// validation to be the blocking error.
	if err := writeTempEd25519Key(t, keyPath); err != nil {
		t.Fatal(err)
	}

	yaml := `
mode: balanced
mediation_envelope:
  enabled: true
  sign: true
  signing_key_path: ` + keyPath + `
  signed_components:
    - "@method"
    - "host"
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"check", "--config", cfgPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected pipelock check to fail for unsupported signed_components entry")
	}
	if !strings.Contains(err.Error(), "signed_components") {
		t.Errorf("error = %q, want a signed_components message", err.Error())
	}
}

// writeTempEd25519Key generates a throwaway Ed25519 key and writes
// it to path using the same SavePrivateKey helper that production
// code uses so the file passes signing.LoadPrivateKeyFile's
// permission + format checks.
func writeTempEd25519Key(t *testing.T, path string) error {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return signing.SavePrivateKey(priv, path)
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
	// check --url runs SSRF checks that require DNS resolution.
	// Skip in restricted/offline environments where DNS is blocked.
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dnsCancel()
	if _, err := net.DefaultResolver.LookupHost(dnsCtx, "example.com"); err != nil {
		t.Skip("DNS unavailable (restricted environment)")
	}

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
	if !errors.Is(err, diag.ErrURLBlocked) {
		t.Errorf("expected ErrURLBlocked, got: %v", err)
	}

	if !strings.Contains(buf.String(), "BLOCKED") {
		t.Errorf("expected BLOCKED in output, got: %q", buf.String())
	}
}

func TestGenerateCmd_AllPresets(t *testing.T) {
	for _, preset := range presets.All {
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

func TestGenerateCmd_OutputPassesValidation(t *testing.T) {
	// Regression: generated configs must be re-loadable without validation errors.
	// This catches reserved fields (e.g. dlp.action) being emitted when they shouldn't be.
	for _, preset := range presets.All {
		t.Run(preset, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetArgs([]string{"generate", "config", "--preset", preset})

			buf := &strings.Builder{}
			cmd.SetOut(buf)
			cmd.SetErr(&strings.Builder{})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("generate config --preset %s failed: %v", preset, err)
			}

			// Write the output to a temp file and reload it.
			dir := t.TempDir()
			cfgPath := dir + "/generated.yaml"
			if err := os.WriteFile(cfgPath, []byte(buf.String()), 0o600); err != nil {
				t.Fatalf("write generated config: %v", err)
			}
			if _, err := config.Load(cfgPath); err != nil {
				t.Errorf("generated %s config fails validation on reload: %v", preset, err)
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

	data, err := os.ReadFile(filepath.Clean(outPath))
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

func TestHealthcheckCmd_NoServer(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"healthcheck", "--addr", "127.0.0.1:19999"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no server is running")
	}
}

func TestHealthcheckCmd_Healthy(t *testing.T) {
	// Use explicit IPv4 listener to avoid IPv6 failures in sandboxed environments.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on IPv4 loopback: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

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

// TestRunCmd_Integration starts the proxy from a config file and verifies the
// --mode flag overrides the file's mode (balanced -> strict) in /health.
func TestRunCmd_Integration(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

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
`, addr, filepath.ToSlash(logPath))
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
		if err := waitForRunRequestWithinResult(ctx, 5*time.Second, errCh, func(reqCtx context.Context) *http.Request {
			req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, healthURL, nil)
			return req
		}, client, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		// Verify the health response shows the flag override (strict, not balanced)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, err := client.Do(req) //nolint:gosec // G704: test-only, URL from httptest server
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
		if health["mode"] != config.ModeStrict {
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
		return nil
	})
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
	cancel() // cancel immediately - we don't want the server to start

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--config", cfgPath})
	stderr := &cliTestBuffer{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(stderr)

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

// TestRunCmd_InvalidMode verifies an invalid --mode override is rejected with
// an "invalid config" error before the server starts.
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
`, filepath.ToSlash(logPath))
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
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

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
		if err := waitForRunRequestWithinResult(ctx, 5*time.Second, errCh, func(reqCtx context.Context) *http.Request {
			req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, healthURL, nil)
			return req
		}, client, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
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
		return nil
	})
}

func TestHealthcheckCmd_Unhealthy(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on IPv4 loopback: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")

	cmd := rootCmd()
	cmd.SetArgs([]string{"healthcheck", "--addr", addr})

	err = cmd.Execute()
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

func TestRunCmd_WithAgentArgs(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

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
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
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
		// parsing path (dashIdx >= 0) was exercised.
		return nil
	})
}

func TestRunCmd_DefaultMode(t *testing.T) {
	// Run with no config, no flags - should use default balanced mode.
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

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
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			return health["mode"] == config.ModeBalanced
		}, "balanced mode health"); err != nil {
			cancel()
			return err
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
		return nil
	})
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
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

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
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			return health["mode"] == config.ModeStrict
		}, "strict mode health"); err != nil {
			cancel()
			return err
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
		return nil
	})
}

func TestRunCmd_WithConfigHotReload(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

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
		stderr := &cliTestBuffer{}
		cmd.SetOut(io.Discard)
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + addr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		// Modify the config to trigger hot-reload via fsnotify.
		updatedCfg := fmt.Sprintf(`version: 1
mode: strict
api_allowlist:
  - "api.example.com"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, addr)
		if err := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); err != nil {
			t.Fatal(err)
		}

		waitForRunHTTP(t, ctx, client, errCh, cancel, healthURL, func(resp *http.Response) bool {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			return health["mode"] == config.ModeStrict
		}, "strict mode after hot reload")

		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}
		return nil
	})
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
	stderr := &cliTestBuffer{}
	cmd.SetErr(stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for bad log file path")
	}
}

func TestRunCmd_ReloadToAskMode(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		// Start with default balanced taint policy, which initializes a HITL
		// approver because taint decisions can ask.
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
		stderr := &cliTestBuffer{}
		cmd.SetOut(io.Discard)
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + addr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		reloaded := installReloadWaiter(t)

		// Reload config to action: ask and audit mode. The mode change is the
		// observable signal that the reload carrying ask-mode config landed.
		updatedCfg := fmt.Sprintf(`version: 1
mode: audit
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

		// Gate on the reload-cycle-complete signal so fsnotify delivery latency
		// (plus the 100ms debounce and the atomic config swap) is not the
		// failure threshold under the heavy -race CI job. Once the cycle has
		// run, the new config is live, so the health check below confirms the
		// effect immediately rather than polling against a wall-clock deadline.
		awaitReloadCycle(t, reloaded, stderr, errCh, cancel)
		waitForRunHTTPWithin(t, reloadWaitBackstop, ctx, client, errCh, cancel, healthURL, func(resp *http.Response) bool {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			return health["mode"] == config.ModeAudit
		}, "%s", "audit ask-mode config after hot reload")

		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}
		return nil
	})
}

func TestRunCmd_WithAskModeApprover(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		// Start with response ask mode so hasApprover=true and approver is created.
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
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		// Proxy started with ask mode - approver was created. Shut down cleanly.
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}
		return nil
	})
}

func TestRunCmd_ForwardProxyBanner(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
forward_proxy:
  enabled: true
  max_tunnel_seconds: 10
  idle_timeout_seconds: 2
`, addr)
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var stderrBuf bytes.Buffer
		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"run", "--config", cfgPath})
		cmd.SetOut(io.Discard)
		cmd.SetErr(&stderrBuf)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + addr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		// Verify health shows forward_proxy_enabled=true
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			t.Fatalf("health request failed: %v", err)
		}
		var health map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&health)
		_ = resp.Body.Close()
		if health["forward_proxy_enabled"] != true {
			t.Errorf("expected forward_proxy_enabled=true, got %v", health["forward_proxy_enabled"])
		}

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}

		// Check stderr banner printed the forward proxy line
		if !strings.Contains(stderrBuf.String(), "forward proxy enabled") {
			t.Errorf("expected forward proxy banner in stderr, got: %s", stderrBuf.String())
		}
		return nil
	})
}

// TestRunCmd_ReloadRejectsForwardProxyEnable verifies that enabling forward_proxy
// via hot reload is rejected and the proxy keeps it disabled.
func TestRunCmd_ReloadRejectsForwardProxyEnable(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		logPath := filepath.Join(dir, "audit.log")
		// Start with forward_proxy disabled
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
forward_proxy:
  enabled: false
logging:
  output: file
  file: "%s"
`, addr, filepath.ToSlash(logPath))
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
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		reloaded := installReloadWaiter(t)

		// Hot-reload: enable forward_proxy (should be rejected)
		updatedCfg := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
forward_proxy:
  enabled: true
  max_tunnel_seconds: 10
  idle_timeout_seconds: 2
logging:
  output: file
  file: "%s"
`, addr, filepath.ToSlash(logPath))
		if err := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); err != nil {
			t.Fatal(err)
		}

		// Gate on the reload-cycle-complete signal so fsnotify delivery latency
		// is not the failure threshold; the short poll below then only covers
		// audit-log file flush, which is fast.
		awaitReloadCycle(t, reloaded, nil, errCh, cancel)
		testwait.For(t, reloadWaitBackstop, func() bool {
			select {
			case cmdErr := <-errCh:
				cancel()
				t.Fatalf("run exited before rejected reload log: %v", cmdErr)
			default:
			}
			logBytes, err := os.ReadFile(filepath.Clean(logPath))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("read audit log: %v", err)
			}
			return strings.Contains(string(logBytes), "forward proxy cannot be enabled via reload")
		}, "rejected forward proxy reload log")

		waitForRunHTTP(t, ctx, client, errCh, cancel, healthURL, func(resp *http.Response) bool {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			return health["forward_proxy_enabled"] == false
		}, "forward proxy remains disabled after rejected reload")

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}
		return nil
	})
}

func TestRunCmd_MCPListenRequiresUpstream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--mcp-listen", "127.0.0.1:0"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --mcp-listen without --mcp-upstream")
	}
	if !strings.Contains(err.Error(), "--mcp-listen requires --mcp-upstream") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunCmd_MCPUpstreamRequiresListen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--mcp-upstream", "http://localhost:3000/mcp"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --mcp-upstream without --mcp-listen")
	}
	if !strings.Contains(err.Error(), "--mcp-upstream requires --mcp-listen") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunCmd_MCPUpstreamInvalidURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"run", "--mcp-listen", "127.0.0.1:0", "--mcp-upstream", "not-a-url"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
	if !strings.Contains(err.Error(), "invalid --mcp-upstream") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunCmd_MCPListenInHelp(t *testing.T) {
	cmd := rootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"run", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "--mcp-listen") {
		t.Error("help should mention --mcp-listen")
	}
	if !strings.Contains(output, "--mcp-upstream") {
		t.Error("help should mention --mcp-upstream")
	}
}

func TestRunCmd_MCPListenBanner(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		fetchAddr := addrs[0]
		mcpAddr := addrs[1]

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{
			"run",
			"--listen", fetchAddr,
			"--mcp-listen", mcpAddr,
			"--mcp-upstream", "http://localhost:19999",
		})
		cmd.SetOut(io.Discard)
		errBuf := &cliTestBuffer{}
		cmd.SetErr(errBuf)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for fetch proxy health.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + fetchAddr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "fetch proxy health"); err != nil {
			cancel()
			return err
		}

		// Verify MCP listener health endpoint.
		mcpHealthURL := "http://" + mcpAddr + "/health"
		waitForRunHTTP(t, ctx, client, errCh, cancel, mcpHealthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "MCP listener health")

		// Verify banner mentions MCP.
		waitForCLIOutput(t, errBuf, errCh, cancel, "MCP:")

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}
		return nil
	})
}

func TestRunCmd_MCPListenStartupFailure(t *testing.T) {
	// Occupy a port, then start pipelock run with --mcp-listen on the same port.
	// The run command should fail immediately with a bind error instead of
	// silently running the fetch proxy without MCP protection.
	lc := net.ListenConfig{}
	blocker, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close() //nolint:errcheck // test
	occupiedPort := blocker.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{
		"run",
		"--listen", "127.0.0.1:0",
		"--mcp-listen", occupiedPort,
		"--mcp-upstream", "http://localhost:19999",
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	cmdErr := cmd.Execute()
	if cmdErr == nil {
		cancel()
		t.Fatal("expected bind error, but run succeeded")
	}
	if !strings.Contains(cmdErr.Error(), "mcp_listen bind") {
		t.Errorf("expected 'mcp_listen bind' error, got: %v", cmdErr)
	}
}

func TestRunCmd_MCPListenReloadUsesResolvedConfigForWarnings(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		fetchAddr := addrs[0]
		mcpAddr := addrs[1]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, fetchAddr)
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{
			"run",
			"--config", cfgPath,
			"--mcp-listen", mcpAddr,
			"--mcp-upstream", "http://localhost:19999",
		})
		cmd.SetOut(io.Discard)
		stderr := &cliTestBuffer{}
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + fetchAddr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "fetch proxy health"); err != nil {
			cancel()
			return err
		}

		reloaded := installReloadWaiter(t)

		updatedCfg := fmt.Sprintf(`version: 1
mode: strict
api_allowlist:
  - "api.example.com"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, fetchAddr)
		if err := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); err != nil {
			t.Fatal(err)
		}

		awaitReloadCycle(t, reloaded, stderr, errCh, cancel)
		waitForRunHTTPWithin(t, reloadWaitBackstop, ctx, client, errCh, cancel, healthURL, func(resp *http.Response) bool {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			return health["mode"] == config.ModeStrict
		}, "%s", "strict mode after hot reload")

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}

		output := stderr.String()
		for _, field := range []string{
			"mcp_input_scanning.enabled",
			"mcp_tool_scanning.enabled",
			"mcp_tool_policy.enabled",
		} {
			if strings.Contains(output, field) {
				t.Errorf("unexpected false-positive reload warning for %s:\n%s", field, output)
			}
		}
		return nil
	})
}

func TestRunCmd_MCPListenReloadStrictAllowsKillSwitchAPIToken(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		fetchAddr := addrs[0]
		mcpAddr := addrs[1]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: strict
api_allowlist:
  - "api.example.com"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, fetchAddr)
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{
			"run",
			"--config", cfgPath,
			"--mcp-listen", mcpAddr,
			"--mcp-upstream", "http://localhost:19999",
		})
		cmd.SetOut(io.Discard)
		var stderr bytes.Buffer
		cmd.SetErr(&stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + fetchAddr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "fetch proxy health"); err != nil {
			cancel()
			return err
		}

		statusURL := "http://" + fetchAddr + "/api/v1/killswitch/status"
		statusReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		statusReq.Header.Set("Authorization", "Bearer reload-token")
		resp, err := client.Do(statusReq)
		if err != nil {
			cancel()
			t.Fatalf("kill switch status request failed before reload: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 before reload, got %d", resp.StatusCode)
		}

		updatedCfg := fmt.Sprintf(`version: 1
mode: strict
api_allowlist:
  - "api.example.com"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
kill_switch:
  api_token: "reload-token"
`, fetchAddr)
		if err := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); err != nil {
			t.Fatal(err)
		}

		lastReloadWrite := time.Now()
		waitForRunRequestWithin(t, ctx, 15*time.Second, errCh, cancel, func(reqCtx context.Context) *http.Request {
			req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, statusURL, nil)
			req.Header.Set("Authorization", "Bearer reload-token")
			return req
		}, client, func(resp *http.Response) bool {
			if resp.StatusCode == http.StatusOK {
				return true
			}
			// /health can become reachable before the config watcher has armed.
			// Rewriting the same target config gives the watcher another observable
			// event without weakening the reload assertion.
			if time.Since(lastReloadWrite) >= 250*time.Millisecond {
				if err := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); err != nil {
					cancel()
					t.Fatalf("rewrite updated config: %v", err)
				}
				lastReloadWrite = time.Now()
			}
			return false
		}, "kill switch API token after strict-mode reload")

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}

		output := stderr.String()
		for _, field := range []string{
			"mcp_input_scanning.enabled",
			"mcp_tool_scanning.enabled",
			"mcp_tool_policy.enabled",
		} {
			if strings.Contains(output, field) {
				t.Errorf("unexpected false-positive reload warning for %s:\n%s", field, output)
			}
		}
		return nil
	})
}

// TestGenerateCmd_WriteError verifies "generate config" surfaces a wrapped
// "writing config file" error when the output path cannot be written.
func TestGenerateCmd_WriteError(t *testing.T) {
	// Point -o at an existing directory so os.WriteFile fails on every
	// platform. This exercises the write-error path portably, without
	// relying on Unix-only chmod 0500 directory permissions.
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "balanced", "-o", dir})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error writing config to a directory path")
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

// TestGenerateDockerComposeCmd_WriteError verifies "generate docker-compose"
// surfaces a wrapped "writing compose file" error when the output path cannot
// be written.
func TestGenerateDockerComposeCmd_WriteError(t *testing.T) {
	// Point -o at an existing directory so os.WriteFile fails on every
	// platform. This exercises the write-error path portably, without
	// relying on Unix-only chmod 0500 directory permissions.
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "docker-compose", "-o", dir})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error writing compose file to a directory path")
	}
	if !strings.Contains(err.Error(), "writing compose file") {
		t.Errorf("expected 'writing compose file' error, got: %v", err)
	}
}

func TestRunCmd_ReloadRejectsMetricsListenChange(t *testing.T) {
	testport.WithRetry(t, 3, func(addrs []string) error {
		mainAddr := addrs[0]
		metricsAddr := addrs[1]
		newMetricsAddr := addrs[2]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
metrics_listen: "%s"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, metricsAddr, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"run", "--config", cfgPath})
		stderr := &cliTestBuffer{}
		cmd.SetOut(io.Discard)
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + mainAddr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		reloaded := installReloadWaiter(t)

		// Hot-reload: change metrics_listen (should be rejected).
		updatedCfg := fmt.Sprintf(`version: 1
mode: balanced
metrics_listen: "%s"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, newMetricsAddr, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		if err := requireCLIOutputAfterReloadResult(reloaded, stderr, errCh, "metrics_listen changed"); err != nil {
			cancel()
			return err
		}

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}

		// Safe to read stderr now that the command has exited.
		if !stderr.contains("metrics_listen changed") {
			t.Errorf("expected metrics_listen reload warning, got:\n%s", stderr.String())
		}
		return nil
	})
}

func TestRunCmd_ReloadLicenseKeyChange(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		mainAddr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
license_key: "old-key"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"run", "--config", cfgPath})
		stderr := &cliTestBuffer{}
		cmd.SetOut(io.Discard)
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + mainAddr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		reloaded := installReloadWaiter(t)

		// Hot-reload: change license_key (should warn).
		updatedCfg := fmt.Sprintf(`version: 1
mode: balanced
license_key: "new-key"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		requireCLIOutputAfterReload(t, reloaded, stderr, errCh, cancel, "license key inputs changed")

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}

		// Verify license change warning appeared.
		if !stderr.contains("license key inputs changed") {
			t.Errorf("expected license reload warning, got:\n%s", stderr.String())
		}
		return nil
	})
}

func TestRunCmd_ReloadLicenseNoSpuriousWarning(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		mainAddr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
license_key: "same-key"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"run", "--config", cfgPath})
		stderr := &cliTestBuffer{}
		cmd.SetOut(io.Discard)
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + mainAddr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		reloaded := installReloadWaiter(t)

		// Hot-reload: same license_key, change something else (mode).
		updatedCfg := fmt.Sprintf(`version: 1
mode: audit
license_key: "same-key"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		requireCLIOutputAfterReload(t, reloaded, stderr, errCh, cancel, "mode downgraded from balanced to audit")

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}

		// Verify NO license warning appeared (same key, just mode change).
		if stderr.contains("license") {
			t.Errorf("unexpected license warning on non-license reload:\n%s", stderr.String())
		}
		return nil
	})
}

func TestRunCmd_ReloadLicenseFileChange(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		mainAddr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"run", "--config", cfgPath})
		stderr := &cliTestBuffer{}
		cmd.SetOut(io.Discard)
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + mainAddr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		// Write a license token file so the config reload succeeds.
		tokenPath := filepath.Join(dir, "license.token")
		if writeErr := os.WriteFile(tokenPath, []byte("some-token"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		reloaded := installReloadWaiter(t)

		// Hot-reload: add license_file (should warn about license inputs change).
		updatedCfg := fmt.Sprintf(`version: 1
mode: balanced
license_file: "license.token"
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
`, mainAddr)
		if writeErr := os.WriteFile(cfgPath, []byte(updatedCfg), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		requireCLIOutputAfterReload(t, reloaded, stderr, errCh, cancel, "license key inputs changed")

		cancel()
		select {
		case cmdErr := <-errCh:
			if cmdErr != nil {
				t.Errorf("unexpected error: %v", cmdErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}

		// Verify license change warning appeared from license_file addition.
		if !stderr.contains("license key inputs changed") {
			t.Errorf("expected license reload warning from license_file change, got:\n%s", stderr.String())
		}
		return nil
	})
}

func TestRunCmd_WebSocketBanner(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		addr := addrs[0]

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "test.yaml")
		cfgContent := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: "%s"
  timeout_seconds: 5
websocket_proxy:
  enabled: true
  max_message_bytes: 65536
`, addr)
		if writeErr := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"run", "--config", cfgPath})
		stderr := &cliTestBuffer{}
		cmd.SetOut(io.Discard)
		cmd.SetErr(stderr)

		errCh := make(chan error, 1)
		go func() {
			errCh <- cmd.Execute()
		}()

		// Wait for healthy.
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + addr + "/health"
		if err := waitForRunHTTPResult(ctx, client, errCh, healthURL, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusOK
		}, "proxy health"); err != nil {
			cancel()
			return err
		}

		waitForCLIOutput(t, stderr, errCh, cancel, "WebSocket proxy enabled")
		if !stderr.contains("WebSocket proxy enabled") {
			t.Errorf("expected WS banner, got:\n%s", stderr.String())
		}

		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("unexpected run error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not shut down")
		}
		return nil
	})
}
