// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// testRunContext returns the expected run context for the current test
// environment. This makes tests work both on host and in container CI.
func testRunContext() string {
	return cliutil.DetectRunContext()
}

// diagTestConfig returns a config suitable for unit-testing individual check
// functions, matching the pattern used in the original cli package.
func diagTestConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return cfg
}

func TestVerifyInstallCmd_AllPass(t *testing.T) {
	var buf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--no-color"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-install failed: %v", err)
	}
	out := buf.String()

	// All 7 scanning checks should pass.
	if !strings.Contains(out, "Scanning: verified") {
		t.Errorf("expected 'Scanning: verified' in output:\n%s", out)
	}

	ctx := testRunContext()
	if ctx == cliutil.RunContextHost {
		if !strings.Contains(out, "Containment: unknown") {
			t.Errorf("expected 'Containment: unknown' in output:\n%s", out)
		}
		if !strings.Contains(out, "7/10 passed") {
			t.Errorf("expected '7/10 passed' in output:\n%s", out)
		}
		if !strings.Contains(out, "3 not applicable") {
			t.Errorf("expected '3 not applicable' in output:\n%s", out)
		}
	}
	// No failures regardless of context (defaults have all protections).
	if strings.Contains(out, "FAIL") {
		t.Errorf("unexpected FAIL in output:\n%s", out)
	}
}

func TestVerifyInstallCmd_JSON(t *testing.T) {
	var buf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json", "--no-color"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-install --json failed: %v", err)
	}

	var report VerifyReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if report.Version == "" {
		t.Error("expected non-empty version")
	}
	ctx := testRunContext()
	if report.RunContext != ctx {
		t.Errorf("expected %s context, got %s", ctx, report.RunContext)
	}
	if len(report.Checks) != 10 {
		t.Errorf("expected 10 checks, got %d", len(report.Checks))
	}

	// Scanning should always be verified with defaults.
	if report.Summary.Scanning != verifyScanningVerified {
		t.Errorf("expected scanning=verified, got %s", report.Summary.Scanning)
	}
	if report.Summary.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", report.Summary.Failed)
	}

	if ctx == cliutil.RunContextHost {
		if report.Summary.Passed != 7 {
			t.Errorf("expected 7 passed on host, got %d", report.Summary.Passed)
		}
		if report.Summary.NotApplicable != 3 {
			t.Errorf("expected 3 not_applicable on host, got %d", report.Summary.NotApplicable)
		}
		if report.Summary.Containment != verifyContainmentUnknown {
			t.Errorf("expected containment=unknown on host, got %s", report.Summary.Containment)
		}
	} else {
		// In container/pod: at least 7 scanning checks pass.
		if report.Summary.Passed < 7 {
			t.Errorf("expected at least 7 passed, got %d", report.Summary.Passed)
		}
	}

	// Verify all check names are present.
	names := make(map[string]bool)
	for _, c := range report.Checks {
		names[c.Name] = true
	}
	expected := []string{
		"config_valid", "proxy_health", "fetch_dlp", "forward_blocked",
		"scanning_dlp", "scanning_injection", "scanning_policy",
		"no_direct_http", "no_direct_dns", "no_direct_https",
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing check %q in report", name)
		}
	}
}

func TestVerifyInstallCmd_WeakConfig(t *testing.T) {
	// Create a config with protections disabled.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "weak.yaml")
	weakCfg := `version: 1
mode: balanced
forward_proxy:
  enabled: false
mcp_tool_policy:
  enabled: false
response_scanning:
  enabled: false
mcp_input_scanning:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(weakCfg), 0o600); err != nil {
		t.Fatalf("writing weak config: %v", err)
	}

	var buf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--json", "--no-color", "--config", cfgPath})
	err := cmd.Execute()

	// Should fail because disabled features are reported as failures.
	if err == nil {
		t.Fatal("expected error for weak config, got nil")
	}

	var report VerifyReport
	if jsonErr := json.Unmarshal(buf.Bytes(), &report); jsonErr != nil {
		t.Fatalf("invalid JSON: %v\n%s", jsonErr, buf.String())
	}

	if report.Summary.Failed == 0 {
		t.Error("expected failures for disabled features, got 0")
	}
	if report.Summary.Scanning == verifyScanningVerified {
		t.Error("weak config should not report scanning=verified")
	}

	// Verify specific disabled checks failed.
	failedNames := make(map[string]bool)
	for _, c := range report.Checks {
		if c.Status == verifyStatusFail {
			failedNames[c.Name] = true
		}
	}
	for _, name := range []string{"forward_blocked", "scanning_dlp", "scanning_injection", "scanning_policy"} {
		if !failedNames[name] {
			t.Errorf("expected %q to fail with weak config", name)
		}
	}
}

func TestVerifyInstallCmd_Help(t *testing.T) {
	var buf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	out := buf.String()
	for _, keyword := range []string{"verify-install", "scanning", "containment", "Ed25519"} {
		if !strings.Contains(out, keyword) {
			t.Errorf("expected %q in help output", keyword)
		}
	}
}

func TestVerifyInstallCmd_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.json")

	var buf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json", "--no-color", "--output", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-install --output failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	var report VerifyReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON in output file: %v", err)
	}
	if len(report.Checks) != 10 {
		t.Errorf("expected 10 checks in file, got %d", len(report.Checks))
	}
}

func TestVerifyInstallCmd_Sign(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	// Generate a key pair.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("saving key: %v", err)
	}

	var buf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json", "--no-color", "--sign", keyPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-install --sign failed: %v", err)
	}

	var report VerifyReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Signature == "" {
		t.Fatal("expected non-empty signature")
	}

	// Verify signature by re-marshalling without signature.
	report.Signature = ""
	canonical, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("canonical marshal: %v", err)
	}

	// Re-read original to get the signature back.
	var withSig VerifyReport
	if err := json.Unmarshal(buf.Bytes(), &withSig); err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(withSig.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, canonical, sigBytes) {
		t.Error("signature verification failed")
	}
}

func TestDetectRunContext(t *testing.T) {
	ctx := cliutil.DetectRunContext()
	// Valid contexts: host, container, pod.
	switch ctx {
	case cliutil.RunContextHost, cliutil.RunContextContainer, cliutil.RunContextPod:
		// OK
	default:
		t.Errorf("unexpected context %q", ctx)
	}
}

func TestBuildDNSQuery(t *testing.T) {
	q := buildDNSQuery()
	// 12 (header) + 13 (7example3com0) + 4 (qtype+qclass) = 29 bytes.
	if len(q) != 29 {
		t.Errorf("expected 29 bytes, got %d", len(q))
	}
}

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"scanning", "Scanning"},
		{"containment", "Containment"},
		{"", ""},
		{"a", "A"},
	}
	for _, tt := range tests {
		got := capitalizeFirst(tt.in)
		if got != tt.want {
			t.Errorf("capitalizeFirst(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// mockConn is a minimal net.Conn for testing containment probes.
type mockConn struct {
	readData []byte
	readErr  error
	closed   bool
}

func (c *mockConn) Read(b []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	n := copy(b, c.readData)
	return n, nil
}

func (c *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *mockConn) Close() error                       { c.closed = true; return nil }
func (c *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestCheckNoDirectHTTP_Blocked(t *testing.T) {
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextContainer,
		DialTCP: func(_ string) (net.Conn, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}
	r := checkNoDirectHTTP(env)
	if r.Status != verifyStatusPass {
		t.Errorf("expected pass (blocked), got %s: %s", r.Status, r.Detail)
	}
	if r.Evidence["error"] == "" {
		t.Error("expected error in evidence")
	}
}

func TestCheckNoDirectHTTP_Exposed(t *testing.T) {
	mc := &mockConn{}
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextContainer,
		DialTCP: func(_ string) (net.Conn, error) {
			return mc, nil
		},
	}
	r := checkNoDirectHTTP(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail (exposed), got %s: %s", r.Status, r.Detail)
	}
	if !mc.closed {
		t.Error("expected connection to be closed")
	}
}

func TestCheckNoDirectHTTPS_Blocked(t *testing.T) {
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextPod,
		DialTCP: func(_ string) (net.Conn, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}
	r := checkNoDirectHTTPS(env)
	if r.Status != verifyStatusPass {
		t.Errorf("expected pass (blocked), got %s: %s", r.Status, r.Detail)
	}
}

func TestCheckNoDirectHTTPS_Exposed(t *testing.T) {
	mc := &mockConn{}
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextPod,
		DialTCP: func(_ string) (net.Conn, error) {
			return mc, nil
		},
	}
	r := checkNoDirectHTTPS(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail (exposed), got %s: %s", r.Status, r.Detail)
	}
}

func TestCheckNoDirectDNS_DialBlocked(t *testing.T) {
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextContainer,
		DialUDP: func(_ string) (net.Conn, error) {
			return nil, fmt.Errorf("network unreachable")
		},
	}
	r := checkNoDirectDNS(env)
	if r.Status != verifyStatusPass {
		t.Errorf("expected pass (dial blocked), got %s: %s", r.Status, r.Detail)
	}
}

func TestCheckNoDirectDNS_WriteBlocked(t *testing.T) {
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextContainer,
		DialUDP: func(_ string) (net.Conn, error) {
			return &writeFailConn{}, nil
		},
	}
	r := checkNoDirectDNS(env)
	if r.Status != verifyStatusPass {
		t.Errorf("expected pass (write blocked), got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "write failed") {
		t.Errorf("expected 'write failed' detail, got: %s", r.Detail)
	}
}

func TestCheckNoDirectDNS_NoResponse(t *testing.T) {
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextPod,
		DialUDP: func(_ string) (net.Conn, error) {
			return &mockConn{readErr: fmt.Errorf("read timeout")}, nil
		},
	}
	r := checkNoDirectDNS(env)
	if r.Status != verifyStatusPass {
		t.Errorf("expected pass (no response), got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "no response") {
		t.Errorf("expected 'no response' detail, got: %s", r.Detail)
	}
}

func TestCheckNoDirectDNS_Exposed(t *testing.T) {
	// Return a fake DNS response (just needs to not error on Read).
	env := &VerifyEnv{
		RunCtx: cliutil.RunContextContainer,
		DialUDP: func(_ string) (net.Conn, error) {
			return &mockConn{readData: make([]byte, 64)}, nil
		},
	}
	r := checkNoDirectDNS(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail (exposed), got %s: %s", r.Status, r.Detail)
	}
}

// writeFailConn succeeds on dial but fails on write.
type writeFailConn struct{ mockConn }

func (c *writeFailConn) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write blocked")
}

func TestVerifyStatusIcon(t *testing.T) {
	// No color.
	if got := verifyStatusIcon(verifyStatusPass, false); got != "PASS" {
		t.Errorf("expected PASS, got %q", got)
	}
	if got := verifyStatusIcon(verifyStatusFail, false); got != "FAIL" {
		t.Errorf("expected FAIL, got %q", got)
	}
	if got := verifyStatusIcon(verifyStatusNA, false); got != " N/A" {
		t.Errorf("expected ' N/A', got %q", got)
	}

	// With color: all statuses should contain ANSI escape.
	for _, status := range []string{verifyStatusPass, verifyStatusFail, verifyStatusNA} {
		got := verifyStatusIcon(status, true)
		if !strings.Contains(got, "\033[") {
			t.Errorf("expected ANSI escape in colored %s, got %q", status, got)
		}
	}
}

// testScanEnv creates a VerifyEnv with a real scanner and policy for unit-testing
// individual check functions. The proxy URL points to a mock that returns 200.
func testScanEnv(t *testing.T) *VerifyEnv {
	t.Helper()
	cfg := diagTestConfig()
	cfg.ForwardProxy.Enabled = true
	cfg.MCPToolPolicy = config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionBlock,
		Rules:   policy.DefaultToolPolicyRules(),
	}
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = config.ActionBlock
	sc := scanner.New(cfg)
	t.Cleanup(func() { sc.Close() })
	pc := policy.New(cfg.MCPToolPolicy)
	return &VerifyEnv{
		Cfg:       cfg,
		Sc:        sc,
		PolicyCfg: pc,
		RunCtx:    cliutil.RunContextHost,
	}
}

func TestCheckConfigValid_Fail(t *testing.T) {
	env := testScanEnv(t)
	// Set an invalid mode to trigger validation failure.
	env.Cfg.Mode = "invalid-mode"
	r := checkConfigValid(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for invalid config, got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "validation error") {
		t.Errorf("expected 'validation error' in detail, got: %s", r.Detail)
	}
}

func TestCheckConfigValid_SurfaceWarnings(t *testing.T) {
	env := testScanEnv(t)
	env.Cfg.ResponseScanning.Enabled = false
	env.Cfg.ResponseScanning.ExemptDomains = []string{"api.openai.com"}

	r := checkConfigValid(env)
	if r.Status != verifyStatusPass {
		t.Fatalf("expected pass for warning-only config, got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "Config validated with warnings") {
		t.Fatalf("expected warning detail, got: %s", r.Detail)
	}
	if !strings.Contains(r.Detail, "response_scanning.exempt_domains") {
		t.Fatalf("expected warning field in detail, got: %s", r.Detail)
	}
	if r.Evidence["warning_1"] == "" {
		t.Fatalf("expected warning evidence, got: %+v", r.Evidence)
	}
}

func TestCheckProxyHealth_Error(t *testing.T) {
	env := testScanEnv(t)
	env.ProxyURL = "http://127.0.0.1:1" // nothing listening
	r := checkProxyHealth(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for unreachable proxy, got %s: %s", r.Status, r.Detail)
	}
}

func TestCheckFetchDLP_Error(t *testing.T) {
	env := testScanEnv(t)
	env.ProxyURL = "http://127.0.0.1:1" // nothing listening
	env.MockURL = "http://127.0.0.1:2"
	r := checkFetchDLP(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for unreachable proxy, got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "fetch request failed") {
		t.Errorf("expected 'fetch request failed' detail, got: %s", r.Detail)
	}
}

func TestCheckVerifyForwardBlocked_Disabled(t *testing.T) {
	env := testScanEnv(t)
	env.Cfg.ForwardProxy.Enabled = false
	r := checkVerifyForwardBlocked(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for disabled forward proxy, got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "disabled") {
		t.Errorf("expected 'disabled' in detail, got: %s", r.Detail)
	}
}

func TestCheckScanningDLP_Disabled(t *testing.T) {
	env := testScanEnv(t)
	env.Cfg.MCPInputScanning.Enabled = false
	r := checkScanningDLP(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for disabled input scanning, got %s: %s", r.Status, r.Detail)
	}
}

func TestCheckScanningInjection_Disabled(t *testing.T) {
	env := testScanEnv(t)
	env.Cfg.ResponseScanning.Enabled = false
	r := checkScanningInjection(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for disabled response scanning, got %s: %s", r.Status, r.Detail)
	}
}

func TestCheckScanningPolicy_Disabled(t *testing.T) {
	env := testScanEnv(t)
	env.Cfg.MCPToolPolicy.Enabled = false
	r := checkScanningPolicy(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for disabled tool policy, got %s: %s", r.Status, r.Detail)
	}
}

func TestBuildVerifyReport_ContainmentExposed(t *testing.T) {
	env := &VerifyEnv{RunCtx: cliutil.RunContextContainer}
	checks := []VerifyCheck{
		{Name: "scan1", Category: verifyCatScanning, Run: func(_ *VerifyEnv) VerifyResult {
			return VerifyResult{Status: verifyStatusPass}
		}},
		{Name: "contain1", Category: verifyCatContainment, Run: func(_ *VerifyEnv) VerifyResult {
			return VerifyResult{Status: verifyStatusFail, Detail: "exposed"}
		}},
	}
	report := BuildVerifyReport(env, checks, "test")
	if report.Summary.Containment != verifyContainmentExposed {
		t.Errorf("expected containment=exposed, got %s", report.Summary.Containment)
	}
	if report.Summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", report.Summary.Failed)
	}
}

func TestBuildVerifyReport_ContainmentContained(t *testing.T) {
	env := &VerifyEnv{RunCtx: cliutil.RunContextPod}
	checks := []VerifyCheck{
		{Name: "scan1", Category: verifyCatScanning, Run: func(_ *VerifyEnv) VerifyResult {
			return VerifyResult{Status: verifyStatusPass}
		}},
		{Name: "contain1", Category: verifyCatContainment, Run: func(_ *VerifyEnv) VerifyResult {
			return VerifyResult{Status: verifyStatusPass}
		}},
	}
	report := BuildVerifyReport(env, checks, "test")
	if report.Summary.Containment != verifyContainmentContained {
		t.Errorf("expected containment=contained, got %s", report.Summary.Containment)
	}
}

func TestBuildVerifyReport_ScanningDegraded(t *testing.T) {
	env := &VerifyEnv{RunCtx: cliutil.RunContextHost}
	checks := []VerifyCheck{
		{Name: "scan1", Category: verifyCatScanning, Run: func(_ *VerifyEnv) VerifyResult {
			return VerifyResult{Status: verifyStatusFail, Detail: "bad"}
		}},
	}
	report := BuildVerifyReport(env, checks, "test")
	if report.Summary.Scanning != verifyScanningDegraded {
		t.Errorf("expected scanning=degraded, got %s", report.Summary.Scanning)
	}
}

func TestVerifyInstallCmd_BadConfig(t *testing.T) {
	var buf, errBuf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--config", "/nonexistent/path.yaml", "--no-color"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestVerifyInstallCmd_BadSignKey(t *testing.T) {
	var buf, errBuf bytes.Buffer
	cmd := VerifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--json", "--no-color", "--sign", "/nonexistent/key.pem"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing sign key")
	}
}

func TestWriteVerifyReportFile_BadPath(t *testing.T) {
	report := VerifyReport{Version: "test"}
	err := writeVerifyReportFile(report, "/nonexistent/dir/report.json")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestCheckProxyHealth_Non200(t *testing.T) {
	// Start a server that returns 503.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	env := testScanEnv(t)
	env.ProxyURL = srv.URL
	r := checkProxyHealth(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for non-200, got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "503") {
		t.Errorf("expected status code in detail, got: %s", r.Detail)
	}
}

func TestCheckFetchDLP_NotBlocked(t *testing.T) {
	// A server that returns an unblocked fetch response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := proxy.FetchResponse{Blocked: false, Content: "OK"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	env := testScanEnv(t)
	env.ProxyURL = srv.URL
	env.MockURL = srv.URL
	r := checkFetchDLP(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail when DLP allows request, got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "allowed") {
		t.Errorf("expected 'allowed' in detail, got: %s", r.Detail)
	}
}

func TestCheckFetchDLP_BadJSON(t *testing.T) {
	// A server that returns invalid JSON.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	env := testScanEnv(t)
	env.ProxyURL = srv.URL
	env.MockURL = srv.URL
	r := checkFetchDLP(env)
	if r.Status != verifyStatusFail {
		t.Errorf("expected fail for bad JSON, got %s: %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "decode error") {
		t.Errorf("expected 'decode error' in detail, got: %s", r.Detail)
	}
}

func TestPrintVerifyTable_WithFailures(t *testing.T) {
	report := VerifyReport{
		Version: "test",
		Checks: []VerifyReportCheck{
			{Name: "scan1", Category: verifyCatScanning, Status: verifyStatusPass, Detail: "ok"},
			{Name: "scan2", Category: verifyCatScanning, Status: verifyStatusFail, Detail: "bad"},
			{Name: "contain1", Category: verifyCatContainment, Status: verifyStatusFail, Detail: "exposed"},
		},
		Summary: VerifyReportSummary{
			Total: 3, Passed: 1, Failed: 2, Scanning: verifyScanningDegraded,
			Containment: verifyContainmentExposed,
		},
	}
	var buf bytes.Buffer
	printVerifyTable(&buf, report, false)
	out := buf.String()
	if !strings.Contains(out, "2 FAILED") {
		t.Errorf("expected '2 FAILED' in output:\n%s", out)
	}
	if !strings.Contains(out, "Scanning: degraded") {
		t.Errorf("expected 'Scanning: degraded' in output:\n%s", out)
	}
	if !strings.Contains(out, "Containment: exposed") {
		t.Errorf("expected 'Containment: exposed' in output:\n%s", out)
	}
}
