package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// testRunContext returns the expected run context for the current test
// environment. This makes tests work both on host and in container CI.
func testRunContext() string {
	return detectRunContext()
}

func TestVerifyInstallCmd_AllPass(t *testing.T) {
	var buf bytes.Buffer
	cmd := verifyInstallCmd()
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
	if ctx == verifyContextHost {
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
	cmd := verifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json", "--no-color"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-install --json failed: %v", err)
	}

	var report verifyReport
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

	if ctx == verifyContextHost {
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
	cmd := verifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--json", "--no-color", "--config", cfgPath})
	err := cmd.Execute()

	// Should fail because disabled features are reported as failures.
	if err == nil {
		t.Fatal("expected error for weak config, got nil")
	}

	var report verifyReport
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
	cmd := verifyInstallCmd()
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
	cmd := verifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json", "--no-color", "--output", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-install --output failed: %v", err)
	}

	data, err := os.ReadFile(outPath) //nolint:gosec // test reads from known temp dir
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	var report verifyReport
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
	cmd := verifyInstallCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json", "--no-color", "--sign", keyPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-install --sign failed: %v", err)
	}

	var report verifyReport
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
	var withSig verifyReport
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
	ctx := detectRunContext()
	// Valid contexts: host, container, pod.
	switch ctx {
	case verifyContextHost, verifyContextContainer, verifyContextPod:
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

	// With color: should contain ANSI escape.
	if got := verifyStatusIcon(verifyStatusPass, true); !strings.Contains(got, "\033[") {
		t.Errorf("expected ANSI escape in colored PASS, got %q", got)
	}
}
