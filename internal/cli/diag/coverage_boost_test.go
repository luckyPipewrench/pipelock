// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Ensure imports are used.
var _ = context.Background

// Test-scoped constants for coverage boost tests.
const (
	testStatusPass = "pass"
	testStatusFail = "fail"
	testStatusSkip = "skip"
)

func TestCheckCmd_DefaultConfig(t *testing.T) {
	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(CheckCmd())

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"check"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Using default config") {
		t.Errorf("expected default config message, got: %s", output)
	}
}

func TestCheckCmd_WithConfig(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte("mode: audit\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(CheckCmd())

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"check", "--config", cfgFile})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Config validation: OK") {
		t.Errorf("expected OK message, got: %s", output)
	}
}

func TestCheckCmd_BadConfig(t *testing.T) {
	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(CheckCmd())

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"check", "--config", "/nonexistent/pipelock.yaml"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for bad config")
	}
}

func TestCheckCmd_ScanURLAllowed(t *testing.T) {
	// Start a mock server the scanner won't block.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mock := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	mock.Listener = ln
	mock.Start()
	defer mock.Close()

	// Write a config that allowlists the mock host and disables SSRF.
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pipelock.yaml")
	mockHost, _, _ := net.SplitHostPort(strings.TrimPrefix(mock.URL, "http://"))
	cfgContent := fmt.Sprintf("mode: audit\ninternal: []\nssrf:\n  ip_allowlist:\n    - 127.0.0.0/8\napi_allowlist:\n  - %s\n", mockHost)
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(CheckCmd())

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"check", "--config", cfgFile, "--url", mock.URL})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ALLOWED") {
		t.Errorf("expected ALLOWED in output, got: %s", output)
	}
}

func TestCheckCmd_ScanURLBlocked(t *testing.T) {
	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(CheckCmd())

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	// Build fake key at runtime to avoid gosec G101.
	fakeKey := "AKIA" + "IOSFODNN7EXAMPLE"
	root.SetArgs([]string{"check", "--url", "https://evil.com/?key=" + fakeKey})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for blocked URL")
	}
	if !errors.Is(err, ErrURLBlocked) {
		t.Errorf("expected ErrURLBlocked, got: %v", err)
	}
}

func TestRunDiagnoseSandbox_JSON(t *testing.T) {
	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(DiagnoseCmd())

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"diagnose", "--sandbox", "--json"})

	// May return exit code 1 if sandbox features are unavailable.
	_ = root.Execute()

	output := buf.String()
	if output == "" {
		t.Fatal("expected non-empty output")
	}

	// Should be valid JSON.
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, output)
	}

	// Should have sandbox key.
	if _, ok := result["sandbox"]; !ok {
		t.Error("expected sandbox key in JSON output")
	}
}

func TestRunDiagnoseSandbox_Text(t *testing.T) {
	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(DiagnoseCmd())

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"diagnose", "--sandbox", "--no-color"})

	// May return exit code 1 if sandbox features are unavailable.
	_ = root.Execute()

	output := buf.String()
	if !strings.Contains(output, "Sandbox Capabilities") {
		t.Errorf("expected Sandbox Capabilities header, got: %s", output)
	}
	if !strings.Contains(output, "Recommendation:") {
		t.Errorf("expected Recommendation in output, got: %s", output)
	}
}

func TestDiagnoseGet_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	resp, err := diagnoseGet(srv.URL)
	if err != nil {
		t.Fatalf("diagnoseGet: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestDiagnoseGet_BadURL(t *testing.T) {
	resp, err := diagnoseGet("http://[invalid-url]:99999/bad")
	if err == nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		t.Error("expected error for invalid URL")
	}
}

func TestCheckFetchHint_SkipWhenDisabled(t *testing.T) {
	cfg := config.Defaults()
	// explain_blocks defaults to false.
	result := checkFetchHint("http://unused", "http://unused", cfg)
	if result.Status != testStatusSkip {
		t.Errorf("expected skip when explain_blocks disabled, got %q", result.Status)
	}
}

func TestCheckFetchHint_SkipWhenExplainBlocksEnabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.DLP.ScanEnv = false
	explainTrue := true
	cfg.ExplainBlocks = &explainTrue

	// checkFetchHint with a bad URL will fail (no proxy running),
	// but it should NOT skip since explain_blocks is enabled.
	result := checkFetchHint("http://127.0.0.1:1/bad", "http://127.0.0.1:1/mock", cfg)
	if result.Status == testStatusSkip {
		t.Error("expected non-skip status when explain_blocks is enabled")
	}
}

func TestCheckRules_NoBundles(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules.RulesDir = t.TempDir() // empty dir, no bundles
	result := checkRules("", "", cfg)
	if result.Status != testStatusSkip {
		t.Errorf("expected skip with no bundles, got %q", result.Status)
	}
}

func TestBuildDiagnoseChecks(t *testing.T) {
	checks := buildDiagnoseChecks()
	expectedNames := []string{
		"health", "fetch_allowed", "fetch_blocked",
		"fetch_hint", "forward_allowed", "forward_blocked", "rules",
	}
	if len(checks) != len(expectedNames) {
		t.Fatalf("expected %d checks, got %d", len(expectedNames), len(checks))
	}
	for i, expected := range expectedNames {
		if checks[i].Name != expected {
			t.Errorf("check %d: got %q, want %q", i, checks[i].Name, expected)
		}
	}
}

func TestStatusIcon_AllCombinations(t *testing.T) {
	tests := []struct {
		status string
		color  bool
		want   string
	}{
		{testStatusPass, false, "PASS"},
		{testStatusFail, false, "FAIL"},
		{testStatusSkip, false, "SKIP"},
		{testStatusPass, true, "\033[32mPASS\033[0m"},
		{testStatusFail, true, "\033[31mFAIL\033[0m"},
		{testStatusSkip, true, "\033[33mSKIP\033[0m"},
	}
	for _, tc := range tests {
		name := fmt.Sprintf("%s_color=%v", tc.status, tc.color)
		t.Run(name, func(t *testing.T) {
			got := statusIcon(tc.status, tc.color)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrintDiagnoseTable(t *testing.T) {
	report := diagnoseReport{
		ConfigFile: "test.yaml",
		Mode:       "balanced",
		Total:      3,
		Passed:     1,
		Failed:     1,
		Skipped:    1,
		Checks: []diagnoseReportCheck{
			{Name: "health", Status: testStatusPass},
			{Name: "fetch", Status: testStatusFail, Detail: "err"},
			{Name: "rules", Status: testStatusSkip, Detail: "none"},
		},
	}

	var buf bytes.Buffer
	printDiagnoseTable(&buf, report, false)

	output := buf.String()
	if !strings.Contains(output, "Pipelock Diagnostics") {
		t.Error("expected header")
	}
	if !strings.Contains(output, "1 passed, 1 failed, 1 skipped") {
		t.Error("expected summary line")
	}
}

func TestLoadTestConfig(t *testing.T) {
	t.Run("empty path returns defaults", func(t *testing.T) {
		cfg, label, err := loadTestConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if label != configLabelDefaults {
			t.Errorf("expected label %q, got %q", configLabelDefaults, label)
		}
	})

	t.Run("valid config file", func(t *testing.T) {
		dir := t.TempDir()
		cfgFile := filepath.Join(dir, "pipelock.yaml")
		if err := os.WriteFile(cfgFile, []byte("mode: audit\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, label, err := loadTestConfig(cfgFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if label != cfgFile {
			t.Errorf("expected label %q, got %q", cfgFile, label)
		}
	})

	t.Run("bad config path", func(t *testing.T) {
		_, _, err := loadTestConfig("/nonexistent/pipelock.yaml")
		if err == nil {
			t.Fatal("expected error for bad path")
		}
	})
}

func TestParseCategoryFilter_Boost(t *testing.T) {
	tests := []struct {
		input    string
		wantNil  bool
		wantLen  int
		wantKeys []string
	}{
		{"", true, 0, nil},
		{"dlp", false, 1, []string{"dlp"}},
		{"dlp,entropy", false, 2, []string{"dlp", "entropy"}},
		{"dlp, entropy , scheme", false, 3, []string{"dlp", "entropy", "scheme"}},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := parseCategoryFilter(tc.input)
			if tc.wantNil && result != nil {
				t.Error("expected nil")
			}
			if !tc.wantNil && len(result) != tc.wantLen {
				t.Errorf("got %d entries, want %d", len(result), tc.wantLen)
			}
			for _, k := range tc.wantKeys {
				if !result[k] {
					t.Errorf("missing key %q", k)
				}
			}
		})
	}
}

func TestValidateCategoryFilter_Boost(t *testing.T) {
	t.Run("valid categories", func(t *testing.T) {
		filter := map[string]bool{"dlp": true, "entropy": true}
		if err := validateCategoryFilter(filter); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid category", func(t *testing.T) {
		filter := map[string]bool{"dlp": true, "nonexistent": true}
		err := validateCategoryFilter(filter)
		if err == nil {
			t.Fatal("expected error for invalid category")
		}
		if !strings.Contains(err.Error(), "nonexistent") {
			t.Errorf("expected category name in error, got: %v", err)
		}
	})
}

func TestBuildSkipSet_Boost(t *testing.T) {
	t.Run("all disabled", func(t *testing.T) {
		cfg := &config.Config{}
		skip := buildSkipSet(cfg)
		if _, ok := skip["dlp"]; !ok {
			t.Error("expected dlp to be skipped when no patterns")
		}
		if _, ok := skip["response_injection"]; !ok {
			t.Error("expected response_injection to be skipped when disabled")
		}
	})

	t.Run("all enabled", func(t *testing.T) {
		cfg := config.Defaults()
		skip := buildSkipSet(cfg)
		if _, ok := skip["dlp"]; ok {
			t.Error("dlp should not be skipped with default config")
		}
	})
}

func TestConnectThroughProxy_BadAddress(t *testing.T) {
	_, err := connectThroughProxy("http://127.0.0.1:1", "example.com:443")
	if err == nil {
		t.Error("expected error connecting to non-listening port")
	}
}
