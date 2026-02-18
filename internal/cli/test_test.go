package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestTestCmd(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	t.Run("header", func(t *testing.T) {
		if !strings.Contains(output, "Pipelock Test Suite") {
			t.Error("expected test suite header in output")
		}
	})

	t.Run("contains_pass", func(t *testing.T) {
		if !strings.Contains(output, "[PASS]") {
			t.Error("expected [PASS] markers in output")
		}
	})

	t.Run("no_failures", func(t *testing.T) {
		if strings.Contains(output, "[FAIL]") {
			t.Errorf("expected no [FAIL] with default config, got:\n%s", output)
		}
	})

	t.Run("results_line", func(t *testing.T) {
		if !strings.Contains(output, "passed") {
			t.Error("expected 'passed' in results summary")
		}
	})

	t.Run("categories_present", func(t *testing.T) {
		for _, cat := range []string{"dlp", "scheme", "clean"} {
			if !strings.Contains(output, cat) {
				t.Errorf("expected category %q in output", cat)
			}
		}
	})
}

func TestTestCmd_JSON(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report testReport
	if err := json.Unmarshal([]byte(buf.String()), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}

	t.Run("mode", func(t *testing.T) {
		if report.Mode != "balanced" { //nolint:goconst // test value
			t.Errorf("mode = %q, want balanced", report.Mode)
		}
	})

	t.Run("total_matches_vectors", func(t *testing.T) {
		if report.Total != len(report.Vectors) {
			t.Errorf("total = %d, vectors = %d", report.Total, len(report.Vectors))
		}
	})

	t.Run("counts_add_up", func(t *testing.T) {
		sum := report.Passed + report.Failed + report.Skipped
		if sum != report.Total {
			t.Errorf("passed(%d) + failed(%d) + skipped(%d) = %d, want %d",
				report.Passed, report.Failed, report.Skipped, sum, report.Total)
		}
	})

	t.Run("no_failures", func(t *testing.T) {
		if report.Failed != 0 {
			for _, v := range report.Vectors {
				if v.Status == "fail" {
					t.Errorf("unexpected failure: %s (%s)", v.Name, v.Detail)
				}
			}
		}
	})

	t.Run("vectors_have_fields", func(t *testing.T) {
		for _, v := range report.Vectors {
			if v.Name == "" {
				t.Error("vector with empty name")
			}
			if v.Category == "" {
				t.Error("vector with empty category")
			}
			if v.Status == "" {
				t.Error("vector with empty status")
			}
		}
	})
}

func TestTestCmd_ConfigFile(t *testing.T) {
	// Write a balanced config to a temp file. No DLP patterns means
	// DLP vectors are skipped, but that's fine — this test verifies
	// that --config loads the file and populates the JSON report.
	cfgYAML := `version: 1
mode: balanced
fetch_proxy:
  listen: "127.0.0.1:8888"
  monitoring:
    max_url_length: 2048
    entropy_threshold: 4.5
    blocklist:
      - "*.pastebin.com"
      - "*.transfer.sh"
response_scanning:
  enabled: true
  action: block
mcp_input_scanning:
  enabled: true
  action: block
mcp_tool_scanning:
  enabled: true
  action: block
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test-config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--config", cfgPath, "--json"})

	// Config without DLP patterns will skip DLP vectors and fail
	// MCP input DLP checks; tolerate ErrTestFailed since this test
	// verifies config loading, not vector outcomes.
	err := cmd.Execute()
	if err != nil && !errors.Is(err, ErrTestFailed) {
		t.Fatalf("unexpected error: %v", err)
	}

	var report testReport
	if err := json.Unmarshal([]byte(buf.String()), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if report.Mode != "balanced" { //nolint:goconst // test value
		t.Errorf("mode = %q, want balanced", report.Mode)
	}

	if report.ConfigFile != cfgPath {
		t.Errorf("config_file = %q, want %q", report.ConfigFile, cfgPath)
	}
}

func TestTestCmd_CategoryFilter(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--json", "--category", "dlp"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report testReport
	if err := json.Unmarshal([]byte(buf.String()), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, v := range report.Vectors {
		if v.Category != "dlp" {
			t.Errorf("expected only dlp vectors, got category %q", v.Category)
		}
	}

	if report.Total == 0 {
		t.Error("expected at least one vector with --category dlp")
	}
}

func TestTestCmd_MultipleCategoryFilter(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--json", "--category", "dlp,scheme"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report testReport
	if err := json.Unmarshal([]byte(buf.String()), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	allowed := map[string]bool{"dlp": true, "scheme": true}
	for _, v := range report.Vectors {
		if !allowed[v.Category] {
			t.Errorf("unexpected category %q with --category dlp,scheme", v.Category)
		}
	}
}

func TestTestCmd_NoColorFlag(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--no-color"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Error("expected no ANSI escape codes with --no-color flag")
	}
	if !strings.Contains(output, "[PASS]") {
		t.Error("expected [PASS] markers in no-color output")
	}
}

func TestTestCmd_InvalidConfig(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--config", "/nonexistent/path/config.yaml"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid config path")
	}
}

func TestTestCmd_HelpRegistered(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "test") {
		t.Error("expected test command in help output")
	}
}

func TestBuildTestVectors_Count(t *testing.T) {
	vectors := buildTestVectors()
	if len(vectors) != 30 {
		t.Errorf("expected 30 vectors, got %d", len(vectors))
	}
	for i, v := range vectors {
		if v.Name == "" {
			t.Errorf("vector %d has empty name", i)
		}
		if v.Category == "" {
			t.Errorf("vector %d has empty category", i)
		}
		if v.Attack == "" {
			t.Errorf("vector %d has empty attack description", i)
		}
		if v.Run == nil {
			t.Errorf("vector %d has nil run function", i)
		}
	}
}

func TestBuildTestVectors_AllCategories(t *testing.T) {
	vectors := buildTestVectors()
	categories := make(map[string]int)
	for _, v := range vectors {
		categories[v.Category]++
	}

	expected := []string{
		"dlp", "blocklist", "entropy", "scheme",
		"response_injection", "mcp_response", "mcp_input", "mcp_tools", "clean",
	}
	for _, cat := range expected {
		if categories[cat] == 0 {
			t.Errorf("no vectors for category %q", cat)
		}
	}
}

func TestTestCmd_SkippedCategories(t *testing.T) {
	// Write a config with response/MCP scanning disabled and no DLP patterns.
	// config.Load + ApplyDefaults will set entropy_threshold=4.5 but not DLP patterns.
	cfgYAML := `version: 1
mode: balanced
response_scanning:
  enabled: false
mcp_input_scanning:
  enabled: false
mcp_tool_scanning:
  enabled: false
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "minimal.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--config", cfgPath, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report testReport
	if err := json.Unmarshal([]byte(buf.String()), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if report.Skipped == 0 {
		t.Error("expected skipped vectors with disabled scanners")
	}

	// Verify skipped vectors are from expected categories.
	skippableCats := map[string]bool{
		"dlp":                true,
		"blocklist":          true,
		"response_injection": true,
		"mcp_response":       true,
		"mcp_input":          true,
		"mcp_tools":          true,
	}
	for _, v := range report.Vectors {
		if v.Status == "skip" && !skippableCats[v.Category] {
			t.Errorf("unexpected skip for category %q", v.Category)
		}
	}

	if len(report.Gaps) == 0 {
		t.Error("expected gaps reported for disabled scanners")
	}
}

func TestTestCmd_ExitCodeOnFailure(t *testing.T) {
	// Config with incomplete DLP patterns — only Anthropic pattern included.
	// AWS, GitHub, and OpenAI key vectors will fail (no matching pattern).
	cfgYAML := `version: 1
mode: balanced
dlp:
  patterns:
    - name: "Anthropic API Key"
      regex: "sk-ant-api03-[A-Za-z0-9_-]{20,}"
      severity: critical
response_scanning:
  enabled: false
mcp_input_scanning:
  enabled: false
mcp_tool_scanning:
  enabled: false
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "incomplete.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--config", cfgPath, "--category", "dlp"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error (exit code 1) for incomplete DLP config")
	}
	if err != nil && !errors.Is(err, ErrTestFailed) {
		t.Errorf("expected ErrTestFailed, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "[FAIL]") {
		t.Error("expected [FAIL] markers for missing DLP patterns")
	}
}

func TestTestCmd_JSONExitCodeOnFailure(t *testing.T) {
	// JSON mode must also return ErrTestFailed when vectors fail.
	// Same incomplete DLP config as text mode test.
	cfgYAML := `version: 1
mode: balanced
dlp:
  patterns:
    - name: "Anthropic API Key"
      regex: "sk-ant-api03-[A-Za-z0-9_-]{20,}"
      severity: critical
response_scanning:
  enabled: false
mcp_input_scanning:
  enabled: false
mcp_tool_scanning:
  enabled: false
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "incomplete.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--config", cfgPath, "--json", "--category", "dlp"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for incomplete DLP config in JSON mode")
	}
	if err != nil && !errors.Is(err, ErrTestFailed) {
		t.Errorf("expected ErrTestFailed, got: %v", err)
	}

	// Verify the JSON output still has the failure data.
	var report testReport
	if err := json.Unmarshal([]byte(buf.String()), &report); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if report.Failed == 0 {
		t.Error("expected failed > 0 in JSON report")
	}
}

func TestTestCmd_AllVectorsRunDefaultConfig(t *testing.T) {
	// Run every vector directly with default config and verify expected outcomes.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false

	sc := scanner.New(cfg)
	defer sc.Close()

	vectors := buildTestVectors()
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			vr := v.Run(sc)
			if vr.Blocked != vr.Expected {
				if vr.Expected {
					t.Errorf("expected block, got allowed: %s", vr.Detail)
				} else {
					t.Errorf("expected allow, got blocked: %s", vr.Detail)
				}
			}
		})
	}
}

func TestBuildSkipSet(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := config.Defaults()
		skip := buildSkipSet(cfg)
		// Default config has DLP patterns, response scanning, blocklist, and entropy enabled.
		if _, ok := skip["dlp"]; ok {
			t.Error("DLP should not be skipped with default config")
		}
		if _, ok := skip["scheme"]; ok {
			t.Error("scheme should never be skipped")
		}
		if _, ok := skip["clean"]; ok {
			t.Error("clean should never be skipped")
		}
	})

	t.Run("all_disabled", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.DLP.Patterns = nil
		cfg.ResponseScanning.Enabled = false
		cfg.MCPInputScanning.Enabled = false
		cfg.MCPToolScanning.Enabled = false
		cfg.FetchProxy.Monitoring.Blocklist = nil
		cfg.FetchProxy.Monitoring.EntropyThreshold = 0

		skip := buildSkipSet(cfg)
		expected := []string{"dlp", "response_injection", "mcp_response", "mcp_input", "mcp_tools", "blocklist", "entropy"}
		for _, cat := range expected {
			if _, ok := skip[cat]; !ok {
				t.Errorf("expected %q to be skipped when disabled", cat)
			}
		}
	})
}

func TestParseCategoryFilter(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		f := parseCategoryFilter("")
		if f != nil {
			t.Error("expected nil for empty filter")
		}
	})

	t.Run("single", func(t *testing.T) {
		f := parseCategoryFilter("dlp")
		if !f["dlp"] {
			t.Error("expected dlp in filter")
		}
	})

	t.Run("multiple", func(t *testing.T) {
		f := parseCategoryFilter("dlp, entropy, scheme")
		for _, cat := range []string{"dlp", "entropy", "scheme"} {
			if !f[cat] {
				t.Errorf("expected %q in filter", cat)
			}
		}
	})
}

func TestDetectGaps(t *testing.T) {
	t.Run("no_skips", func(t *testing.T) {
		gaps := detectGaps(map[string]string{}, nil)
		if len(gaps) != 0 {
			t.Errorf("expected no gaps, got %v", gaps)
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		skip := map[string]string{
			"response_injection": "response scanning disabled",
			"mcp_response":       "response scanning disabled",
		}
		gaps := detectGaps(skip, nil)
		if len(gaps) != 1 {
			t.Errorf("expected 1 deduplicated gap, got %d: %v", len(gaps), gaps)
		}
	})

	t.Run("filtered_out", func(t *testing.T) {
		skip := map[string]string{
			"mcp_input": "MCP input scanning disabled",
		}
		filter := map[string]bool{"dlp": true}
		gaps := detectGaps(skip, filter)
		if len(gaps) != 0 {
			t.Errorf("expected no gaps when category filtered out, got %v", gaps)
		}
	})
}

func TestTestCmd_FailOnGap(t *testing.T) {
	// Config with everything disabled — should have gaps.
	cfgYAML := `version: 1
mode: balanced
response_scanning:
  enabled: false
mcp_input_scanning:
  enabled: false
mcp_tool_scanning:
  enabled: false
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gappy.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--config", cfgPath, "--json", "--fail-on-gap"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error with --fail-on-gap and disabled scanners")
	}
	if err != nil && !errors.Is(err, ErrGapsDetected) {
		t.Errorf("expected ErrGapsDetected, got: %v", err)
	}

	var report testReport
	if jsonErr := json.Unmarshal([]byte(buf.String()), &report); jsonErr != nil {
		t.Fatalf("invalid JSON: %v", jsonErr)
	}
	if len(report.Gaps) == 0 {
		t.Error("expected gaps in report")
	}
	if report.Failed != 0 {
		t.Error("expected no explicit failures, just gaps")
	}
}

func TestTestCmd_FailOnGap_NoGaps(t *testing.T) {
	// Verify --fail-on-gap succeeds when the config has no gaps.
	// Build the full config programmatically (config.Load doesn't
	// populate DLP patterns; config.Defaults does).
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Enabled = true
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPToolScanning.Enabled = true

	sc := scanner.New(cfg)
	defer sc.Close()

	vectors := buildTestVectors()
	skipSet := buildSkipSet(cfg)
	if len(skipSet) != 0 {
		t.Fatalf("expected no skips with full config, got: %v", skipSet)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	testSub, _, _ := cmd.Find([]string{"test"})
	if testSub == nil {
		t.Fatal("test subcommand not found")
	}

	err := runTests(testSub, cfg, "defaults", vectors, skipSet, nil, true, false, true)
	if err != nil {
		t.Fatalf("unexpected error with full config and failOnGap=true: %v", err)
	}

	var report testReport
	if jsonErr := json.Unmarshal([]byte(buf.String()), &report); jsonErr != nil {
		t.Fatalf("invalid JSON: %v", jsonErr)
	}
	if len(report.Gaps) != 0 {
		t.Errorf("expected no gaps, got: %v", report.Gaps)
	}
}

func TestTestCmd_UnknownCategory(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--category", "nope"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for unknown category")
	}
	if err != nil && !strings.Contains(err.Error(), "unknown category") {
		t.Errorf("expected 'unknown category' error, got: %v", err)
	}
}

func TestTestCmd_UnknownCategoryMixed(t *testing.T) {
	// One valid and one invalid category.
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"test", "--category", "dlp,bogus"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for unknown category in mixed list")
	}
	if err != nil && !strings.Contains(err.Error(), "bogus") {
		t.Errorf("expected error mentioning 'bogus', got: %v", err)
	}
}

func TestValidateCategoryFilter(t *testing.T) {
	t.Run("nil_filter", func(t *testing.T) {
		if err := validateCategoryFilter(nil); err != nil {
			t.Errorf("unexpected error for nil filter: %v", err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		filter := map[string]bool{"dlp": true, "scheme": true}
		if err := validateCategoryFilter(filter); err != nil {
			t.Errorf("unexpected error for valid filter: %v", err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		filter := map[string]bool{"dlp": true, "nonexistent": true}
		err := validateCategoryFilter(filter)
		if err == nil {
			t.Error("expected error for invalid category")
		}
	})
}

func TestTestCmd_ColorOutput(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	// Run directly with color=true.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false

	vectors := buildTestVectors()
	skipSet := buildSkipSet(cfg)

	testSub, _, _ := cmd.Find([]string{"test"})
	if testSub == nil {
		t.Fatal("test subcommand not found")
	}

	err := runTests(testSub, cfg, "defaults", vectors, skipSet, nil, false, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "\033[1m") {
		t.Error("expected ANSI bold escape in color output")
	}
	if !strings.Contains(output, "\033[0m") {
		t.Error("expected ANSI reset escape in color output")
	}
	if !strings.Contains(output, "[PASS]") {
		t.Error("expected [PASS] in color output")
	}
}
