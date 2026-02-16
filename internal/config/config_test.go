package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Mode != ModeBalanced {
		t.Errorf("expected mode balanced, got %s", cfg.Mode)
	}
	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
	if cfg.FetchProxy.Listen != DefaultListen {
		t.Errorf("expected listen 127.0.0.1:8888, got %s", cfg.FetchProxy.Listen)
	}
	if cfg.FetchProxy.TimeoutSeconds != 30 {
		t.Errorf("expected timeout 30, got %d", cfg.FetchProxy.TimeoutSeconds)
	}
	if len(cfg.APIAllowlist) == 0 {
		t.Error("expected non-empty API allowlist")
	}
	if len(cfg.DLP.Patterns) == 0 {
		t.Error("expected non-empty DLP patterns")
	}
	if len(cfg.Internal) == 0 {
		t.Error("expected non-empty internal CIDRs")
	}
}

func TestDefaults_Validates(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("defaults should validate, got: %v", err)
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = "invalid" //nolint:goconst // test value
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestValidate_StrictModeRequiresAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = ModeStrict
	cfg.APIAllowlist = nil
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for strict mode with empty allowlist")
	}
}

func TestValidate_InvalidDLPRegex(t *testing.T) {
	cfg := Defaults()
	cfg.DLP.Patterns = []DLPPattern{
		{Name: "bad", Regex: "[invalid", Severity: "high"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid DLP regex")
	}
}

func TestValidate_DLPPatternMissingName(t *testing.T) {
	cfg := Defaults()
	cfg.DLP.Patterns = []DLPPattern{
		{Name: "", Regex: "test", Severity: "high"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for DLP pattern without name")
	}
}

func TestValidate_DLPPatternMissingRegex(t *testing.T) {
	cfg := Defaults()
	cfg.DLP.Patterns = []DLPPattern{
		{Name: "test", Regex: "", Severity: "high"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for DLP pattern without regex")
	}
}

func TestValidate_InvalidLoggingFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid logging format")
	}
}

func TestValidate_InvalidLoggingOutput(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Output = "database"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid logging output")
	}
}

func TestValidate_FileOutputRequiresPath(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Output = "file"
	cfg.Logging.File = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for file output without path")
	}
}

func TestApplyDefaults_FillsZeroValues(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()

	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
	if cfg.Mode != "balanced" {
		t.Errorf("expected mode balanced, got %s", cfg.Mode)
	}
	if cfg.FetchProxy.Listen == "" {
		t.Error("expected listen to be set")
	}
	if cfg.FetchProxy.TimeoutSeconds <= 0 {
		t.Error("expected timeout to be positive")
	}
	if cfg.FetchProxy.MaxResponseMB <= 0 {
		t.Error("expected max response MB to be positive")
	}
	if cfg.FetchProxy.UserAgent == "" {
		t.Error("expected user agent to be set")
	}
	if cfg.Logging.Format == "" {
		t.Error("expected logging format to be set")
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.anthropic.com"
fetch_proxy:
  listen: "127.0.0.1:9090"
  timeout_seconds: 15
logging:
  format: json
  output: stdout
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != "balanced" {
		t.Errorf("expected mode balanced, got %s", cfg.Mode)
	}
	if cfg.FetchProxy.Listen != "127.0.0.1:9090" {
		t.Errorf("expected listen 127.0.0.1:9090, got %s", cfg.FetchProxy.Listen)
	}
	if cfg.FetchProxy.TimeoutSeconds != 15 {
		t.Errorf("expected timeout 15, got %d", cfg.FetchProxy.TimeoutSeconds)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml}}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoad_InvalidConfig(t *testing.T) {
	yaml := `
version: 1
mode: invalid_mode
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	yaml := `
version: 1
mode: audit
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Defaults should be applied
	if cfg.FetchProxy.Listen == "" {
		t.Error("expected listen to have default value")
	}
	if cfg.FetchProxy.TimeoutSeconds <= 0 {
		t.Error("expected timeout to have default value")
	}
}

func TestValidate_AllModes(t *testing.T) {
	for _, mode := range []string{ModeStrict, ModeBalanced, ModeAudit} {
		cfg := Defaults()
		cfg.Mode = mode
		if err := cfg.Validate(); err != nil {
			t.Errorf("mode %s should validate, got: %v", mode, err)
		}
	}
}

func TestValidate_EmptyBlocklistEntry(t *testing.T) {
	cfg := Defaults()
	cfg.FetchProxy.Monitoring.Blocklist = []string{"*.pastebin.com", ""}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty blocklist entry")
	}
}

func TestLoad_PresetYAMLFiles(t *testing.T) {
	// Find the project root configs/ directory
	// Tests run from the package dir, so go up two levels
	presets := []string{
		"../../configs/balanced.yaml",
		"../../configs/strict.yaml",
		"../../configs/audit.yaml",
	}

	for _, path := range presets {
		abs, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("resolving %s: %v", path, err)
		}

		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := Load(abs)
			if err != nil {
				t.Fatalf("failed to load preset %s: %v", abs, err)
			}

			if cfg.Version != 1 {
				t.Errorf("expected version 1, got %d", cfg.Version)
			}
			if cfg.FetchProxy.Listen == "" {
				t.Error("expected non-empty listen address")
			}
			if len(cfg.Internal) == 0 {
				t.Error("expected non-empty internal CIDRs")
			}
		})
	}
}

func TestDefaults_ContainsIPv6CIDRs(t *testing.T) {
	cfg := Defaults()

	expected := []string{"::1/128", "fc00::/7", "fe80::/10"}
	for _, want := range expected {
		found := false
		for _, cidr := range cfg.Internal {
			if cidr == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected default CIDRs to contain %q", want)
		}
	}
}

func TestValidate_InvalidCIDR(t *testing.T) {
	cfg := Defaults()
	cfg.Internal = []string{"127.0.0.0/8", "not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestValidate_IPv6CIDRs(t *testing.T) {
	cfg := Defaults()
	cfg.Internal = []string{"::1/128", "fc00::/7", "fe80::/10"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid IPv6 CIDRs should validate, got: %v", err)
	}
}

func TestValidate_EmptyInternalCIDRs(t *testing.T) {
	cfg := Defaults()
	cfg.Internal = []string{}
	// Empty list is valid (disables SSRF checks)
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty internal CIDRs should validate, got: %v", err)
	}
}

func TestApplyDefaults_DoesNotOverwriteExistingValues(t *testing.T) {
	cfg := &Config{
		Version: 2,
		Mode:    ModeStrict,
		FetchProxy: FetchProxy{
			Listen:         "0.0.0.0:9999",
			TimeoutSeconds: 60,
			MaxResponseMB:  20,
			UserAgent:      "Custom/1.0",
		},
	}
	cfg.ApplyDefaults()

	if cfg.Version != 2 {
		t.Errorf("expected version 2, got %d", cfg.Version)
	}
	if cfg.Mode != ModeStrict {
		t.Errorf("expected mode strict, got %s", cfg.Mode)
	}
	if cfg.FetchProxy.Listen != "0.0.0.0:9999" {
		t.Errorf("expected listen 0.0.0.0:9999, got %s", cfg.FetchProxy.Listen)
	}
	if cfg.FetchProxy.TimeoutSeconds != 60 {
		t.Errorf("expected timeout 60, got %d", cfg.FetchProxy.TimeoutSeconds)
	}
	if cfg.FetchProxy.MaxResponseMB != 20 {
		t.Errorf("expected max response 20, got %d", cfg.FetchProxy.MaxResponseMB)
	}
	if cfg.FetchProxy.UserAgent != "Custom/1.0" {
		t.Errorf("expected user agent Custom/1.0, got %s", cfg.FetchProxy.UserAgent)
	}
}

func TestLoad_ExtraFieldsIgnored(t *testing.T) {
	yaml := `
version: 1
mode: audit
unknown_field: "should be silently ignored"
extra_section:
  nested: "also ignored"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error for config with extra fields: %v", err)
	}
	if cfg.Mode != ModeAudit {
		t.Errorf("expected mode audit, got %s", cfg.Mode)
	}
}

func TestLoad_MinimalConfig(t *testing.T) {
	yaml := `
version: 1
mode: audit
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All defaults should be applied
	if cfg.FetchProxy.Listen != "127.0.0.1:8888" {
		t.Errorf("expected default listen, got %s", cfg.FetchProxy.Listen)
	}
	if cfg.FetchProxy.TimeoutSeconds != 30 {
		t.Errorf("expected default timeout, got %d", cfg.FetchProxy.TimeoutSeconds)
	}
	if cfg.FetchProxy.MaxResponseMB != 10 {
		t.Errorf("expected default max response, got %d", cfg.FetchProxy.MaxResponseMB)
	}
	if cfg.FetchProxy.UserAgent != "Pipelock Fetch/1.0" {
		t.Errorf("expected default user agent, got %s", cfg.FetchProxy.UserAgent)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected default format json, got %s", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "stdout" {
		t.Errorf("expected default output stdout, got %s", cfg.Logging.Output)
	}
	if len(cfg.Internal) == 0 {
		t.Error("expected default internal CIDRs")
	}
}

func TestValidate_AllDLPPatternsCompile(t *testing.T) {
	cfg := Defaults()
	// All default DLP patterns should pass validation
	if err := cfg.Validate(); err != nil {
		t.Errorf("default DLP patterns should validate: %v", err)
	}
}

func TestValidate_StrictModeWithAllowlist(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = ModeStrict
	// Defaults() includes an allowlist, so this should pass
	if err := cfg.Validate(); err != nil {
		t.Errorf("strict mode with allowlist should validate: %v", err)
	}
}

func TestValidate_AuditModeAllowsEmpty(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = ModeAudit
	cfg.APIAllowlist = nil
	cfg.DLP.Patterns = nil
	cfg.FetchProxy.Monitoring.Blocklist = nil
	cfg.Internal = nil
	if err := cfg.Validate(); err != nil {
		t.Errorf("audit mode with empty lists should validate: %v", err)
	}
}

func TestLoad_WithDLPPatterns(t *testing.T) {
	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.example.com"
dlp:
  scan_env: true
  patterns:
    - name: "Test Pattern"
      regex: 'test-[a-z]+'
      severity: high
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DLP.Patterns) != 1 {
		t.Fatalf("expected 1 DLP pattern, got %d", len(cfg.DLP.Patterns))
	}
	if cfg.DLP.Patterns[0].Name != "Test Pattern" {
		t.Errorf("expected pattern name 'Test Pattern', got %s", cfg.DLP.Patterns[0].Name)
	}
}

func TestLoad_WithBlocklist(t *testing.T) {
	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.example.com"
fetch_proxy:
  listen: "127.0.0.1:8888"
  monitoring:
    blocklist:
      - "*.evil.com"
      - "*.bad.org"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.FetchProxy.Monitoring.Blocklist) != 2 {
		t.Fatalf("expected 2 blocklist entries, got %d", len(cfg.FetchProxy.Monitoring.Blocklist))
	}
}

func TestValidate_FileOutputWithPath(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Output = "file"
	cfg.Logging.File = "/tmp/test.log"
	if err := cfg.Validate(); err != nil {
		t.Errorf("file output with path should validate: %v", err)
	}
}

func TestValidate_BothOutputWithPath(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Output = "both"
	cfg.Logging.File = "/tmp/test.log"
	if err := cfg.Validate(); err != nil {
		t.Errorf("both output with path should validate: %v", err)
	}
}

func TestValidate_BothOutputRequiresPath(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Output = "both"
	cfg.Logging.File = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for both output without path")
	}
}

func TestValidate_TextFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Format = "text"
	if err := cfg.Validate(); err != nil {
		t.Errorf("text format should validate: %v", err)
	}
}

// --- Response Scanning Tests ---

func TestDefaults_ResponseScanningEnabled(t *testing.T) {
	cfg := Defaults()
	if !cfg.ResponseScanning.Enabled {
		t.Error("expected response scanning enabled by default")
	}
	if cfg.ResponseScanning.Action != "warn" { //nolint:goconst // test assertion
		t.Errorf("expected default action warn, got %s", cfg.ResponseScanning.Action)
	}
	if len(cfg.ResponseScanning.Patterns) != 10 {
		t.Errorf("expected 10 default response patterns, got %d", len(cfg.ResponseScanning.Patterns))
	}
}

func TestValidate_ResponseScanningValidActions(t *testing.T) {
	for _, action := range []string{"strip", "warn", "block", "ask"} {
		cfg := Defaults()
		cfg.ResponseScanning.Action = action
		if err := cfg.Validate(); err != nil {
			t.Errorf("action %q should validate, got: %v", action, err)
		}
	}
}

func TestValidate_ResponseScanningInvalidAction(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Action = "delete"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid response scanning action")
	}
}

func TestValidate_ResponseScanningInvalidRegex(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Patterns = []ResponseScanPattern{
		{Name: "bad", Regex: "[invalid"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid response scanning regex")
	}
}

func TestValidate_ResponseScanningMissingName(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Patterns = []ResponseScanPattern{
		{Name: "", Regex: "test"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for response scanning pattern without name")
	}
}

func TestValidate_ResponseScanningMissingRegex(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Patterns = []ResponseScanPattern{
		{Name: "test", Regex: ""},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for response scanning pattern without regex")
	}
}

func TestValidate_ResponseScanningDisabledSkipsValidation(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.Enabled = false
	cfg.ResponseScanning.Action = "invalid"
	cfg.ResponseScanning.Patterns = []ResponseScanPattern{
		{Name: "bad", Regex: "[invalid"},
	}
	// When disabled, validation should be skipped
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled response scanning should skip validation, got: %v", err)
	}
}

func TestApplyDefaults_ResponseScanningActionDefault(t *testing.T) {
	cfg := &Config{}
	cfg.ResponseScanning.Enabled = true
	cfg.ApplyDefaults()
	if cfg.ResponseScanning.Action != "warn" { //nolint:goconst // test assertion
		t.Errorf("expected default action warn, got %s", cfg.ResponseScanning.Action)
	}
}

func TestApplyDefaults_ResponseScanningActionPreserved(t *testing.T) {
	cfg := &Config{}
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = "block" //nolint:goconst // test assertion
	cfg.ApplyDefaults()
	if cfg.ResponseScanning.Action != "block" {
		t.Errorf("expected action block preserved, got %s", cfg.ResponseScanning.Action)
	}
}

func TestApplyDefaults_AskTimeoutDefault(t *testing.T) {
	cfg := &Config{}
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = "ask" //nolint:goconst // test value
	cfg.ApplyDefaults()
	if cfg.ResponseScanning.AskTimeoutSeconds != 30 {
		t.Errorf("expected default ask timeout 30, got %d", cfg.ResponseScanning.AskTimeoutSeconds)
	}
}

func TestApplyDefaults_AskTimeoutPreserved(t *testing.T) {
	cfg := &Config{}
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = "ask"
	cfg.ResponseScanning.AskTimeoutSeconds = 10
	cfg.ApplyDefaults()
	if cfg.ResponseScanning.AskTimeoutSeconds != 10 {
		t.Errorf("expected ask timeout 10 preserved, got %d", cfg.ResponseScanning.AskTimeoutSeconds)
	}
}

func TestApplyDefaults_ResponseScanningDisabledNoActionDefault(t *testing.T) {
	cfg := &Config{}
	cfg.ResponseScanning.Enabled = false
	cfg.ApplyDefaults()
	if cfg.ResponseScanning.Action != "" {
		t.Errorf("expected empty action when disabled, got %s", cfg.ResponseScanning.Action)
	}
}

// --- EnforceEnabled Tests ---

func TestEnforceEnabled_NilDefaultsTrue(t *testing.T) {
	cfg := &Config{} // Enforce is nil by default
	if !cfg.EnforceEnabled() {
		t.Error("expected EnforceEnabled() == true when Enforce is nil")
	}
}

func TestEnforceEnabled_ExplicitTrue(t *testing.T) {
	v := true
	cfg := &Config{Enforce: &v}
	if !cfg.EnforceEnabled() {
		t.Error("expected EnforceEnabled() == true when Enforce is explicitly true")
	}
}

func TestEnforceEnabled_ExplicitFalse(t *testing.T) {
	v := false
	cfg := &Config{Enforce: &v}
	if cfg.EnforceEnabled() {
		t.Error("expected EnforceEnabled() == false when Enforce is explicitly false")
	}
}

// --- Git Protection Validation Tests ---

func TestValidate_GitProtectionEnabled(t *testing.T) {
	cfg := Defaults()
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedBranches = []string{"main", "feature/*"}
	cfg.GitProtection.BlockedCommands = []string{"push --force"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid git protection config should validate, got: %v", err)
	}
}

func TestValidate_GitProtectionEmptyAllowedBranch(t *testing.T) {
	cfg := Defaults()
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedBranches = []string{"main", ""}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty allowed_branches pattern")
	}
}

func TestValidate_GitProtectionInvalidGlob(t *testing.T) {
	cfg := Defaults()
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedBranches = []string{"[invalid"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid allowed_branches glob pattern")
	}
}

func TestValidate_GitProtectionEmptyBlockedCommand(t *testing.T) {
	cfg := Defaults()
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedBranches = []string{"main"}
	cfg.GitProtection.BlockedCommands = []string{"push --force", ""}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty blocked_commands entry")
	}
}

func TestValidate_GitProtectionDisabledSkipsValidation(t *testing.T) {
	cfg := Defaults()
	cfg.GitProtection.Enabled = false
	cfg.GitProtection.AllowedBranches = []string{"[invalid"}
	cfg.GitProtection.BlockedCommands = []string{""}
	// When disabled, validation should be skipped
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled git protection should skip validation, got: %v", err)
	}
}

// --- ApplyDefaults Git Protection Tests ---

func TestApplyDefaults_GitProtectionEnabledDefaultsBranches(t *testing.T) {
	cfg := &Config{}
	cfg.GitProtection.Enabled = true
	cfg.ApplyDefaults()
	if len(cfg.GitProtection.AllowedBranches) == 0 {
		t.Error("expected default allowed_branches when git protection enabled")
	}
}

func TestApplyDefaults_GitProtectionEnabledPreservesBranches(t *testing.T) {
	cfg := &Config{}
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedBranches = []string{"develop"}
	cfg.ApplyDefaults()
	if len(cfg.GitProtection.AllowedBranches) != 1 || cfg.GitProtection.AllowedBranches[0] != "develop" {
		t.Errorf("expected preserved allowed_branches, got %v", cfg.GitProtection.AllowedBranches)
	}
}

func TestApplyDefaults_MonitoringDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()
	if cfg.FetchProxy.Monitoring.MaxURLLength != 2048 {
		t.Errorf("expected default max URL length 2048, got %d", cfg.FetchProxy.Monitoring.MaxURLLength)
	}
	if cfg.FetchProxy.Monitoring.EntropyThreshold != 4.5 {
		t.Errorf("expected default entropy threshold 4.5, got %f", cfg.FetchProxy.Monitoring.EntropyThreshold)
	}
	if cfg.FetchProxy.Monitoring.MaxReqPerMinute != 60 {
		t.Errorf("expected default max req/min 60, got %d", cfg.FetchProxy.Monitoring.MaxReqPerMinute)
	}
}

func TestLoad_WithResponseScanning(t *testing.T) {
	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.example.com"
response_scanning:
  enabled: true
  action: strip
  patterns:
    - name: "Test Pattern"
      regex: '(?i)test\s+injection'
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ResponseScanning.Enabled {
		t.Error("expected response scanning enabled")
	}
	if cfg.ResponseScanning.Action != "strip" { //nolint:goconst // test value
		t.Errorf("expected action strip, got %s", cfg.ResponseScanning.Action)
	}
	if len(cfg.ResponseScanning.Patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(cfg.ResponseScanning.Patterns))
	}
	if cfg.ResponseScanning.Patterns[0].Name != "Test Pattern" {
		t.Errorf("expected pattern name 'Test Pattern', got %s", cfg.ResponseScanning.Patterns[0].Name)
	}
}

// --- ValidateReload Tests ---

func TestValidateReload_NoWarnings(t *testing.T) {
	old := Defaults()
	updated := Defaults()

	warnings := ValidateReload(old, updated)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestValidateReload_ModeDowngrade(t *testing.T) {
	old := Defaults()
	old.Mode = ModeStrict
	updated := Defaults()
	updated.Mode = ModeBalanced

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "mode" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected mode downgrade warning")
	}
}

func TestValidateReload_ModeUpgrade_NoWarning(t *testing.T) {
	old := Defaults()
	old.Mode = ModeAudit
	updated := Defaults()
	updated.Mode = ModeStrict

	warnings := ValidateReload(old, updated)
	for _, w := range warnings {
		if w.Field == "mode" {
			t.Errorf("mode upgrade should not produce warning, got: %s", w.Message)
		}
	}
}

func TestValidateReload_DLPPatternsReduced(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.DLP.Patterns = old.DLP.Patterns[:2] // reduce patterns

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "dlp.patterns" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP patterns reduction warning")
	}
}

func TestValidateReload_DLPPatternsIncreased_NoWarning(t *testing.T) {
	old := Defaults()
	old.DLP.Patterns = old.DLP.Patterns[:2]
	updated := Defaults()

	warnings := ValidateReload(old, updated)
	for _, w := range warnings {
		if w.Field == "dlp.patterns" {
			t.Errorf("increasing patterns should not warn, got: %s", w.Message)
		}
	}
}

func TestValidateReload_InternalCIDRsEmptied(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.Internal = nil

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "internal" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected internal CIDRs emptied warning")
	}
}

func TestValidateReload_InternalCIDRsBothEmpty_NoWarning(t *testing.T) {
	old := Defaults()
	old.Internal = nil
	updated := Defaults()
	updated.Internal = nil

	warnings := ValidateReload(old, updated)
	for _, w := range warnings {
		if w.Field == "internal" {
			t.Errorf("both empty should not warn, got: %s", w.Message)
		}
	}
}

func TestValidateReload_EnforceDisabled(t *testing.T) {
	old := Defaults() // Enforce nil => enabled
	v := false
	updated := Defaults()
	updated.Enforce = &v

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "enforce" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected enforce disabled warning")
	}
}

func TestValidateReload_ResponseScanningDisabled(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.ResponseScanning.Enabled = false

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "response_scanning.enabled" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected response scanning disabled warning")
	}
}

func TestValidateReload_MultipleWarnings(t *testing.T) {
	old := Defaults()
	old.Mode = ModeStrict

	v := false
	updated := Defaults()
	updated.Mode = ModeAudit
	updated.DLP.Patterns = nil
	updated.Internal = nil
	updated.Enforce = &v
	updated.ResponseScanning.Enabled = false

	warnings := ValidateReload(old, updated)
	if len(warnings) != 5 {
		t.Errorf("expected 5 warnings, got %d", len(warnings))
		for _, w := range warnings {
			t.Logf("  %s: %s", w.Field, w.Message)
		}
	}
}

func TestValidateReload_MCPInputScanningDisabled(t *testing.T) {
	old := Defaults()
	old.MCPInputScanning.Enabled = true

	updated := Defaults()
	updated.MCPInputScanning.Enabled = false

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "mcp_input_scanning.enabled" {
			found = true
		}
	}
	if !found {
		t.Error("expected warning for MCP input scanning disabled")
	}
}

func TestApplyDefaults_MCPInputScanningActionDefaultsWhenEnabled(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = "" // not set
	cfg.ApplyDefaults()

	if cfg.MCPInputScanning.Action != "warn" {
		t.Errorf("expected Action=warn when enabled with no action, got %q", cfg.MCPInputScanning.Action)
	}
}

func TestApplyDefaults_MCPInputScanningOnParseErrorDefaulted(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning.OnParseError = "" // cleared
	cfg.ApplyDefaults()

	if cfg.MCPInputScanning.OnParseError != "block" {
		t.Errorf("expected OnParseError=block, got %q", cfg.MCPInputScanning.OnParseError)
	}
}

// --- Default DLP Pattern Tests ---

func TestDefaults_ContainsNewDLPPatterns(t *testing.T) {
	cfg := Defaults()
	patterns := make(map[string]bool)
	for _, p := range cfg.DLP.Patterns {
		patterns[p.Name] = true
	}

	required := []string{
		"GitHub Fine-Grained PAT",
		"OpenAI Service Key",
		"Stripe Key",
	}
	for _, name := range required {
		if !patterns[name] {
			t.Errorf("default DLP patterns missing %q", name)
		}
	}
}

func TestDefaults_SlackTokenRegex(t *testing.T) {
	cfg := Defaults()
	found := false
	for _, p := range cfg.DLP.Patterns {
		if p.Name == "Slack Token" {
			found = true
			// Regex should use {15,} not just + to require minimum length
			if p.Regex == "" {
				t.Error("Slack Token regex is empty")
			}
			// Verify the pattern compiles and matches expected format
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				t.Fatalf("Slack Token regex does not compile: %v", err)
			}
			// Build test token at runtime to avoid gitleaks
			prefix := "xoxb"
			suffix := "-1234567890123-abc"
			token := prefix + suffix
			if !re.MatchString(token) {
				t.Error("Slack Token regex should match valid token format")
			}
			break
		}
	}
	if !found {
		t.Fatal("Slack Token pattern not found in defaults")
	}
}

// --- Listen Address Validation ---

func TestValidate_NonLoopbackListenWarning(t *testing.T) {
	cfg := Defaults()
	cfg.FetchProxy.Listen = "0.0.0.0:8888"
	// Should still validate (warning, not error), but the warning goes to stderr
	if err := cfg.Validate(); err != nil {
		t.Errorf("non-loopback listen should validate: %v", err)
	}
}

// --- MCP Input Scanning Validation ---

func TestValidate_MCPInputScanningValidActions(t *testing.T) {
	for _, action := range []string{"warn", "block"} {
		cfg := Defaults()
		cfg.MCPInputScanning.Enabled = true
		cfg.MCPInputScanning.Action = action
		if err := cfg.Validate(); err != nil {
			t.Errorf("action %q should validate, got: %v", action, err)
		}
	}
}

func TestValidate_MCPInputScanningAskRejected(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = "ask"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for ask action on input scanning")
	}
	if !strings.Contains(err.Error(), "must be warn or block") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidate_MCPInputScanningInvalidAction(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = "strip"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for strip action on input scanning")
	}
}

func TestValidate_MCPInputScanningDisabledSkipsValidation(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning.Enabled = false
	cfg.MCPInputScanning.Action = "invalid"
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled input scanning should skip validation, got: %v", err)
	}
}

func TestValidate_MCPInputScanningOnParseErrorValid(t *testing.T) {
	for _, val := range []string{"block", "forward"} { //nolint:goconst // test value
		cfg := Defaults()
		cfg.MCPInputScanning.Enabled = true
		cfg.MCPInputScanning.Action = "warn" //nolint:goconst // test value
		cfg.MCPInputScanning.OnParseError = val
		if err := cfg.Validate(); err != nil {
			t.Errorf("on_parse_error=%q should be valid, got: %v", val, err)
		}
	}
}

func TestValidate_MCPInputScanningOnParseErrorInvalid(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = "warn" //nolint:goconst // test value
	cfg.MCPInputScanning.OnParseError = "ignore"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for on_parse_error=ignore")
	}
	if !strings.Contains(err.Error(), "on_parse_error") {
		t.Errorf("error should mention on_parse_error, got: %v", err)
	}
}

// --- MCPToolScanning Tests ---

func TestApplyDefaults_MCPToolScanningActionDefaultsWhenEnabled(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolScanning.Enabled = true
	cfg.MCPToolScanning.Action = "" // not set
	cfg.ApplyDefaults()

	if cfg.MCPToolScanning.Action != "warn" { //nolint:goconst // test value
		t.Errorf("expected Action=warn when enabled with no action, got %q", cfg.MCPToolScanning.Action)
	}
}

func TestValidate_MCPToolScanningValidActions(t *testing.T) {
	for _, action := range []string{"warn", "block"} {
		cfg := Defaults()
		cfg.MCPToolScanning.Enabled = true
		cfg.MCPToolScanning.Action = action
		if err := cfg.Validate(); err != nil {
			t.Errorf("action %q should validate, got: %v", action, err)
		}
	}
}

func TestValidate_MCPToolScanningInvalidAction(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolScanning.Enabled = true
	cfg.MCPToolScanning.Action = "strip"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for strip action on tool scanning")
	}
}

func TestValidate_MCPToolScanningDisabledSkipsValidation(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolScanning.Enabled = false
	cfg.MCPToolScanning.Action = "invalid"
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled tool scanning should skip validation, got: %v", err)
	}
}

func TestValidateReload_MCPToolScanningDisabled(t *testing.T) {
	old := Defaults()
	old.MCPToolScanning.Enabled = true

	updated := Defaults()
	updated.MCPToolScanning.Enabled = false

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "mcp_tool_scanning.enabled" {
			found = true
		}
	}
	if !found {
		t.Error("expected warning for MCP tool scanning disabled")
	}
}
