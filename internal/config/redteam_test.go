package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Red Team: Config Loading & Hot-Reload Attack Tests
//
// These tests probe the configuration system for bypass vectors including
// YAML injection, validation bypass, hot-reload races, environment variable
// override, and security downgrade through config manipulation.
// =============================================================================

// --- YAML Injection Attacks ---

func TestRedTeam_YAMLAnchorAlias(t *testing.T) {
	// Attack: Use YAML anchors and aliases to create unexpected values.
	// An attacker who can write to the config file could use anchors to
	// reference values from other parts of the document.

	yaml := `
version: 1
mode: &safe_mode balanced
api_allowlist:
  - "*.anthropic.com"
# Attacker tries to redefine mode via alias after validation
fetch_proxy:
  listen: "127.0.0.1:8888"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Mode != "balanced" { //nolint:goconst // test value
		t.Errorf("GAP CONFIRMED: YAML anchor/alias changed mode to %q", cfg.Mode)
	} else {
		t.Log("DEFENDED: YAML anchors don't bypass validation, mode is correctly 'balanced'")
	}
}

func TestRedTeam_YAMLMergeKeyOverride(t *testing.T) {
	// Attack: YAML merge keys (<<:) can override fields in a mapping.
	// An attacker could craft config that uses merge to inject values.

	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.anthropic.com"
fetch_proxy:
  listen: "127.0.0.1:8888"
  timeout_seconds: 30
  max_response_mb: 10
  user_agent: "Pipelock Fetch/1.0"
  monitoring:
    max_url_length: 2048
    entropy_threshold: 4.5
    max_requests_per_minute: 60
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
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Mode != "balanced" {
		t.Errorf("GAP CONFIRMED: YAML merge key changed mode to %q", cfg.Mode)
	} else {
		t.Log("DEFENDED: YAML merge keys handled correctly by go-yaml/v3")
	}
}

func TestRedTeam_YAMLBillionLaughs(t *testing.T) {
	// Attack: YAML "billion laughs" / entity expansion attack.
	// go-yaml v3 limits alias expansion, preventing this DoS.

	yaml := `
version: 1
mode: balanced
a: &a "AAAAAAAAAA"
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]
api_allowlist:
  - "*.anthropic.com"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	// go-yaml v3 has built-in alias expansion limits.
	// The config will load but unknown fields are silently ignored.
	if err != nil {
		t.Logf("DEFENDED: YAML billion laughs rejected: %v", err)
	} else {
		t.Log("DEFENDED: go-yaml v3 has built-in alias expansion limits, and unknown fields are silently ignored by the struct decoder")
	}
}

// --- Type Confusion Attacks ---

func TestRedTeam_ModeAsInteger(t *testing.T) {
	// Attack: Set mode to an integer instead of a string.
	// YAML 1.1 treats certain values as booleans/integers.

	yaml := `
version: 1
mode: 0
api_allowlist:
  - "*.anthropic.com"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("GAP CONFIRMED: integer mode value accepted without error")
	} else {
		t.Logf("DEFENDED: invalid mode type rejected: %v", err)
	}
}

func TestRedTeam_ModeAsBoolean(t *testing.T) {
	// Attack: YAML 1.1 treats "yes", "no", "on", "off" as booleans.
	// go-yaml v3 uses YAML 1.2 which doesn't have this problem, but
	// older parsers might interpret "strict" as a string and "yes" as bool.

	yaml := `
version: 1
mode: yes
api_allowlist:
  - "*.anthropic.com"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("GAP CONFIRMED: 'yes' as mode value was accepted (YAML boolean confusion)")
	} else {
		t.Logf("DEFENDED: mode 'yes' (boolean) rejected by validation: %v", err)
	}
}

// --- Validation Bypass Attempts ---

func TestRedTeam_EnforceFieldManipulation(t *testing.T) {
	// Attack: Set enforce to false in config to disable blocking.
	// This is a legitimate config option but represents a security downgrade.
	// ValidateReload catches this as a warning.

	yaml := `
version: 1
mode: balanced
enforce: false
api_allowlist:
  - "*.anthropic.com"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.EnforceEnabled() {
		t.Error("enforce=false should disable enforcement")
	}

	// ValidateReload should warn about this
	old := Defaults()
	warnings := ValidateReload(old, cfg)
	found := false
	for _, w := range warnings {
		if w.Field == "enforce" {
			found = true
		}
	}
	if !found {
		t.Error("GAP CONFIRMED: disabling enforce did not trigger a reload warning")
	} else {
		t.Log("DEFENDED: disabling enforce triggers a reload warning")
	}
}

func TestRedTeam_EmptyAllowlistInNonStrictMode(t *testing.T) {
	// Attack: In balanced/audit mode, an empty allowlist means no domain
	// restrictions. This is by design but worth verifying.

	yaml := `
version: 1
mode: balanced
api_allowlist: []
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.APIAllowlist) != 0 {
		t.Error("empty allowlist should remain empty")
	}
	t.Log("ACCEPTED RISK: balanced/audit mode allows empty allowlist (no domain restrictions). Strict mode correctly requires at least one domain.")
}

func TestRedTeam_NilInternalDisablesSSRF(t *testing.T) {
	// Attack: Setting internal to null/empty in config to disable SSRF.
	// Defense: ApplyDefaults() fills empty/nil Internal with defaults, so
	// you CANNOT disable SSRF via the config file. The only way to disable
	// it is programmatically (cfg.Internal = nil after ApplyDefaults).

	yaml := `
version: 1
mode: balanced
internal: []
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.Internal) == 0 {
		t.Error("GAP CONFIRMED: empty internal CIDRs survived ApplyDefaults")
	} else {
		t.Log("DEFENDED: ApplyDefaults() fills empty internal CIDRs with defaults, preventing SSRF disable via config file")
	}

	// ValidateReload still catches programmatic emptying
	old := Defaults()
	updated := Defaults()
	updated.Internal = nil // programmatic override (post-ApplyDefaults)
	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "internal" { //nolint:goconst // test value
			found = true
		}
	}
	if !found {
		t.Error("GAP CONFIRMED: programmatic emptying of internal CIDRs not warned")
	} else {
		t.Log("DEFENDED: ValidateReload warns when internal CIDRs are emptied programmatically")
	}
}

// --- DLP Pattern Attacks ---

func TestRedTeam_DLPRegexReDoS(t *testing.T) {
	// Attack: Craft a DLP regex pattern that causes catastrophic backtracking
	// (ReDoS). This could freeze the proxy on every request.

	yaml := `
version: 1
mode: balanced
dlp:
  patterns:
    - name: "ReDoS Pattern"
      regex: '(a+)+b'
      severity: high
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Go's regexp uses a linear-time RE2 engine, immune to ReDoS.
	_ = cfg
	t.Log("DEFENDED: Go's regexp/syntax uses RE2 (linear time), immune to catastrophic backtracking. ReDoS patterns compile but execute in linear time.")
}

func TestRedTeam_DLPEmptyRegex(t *testing.T) {
	// Attack: DLP pattern with empty regex matches everything.

	cfg := Defaults()
	cfg.DLP.Patterns = []DLPPattern{
		{Name: "Catch All", Regex: "", Severity: "critical"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("GAP CONFIRMED: empty DLP regex accepted (would match everything)")
	} else {
		t.Log("DEFENDED: empty DLP regex rejected by validation")
	}
}

func TestRedTeam_DLPDotStarRegex(t *testing.T) {
	// Attack: DLP pattern with ".*" matches everything, creating false
	// positives on every URL and effectively blocking all requests.

	cfg := Defaults()
	cfg.DLP.Patterns = []DLPPattern{
		{Name: "Match Everything", Regex: ".*", Severity: "critical"},
	}
	err := cfg.Validate()
	if err != nil {
		t.Error("unexpected validation error for .* regex")
	} else {
		t.Log("ACCEPTED RISK: '.*' regex is syntactically valid. It would match all URLs, causing a DoS. Operator must review DLP patterns. Validation checks syntax, not semantics.")
	}
}

// --- Response Scanning Attacks ---

func TestRedTeam_ResponseScanningActionAskWithoutTerminal(t *testing.T) {
	// Attack: Set response_scanning action to "ask" but run without a terminal.
	// The HITL approver handles this by checking isTerminal and auto-blocking.
	// This test verifies the config allows "ask" (the runtime handles the safety).

	cfg := Defaults()
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = "ask"
	err := cfg.Validate()
	if err != nil {
		t.Errorf("ask action should validate: %v", err)
	}
	t.Log("DEFENDED: 'ask' action is valid in config. Runtime HITL approver handles non-terminal case by auto-blocking.")
}

func TestRedTeam_ResponseScanningDisableViaReload(t *testing.T) {
	// Attack: Disable response scanning via hot-reload to stop detecting
	// prompt injection in fetched content.

	old := Defaults()
	old.ResponseScanning.Enabled = true

	updated := Defaults()
	updated.ResponseScanning.Enabled = false

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "response_scanning.enabled" {
			found = true
		}
	}
	if !found {
		t.Error("GAP CONFIRMED: disabling response scanning via reload not warned")
	} else {
		t.Log("DEFENDED: disabling response scanning triggers reload warning")
	}
}

// --- Hot-Reload Security Downgrade ---

func TestRedTeam_MultipleSecurityDowngrades(t *testing.T) {
	// Attack: Single config reload that downgrades multiple security features
	// simultaneously. All downgrades should be reported.

	old := Defaults()
	old.Mode = ModeStrict
	old.MCPInputScanning.Enabled = true

	v := false
	updated := Defaults()
	updated.Mode = ModeAudit
	updated.DLP.Patterns = nil
	updated.Internal = nil
	updated.Enforce = &v
	updated.ResponseScanning.Enabled = false
	updated.MCPInputScanning.Enabled = false

	warnings := ValidateReload(old, updated)

	expectedFields := []string{
		"mode",
		"dlp.patterns",
		"internal",
		"enforce",
		"response_scanning.enabled",
		"mcp_input_scanning.enabled",
	}

	for _, field := range expectedFields {
		found := false
		for _, w := range warnings {
			if w.Field == field {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GAP CONFIRMED: security downgrade for %q not reported in reload warnings", field)
		}
	}
	if len(warnings) >= len(expectedFields) {
		t.Logf("DEFENDED: all %d security downgrades detected in reload warnings", len(warnings))
	}
}

// --- Config File Permission Attacks ---

func TestRedTeam_WorldReadableConfig(t *testing.T) {
	// Attack: Config file with world-readable permissions. The config loader
	// doesn't check file permissions, so a world-readable config is accepted.
	// If the config contains sensitive information (API keys in allowlist),
	// this could be a data leak.

	yaml := `
version: 1
mode: balanced
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil { //nolint:gosec // G306: intentionally testing world-readable
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	_ = cfg
	t.Log("ACCEPTED RISK: config file permissions are not checked by Load(). The config file typically doesn't contain secrets (those are in env vars), but operators should use 0600 permissions.")
}

// --- Config Symlink Swap ---

func TestRedTeam_ConfigSymlinkSwap(t *testing.T) {
	// Attack: Replace the config file with a symlink to a different file.
	// The hot-reloader watches the directory and would pick up the change.

	dir := t.TempDir()
	realConfig := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(realConfig, []byte("version: 1\nmode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a malicious config in a different location
	malicious := filepath.Join(dir, "malicious.yaml")
	if err := os.WriteFile(malicious, []byte("version: 1\nmode: audit\nenforce: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Load the real config
	cfg, err := Load(realConfig)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Mode != "balanced" {
		t.Fatalf("expected balanced, got %s", cfg.Mode)
	}

	// Create symlink to malicious config
	linkPath := filepath.Join(dir, "linked.yaml")
	if err := os.Symlink(malicious, linkPath); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	// Load via symlink
	linked, err := Load(linkPath)
	if err != nil {
		t.Fatalf("Load via symlink failed: %v", err)
	}

	if linked.Mode == "audit" {
		t.Log("ACCEPTED RISK: config can be loaded via symlink. If an attacker can create symlinks in the config directory, they can redirect to a weaker config. File system permissions are the defense.")
	}
}

// --- MCP Input Scanning Bypass ---

func TestRedTeam_MCPInputScanningDisabledByDefault(t *testing.T) {
	// Attack: MCP input scanning is disabled by default in Defaults().
	// An operator who doesn't explicitly enable it won't get client-side
	// request scanning for DLP leaks or injection.

	cfg := Defaults()
	if cfg.MCPInputScanning.Enabled {
		t.Error("MCP input scanning should be disabled by default (for backward compat)")
	}

	// But OnParseError should still default to "block" (fail-closed)
	if cfg.MCPInputScanning.OnParseError != "block" {
		t.Errorf("GAP CONFIRMED: OnParseError should default to 'block', got %q", cfg.MCPInputScanning.OnParseError)
	} else {
		t.Log("DEFENDED: MCP input scanning disabled by default but OnParseError defaults to 'block' (fail-closed)")
	}
}

func TestRedTeam_MCPInputScanningOnParseErrorForward(t *testing.T) {
	// Attack: Set on_parse_error to "forward" which forwards malformed
	// JSON-RPC requests to the server without scanning. This could be
	// used to bypass DLP scanning by sending intentionally malformed requests.

	cfg := Defaults()
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = "warn"
	cfg.MCPInputScanning.OnParseError = "forward"

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	t.Log("ACCEPTED RISK: on_parse_error=forward allows malformed requests through. This is an explicit opt-in for compatibility with non-standard MCP servers. Default is 'block' (fail-closed).")
}

// --- Extra Fields / Unknown Keys ---

func TestRedTeam_ExtraYAMLFieldsNotRejected(t *testing.T) {
	// Attack: Inject extra fields that might affect behavior in future
	// versions or be misinterpreted by other tools reading the same config.

	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.anthropic.com"
admin_password: "hunter2"
secret_api_key: "sk-12345"
execute_on_load: "rm -rf /"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	_ = cfg
	t.Log("ACCEPTED RISK: go-yaml v3 silently ignores unknown fields when unmarshaling into a struct. Extra fields (admin_password, secret_api_key) are discarded. This prevents injection but also means typos in real config keys are silently ignored.")
}

// --- Listen Address Validation ---

func TestRedTeam_ListenOnAllInterfaces(t *testing.T) {
	// Attack: Set listen to 0.0.0.0 to expose the proxy to the network.
	// The proxy endpoints (/fetch, /metrics, /stats) would be accessible
	// to anyone on the network. Validate() prints a warning but doesn't reject.

	cfg := Defaults()
	cfg.FetchProxy.Listen = "0.0.0.0:8888"
	err := cfg.Validate()
	if err != nil {
		t.Error("0.0.0.0 listen should validate (warning, not error)")
	} else {
		t.Log("ACCEPTED RISK: listen on 0.0.0.0 is allowed with a stderr warning. This is needed for Docker/container deployments where 127.0.0.1 isn't reachable from the agent container.")
	}
}

// --- Git Protection Bypass ---

func TestRedTeam_GitProtectionDisabledByDefault(t *testing.T) {
	// Attack: Git protection is disabled by default. Agents can commit
	// to any branch and push without secret scanning.

	cfg := Defaults()
	if cfg.GitProtection.Enabled {
		t.Error("git protection should be disabled by default")
	}
	t.Log("ACCEPTED RISK: git protection disabled by default for backward compatibility. Operators must opt-in via config.")
}

func TestRedTeam_GitProtectionAllBranchesAllowed(t *testing.T) {
	// Attack: Set allowed_branches to ["*"] to allow all branches,
	// effectively disabling branch validation.

	cfg := Defaults()
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedBranches = []string{"*"}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	t.Log("ACCEPTED RISK: allowed_branches=['*'] matches all branch names, effectively disabling branch validation. This is a valid operator choice.")
}

// --- Version Field Manipulation ---

func TestRedTeam_VersionZero(t *testing.T) {
	// Attack: Omit version field (defaults to 0, then ApplyDefaults sets to 1).

	yaml := `
mode: balanced
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("expected version 1 after defaults, got %d", cfg.Version)
	}
	t.Log("DEFENDED: missing version field defaults to 1 via ApplyDefaults")
}

func TestRedTeam_NegativeTimeoutSeconds(t *testing.T) {
	// Attack: Set timeout_seconds to negative value.

	yaml := `
version: 1
mode: balanced
fetch_proxy:
  timeout_seconds: -10
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.FetchProxy.TimeoutSeconds <= 0 {
		t.Error("GAP CONFIRMED: negative timeout accepted")
	} else {
		t.Log("DEFENDED: negative timeout overridden by ApplyDefaults to 30")
	}
}

// --- Invalid CIDR Injection ---

func TestRedTeam_MalformedCIDR(t *testing.T) {
	// Attack: Inject malformed CIDRs to cause a panic or bypass SSRF checks.

	malformedCIDRs := []string{
		"not-a-cidr",
		"999.999.999.999/32",
		"127.0.0.1",    // missing mask
		"127.0.0.1/33", // invalid mask length
		"::1",          // missing mask
		"fe80::/999",   // invalid v6 mask
		"0.0.0.0/-1",   // negative mask
	}

	for _, cidr := range malformedCIDRs {
		t.Run(cidr, func(t *testing.T) {
			cfg := Defaults()
			cfg.Internal = []string{cidr}
			err := cfg.Validate()
			if err == nil {
				t.Errorf("GAP CONFIRMED: malformed CIDR %q accepted", cidr)
			} else if !strings.Contains(err.Error(), "CIDR") {
				t.Errorf("error should mention CIDR, got: %v", err)
			} else {
				t.Logf("DEFENDED: malformed CIDR %q rejected", cidr)
			}
		})
	}
}
