//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package config_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// testLicenseKeyPair generates an Ed25519 keypair and a valid signed license
// token for testing. Returns the token string and the hex-encoded public key.
func testLicenseKeyPair(t *testing.T) (token, pubKeyHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lic := license.License{
		ID:        "lic_test",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	tok, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tok, hex.EncodeToString(pub)
}

// TestAgentProfileParsing tests YAML parsing of the agents section.
// Enterprise-gated because Load() calls EnforceLicenseGateFunc, which strips
// non-default agents when no valid license is present.
func TestAgentProfileParsing(t *testing.T) {
	token, pubHex := testLicenseKeyPair(t)
	yamlContent := "mode: balanced\nlicense_key: " + token + "\nlicense_public_key: " + pubHex + "\n" + `agents:
  claude-code:
    mode: strict
    enforce: true
    api_allowlist:
      - github.com
    dlp:
      include_defaults: true
      patterns:
        - name: "Internal Token"
          regex: "int_tok_[A-Za-z0-9]{32}"
          severity: critical
    budget:
      max_requests_per_session: 500
      max_bytes_per_session: 10485760
      max_unique_domains_per_session: 50
      window_minutes: 60
  _default:
    mode: balanced
    budget:
      max_unique_domains_per_session: 25
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(cfg.Agents))
	}

	cc := cfg.Agents["claude-code"]
	if cc.Mode != config.ModeStrict {
		t.Errorf("claude-code mode = %q, want strict", cc.Mode)
	}
	if cc.Enforce == nil || !*cc.Enforce {
		t.Error("claude-code enforce should be true")
	}
	if len(cc.APIAllowlist) != 1 || cc.APIAllowlist[0] != "github.com" {
		t.Errorf("claude-code api_allowlist = %v, want [github.com]", cc.APIAllowlist)
	}
	if cc.DLP == nil {
		t.Fatal("claude-code dlp should not be nil")
	}
	if cc.DLP.IncludeDefaults == nil || !*cc.DLP.IncludeDefaults {
		t.Error("claude-code dlp.include_defaults should be true")
	}
	if len(cc.DLP.Patterns) != 1 {
		t.Fatalf("expected 1 dlp pattern, got %d", len(cc.DLP.Patterns))
	}
	if cc.DLP.Patterns[0].Name != "Internal Token" {
		t.Errorf("dlp pattern name = %q, want %q", cc.DLP.Patterns[0].Name, "Internal Token")
	}
	if cc.Budget.MaxRequestsPerSession != 500 {
		t.Errorf("budget.max_requests = %d, want 500", cc.Budget.MaxRequestsPerSession)
	}
	if cc.Budget.MaxBytesPerSession != 10485760 {
		t.Errorf("budget.max_bytes = %d, want 10485760", cc.Budget.MaxBytesPerSession)
	}
	if cc.Budget.MaxUniqueDomainsPerSession != 50 {
		t.Errorf("budget.max_unique_domains = %d, want 50", cc.Budget.MaxUniqueDomainsPerSession)
	}
	if cc.Budget.WindowMinutes != 60 {
		t.Errorf("budget.window_minutes = %d, want 60", cc.Budget.WindowMinutes)
	}

	def := cfg.Agents["_default"]
	if def.Mode != config.ModeBalanced {
		t.Errorf("_default mode = %q, want balanced", def.Mode)
	}
	if def.Budget.MaxUniqueDomainsPerSession != 25 {
		t.Errorf("_default budget.max_unique_domains = %d, want 25", def.Budget.MaxUniqueDomainsPerSession)
	}
	if def.Budget.MaxRequestsPerSession != 0 {
		t.Errorf("_default budget.max_requests should be 0, got %d", def.Budget.MaxRequestsPerSession)
	}
}

// Integration tests: Validate() calls ValidateAgentsFunc hook.

func TestValidateAgentsDuplicateListeners(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"a": {Listeners: []string{":8889"}},
		"b": {Listeners: []string{":8889"}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for duplicate listener")
	}
	if !strings.Contains(err.Error(), "collides") {
		t.Errorf("error should mention collision, got: %v", err)
	}
}

func TestValidateAgentsDuplicateListenerWithMain(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"a": {Listeners: []string{config.DefaultListen}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for listener colliding with main listen")
	}
	if !strings.Contains(err.Error(), "collides") {
		t.Errorf("error should mention collision, got: %v", err)
	}
}

func TestValidateAgentsInvalidMode(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"bad-agent": {Mode: "invalid_mode"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid agent mode")
	}
	if !strings.Contains(err.Error(), "bad-agent") {
		t.Errorf("error should mention agent name, got: %v", err)
	}
}

func TestValidateAgentsEmptyName(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"": {Mode: config.ModeStrict},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for empty agent name")
	}
}

func TestValidateAgentsValidConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {
			Listeners:    []string{":8889"},
			Mode:         config.ModeStrict,
			APIAllowlist: []string{"github.com"},
		},
		"agent-b": {
			Listeners: []string{":8890"},
			Mode:      config.ModeAudit,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAgentsNegativeBudget(t *testing.T) {
	fields := []struct {
		name   string
		modify func(*config.BudgetConfig)
	}{
		{"max_requests_per_session", func(b *config.BudgetConfig) { b.MaxRequestsPerSession = -1 }},
		{"max_bytes_per_session", func(b *config.BudgetConfig) { b.MaxBytesPerSession = -1 }},
		{"max_unique_domains_per_session", func(b *config.BudgetConfig) { b.MaxUniqueDomainsPerSession = -1 }},
		{"window_minutes", func(b *config.BudgetConfig) { b.WindowMinutes = -1 }},
	}
	for _, tt := range fields {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			budget := config.BudgetConfig{}
			tt.modify(&budget)
			cfg.Agents = map[string]config.AgentProfile{
				"test": {Budget: budget},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for negative %s", tt.name)
			}
		})
	}
}

func TestValidateAgentSourceCIDRsInvalid(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {SourceCIDRs: []string{"not-a-cidr"}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid CIDR")
	}
}

func TestValidateAgentsNegativeRateLimits(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"bad-agent": {
			RateLimit: &config.AgentRateLimit{
				MaxRequestsPerMinute: -1,
			},
		},
	}
	cfg.ApplyDefaults()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for negative rate limit")
	}
	if !strings.Contains(err.Error(), "max_requests_per_minute must be >= 0") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Integration tests: Load() calls EnforceLicenseGateFunc hook.

func TestLicenseGateViaLoad(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "cfg.yaml")
	data := "mode: balanced\nagents:\n  claude-code:\n    mode: audit\n"
	if err := os.WriteFile(cfgPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agents != nil {
		t.Error("agents should be disabled by license gate when loaded without license_key")
	}
}

func TestLicenseGateViaLoad_WithValidToken(t *testing.T) {
	token, pubHex := testLicenseKeyPair(t)
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "cfg.yaml")
	data := "mode: balanced\nlicense_key: " + token + "\nlicense_public_key: " + pubHex + "\nagents:\n  claude-code:\n    mode: audit\n"
	if err := os.WriteFile(cfgPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agents == nil {
		t.Error("agents should NOT be disabled with valid license token")
	}
	if _, ok := cfg.Agents["claude-code"]; !ok {
		t.Error("claude-code profile should be present")
	}
}
