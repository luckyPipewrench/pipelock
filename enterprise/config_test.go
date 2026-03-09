//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestValidateAgents_ValidConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict, APIAllowlist: []string{"api.anthropic.com"}},
		"_default":    {Mode: config.ModeBalanced},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestValidateAgents_NoAgents(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = nil
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("expected no error for nil agents: %v", err)
	}
}

func TestValidateAgents_EmptyName(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"": {Mode: config.ModeBalanced},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for empty agent name")
	}
}

func TestValidateAgents_InvalidName(t *testing.T) {
	cfg := testConfig()
	tests := []struct {
		name    string
		agent   string
		wantErr bool
	}{
		{"spaces", "my agent", true},
		{"reserved anonymous", "anonymous", true},
		{"special chars", "agent!@#", true},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true}, // 69 chars > 64
		{"_default allowed", "_default", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.Agents = map[string]config.AgentProfile{
				tt.agent: {Mode: config.ModeBalanced},
			}
			err := ValidateAgents(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAgents(%q) error = %v, wantErr %v", tt.agent, err, tt.wantErr)
			}
		})
	}
}

func TestValidateAgents_InvalidMode(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"bad-agent": {Mode: "invalid-mode"},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestValidateAgents_DuplicateListeners(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {Listeners: []string{":9001"}},
		"agent-b": {Listeners: []string{":9001"}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for duplicate listeners")
	}
}

func TestValidateAgents_ListenerCollidesWithMain(t *testing.T) {
	cfg := testConfig()
	// Default fetch_proxy.listen is typically ":8888".
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {Listeners: []string{cfg.FetchProxy.Listen}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for listener colliding with main")
	}
}

func TestValidateAgents_ListenerCollisionCanonical(t *testing.T) {
	cfg := testConfig()
	// ":8888" binds 0.0.0.0:8888, same as "0.0.0.0:8888".
	cfg.FetchProxy.Listen = "0.0.0.0:8888"
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {Listeners: []string{":8888"}},
	}
	err := ValidateAgents(cfg)
	if err == nil {
		t.Fatal("expected error: ':8888' and '0.0.0.0:8888' bind the same port")
	}
}

func TestValidateAgents_InvalidListenerFormat(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {Listeners: []string{"not-a-valid-addr"}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for invalid listener format")
	}
}

func TestValidateAgents_NegativeBudget(t *testing.T) {
	fields := []struct {
		name   string
		budget config.BudgetConfig
	}{
		{"max_requests", config.BudgetConfig{MaxRequestsPerSession: -1}},
		{"max_bytes", config.BudgetConfig{MaxBytesPerSession: -1}},
		{"max_domains", config.BudgetConfig{MaxUniqueDomainsPerSession: -1}},
		{"window_minutes", config.BudgetConfig{WindowMinutes: -1}},
	}
	for _, tt := range fields {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Agents = map[string]config.AgentProfile{
				"agent": {Budget: tt.budget},
			}
			if err := ValidateAgents(cfg); err == nil {
				t.Fatalf("expected error for negative %s", tt.name)
			}
		})
	}
}

func TestValidateAgents_SourceCIDRsValid(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {SourceCIDRs: []string{"10.0.0.0/24"}},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("expected valid CIDRs: %v", err)
	}
}

func TestValidateAgents_SourceCIDRsInvalid(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {SourceCIDRs: []string{"not-a-cidr"}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestValidateAgents_SourceCIDRsOverlap(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {SourceCIDRs: []string{"10.0.0.0/24"}},
		"agent-b": {SourceCIDRs: []string{"10.0.0.0/16"}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for overlapping CIDRs across agents")
	}
}

func TestValidateAgents_SourceCIDRsSameAgentAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {SourceCIDRs: []string{"10.0.0.0/24", "10.0.0.0/16"}},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("same-agent CIDR overlap should be allowed: %v", err)
	}
}

func TestValidateAgents_InvalidDLPPattern(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			DLP: &config.AgentDLP{
				Patterns: []config.DLPPattern{{Name: "bad", Regex: "[invalid"}},
			},
		},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for invalid DLP regex")
	}
}

func TestValidateAgents_NegativeRateLimits(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			RateLimit: &config.AgentRateLimit{MaxRequestsPerMinute: -1},
		},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for negative rate limit")
	}
}

func TestMergeAgentProfile_NilProfile(t *testing.T) {
	cfg := testConfig()
	merged, err := MergeAgentProfile(cfg, nil)
	if err != nil {
		t.Fatalf("MergeAgentProfile nil: %v", err)
	}
	if merged == cfg {
		t.Error("expected deep copy, not same pointer")
	}
}

func TestMergeAgentProfile_ModeOverride(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeBalanced
	profile := &config.AgentProfile{Mode: config.ModeStrict}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Mode != config.ModeStrict {
		t.Errorf("mode = %q, want strict", merged.Mode)
	}
	// Base should be unchanged.
	if cfg.Mode != config.ModeBalanced {
		t.Error("base config was mutated")
	}
}

func TestMergeAgentProfile_DLPIncludeDefaults(t *testing.T) {
	cfg := testConfig()
	// cfg.DLP.Patterns has default patterns.
	baseCount := len(cfg.DLP.Patterns)

	profile := &config.AgentProfile{
		DLP: &config.AgentDLP{
			Patterns: []config.DLPPattern{{Name: "custom", Regex: "custom-.*"}},
		},
	}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	// Should have base patterns + custom (include_defaults = nil means true).
	if len(merged.DLP.Patterns) != baseCount+1 {
		t.Errorf("expected %d patterns, got %d", baseCount+1, len(merged.DLP.Patterns))
	}
}

func TestMergeAgentProfile_DLPReplaceDefaults(t *testing.T) {
	cfg := testConfig()
	f := false
	profile := &config.AgentProfile{
		DLP: &config.AgentDLP{
			IncludeDefaults: &f,
			Patterns:        []config.DLPPattern{{Name: "only", Regex: "only-.*"}},
		},
	}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.DLP.Patterns) != 1 {
		t.Errorf("expected 1 pattern (replace mode), got %d", len(merged.DLP.Patterns))
	}
}

func TestValidateMergedAgent_StrictNoAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = nil
	if err := ValidateMergedAgent("test", cfg); err == nil {
		t.Fatal("expected error for strict mode without allowlist")
	}
}

func TestValidateMergedAgent_Valid(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.example.com"}
	if err := ValidateMergedAgent("test", cfg); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func testLicenseKeyPair(t *testing.T) (token string, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lic := license.License{
		ID:        "lic_test123",
		Email:     "test@example.com",
		Features:  []string{license.FeatureAgents},
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	tok, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tok, hex.EncodeToString(pub)
}

func TestEnforceLicenseGate_NoAgents(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = nil
	EnforceLicenseGate(cfg) // should not panic
}

func TestEnforceLicenseGate_OnlyDefault(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"_default": {Mode: config.ModeBalanced},
	}
	EnforceLicenseGate(cfg)
	if cfg.Agents == nil {
		t.Error("_default-only agents should not be disabled")
	}
}

func TestEnforceLicenseGate_NoLicenseKey(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	cfg.LicenseKey = ""
	EnforceLicenseGate(cfg)
	if cfg.Agents != nil {
		t.Error("expected agents disabled when no license key")
	}
}

func TestEnforceLicenseGate_ValidLicense(t *testing.T) {
	token, pubHex := testLicenseKeyPair(t)
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	cfg.LicenseKey = token
	cfg.LicensePublicKey = pubHex

	EnforceLicenseGate(cfg)
	if cfg.Agents == nil {
		t.Error("expected agents to remain with valid license")
	}
	if cfg.LicenseExpiresAt == 0 {
		t.Error("expected non-zero LicenseExpiresAt after valid license")
	}
}

func TestEnforceLicenseGate_InvalidToken(t *testing.T) {
	_, pubHex := testLicenseKeyPair(t)
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	cfg.LicenseKey = "invalid-token"
	cfg.LicensePublicKey = pubHex

	EnforceLicenseGate(cfg)
	if cfg.Agents != nil {
		t.Error("expected agents disabled with invalid token")
	}
}

func TestEnforceLicenseGate_ExpiredLicense(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lic := license.License{
		ID:        "lic_expired",
		Email:     "test@example.com",
		Features:  []string{license.FeatureAgents},
		ExpiresAt: time.Now().Add(-24 * time.Hour).Unix(), // expired yesterday
	}
	tok, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	cfg.LicenseKey = tok
	cfg.LicensePublicKey = hex.EncodeToString(pub)

	EnforceLicenseGate(cfg)
	if cfg.Agents != nil {
		t.Error("expected agents disabled with expired license")
	}
}

func TestEnforceLicenseGate_MissingFeature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lic := license.License{
		ID:        "lic_nofeature",
		Email:     "test@example.com",
		Features:  []string{"some-other-feature"}, // no "agents" feature
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	tok, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	cfg.LicenseKey = tok
	cfg.LicensePublicKey = hex.EncodeToString(pub)

	EnforceLicenseGate(cfg)
	if cfg.Agents != nil {
		t.Error("expected agents disabled when license lacks 'agents' feature")
	}
}

func TestDeepCopyConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict

	cloned, err := deepCopyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cloned.Mode = config.ModeAudit
	if cfg.Mode != config.ModeStrict {
		t.Error("deep copy mutated original")
	}
}
