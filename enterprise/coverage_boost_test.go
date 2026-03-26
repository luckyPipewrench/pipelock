//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const testMetricsListen = ":9090"

// --- ValidateMergedAgent coverage tests ---
// These tests target the 57.7% → higher coverage gap.

func TestValidateMergedAgent_TrustedDomainsInvalid(t *testing.T) {
	cfg := testConfig()
	// ValidateTrustedDomains rejects bare wildcard domains.
	cfg.TrustedDomains = []string{"*"}
	err := ValidateMergedAgent("test-agent", cfg)
	if err == nil {
		t.Fatal("expected error for bare wildcard in trusted_domains")
	}
}

func TestValidateMergedAgent_SessionProfilingEnabledEmptyAction(t *testing.T) {
	cfg := testConfig()
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.AnomalyAction = "" // empty action is valid (uses default)
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("empty anomaly_action with profiling enabled should be valid: %v", err)
	}
}

func TestValidateMergedAgent_SessionProfilingBlockAction(t *testing.T) {
	cfg := testConfig()
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.AnomalyAction = config.ActionBlock
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("block anomaly_action should be valid: %v", err)
	}
}

func TestValidateMergedAgent_MCPToolPolicyEnabledEmptyAction(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = "" // empty action is valid (uses default)
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("empty mcp_tool_policy action should be valid: %v", err)
	}
}

func TestValidateMergedAgent_BalancedModeNoAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeBalanced
	cfg.APIAllowlist = nil
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("balanced mode without allowlist should be valid: %v", err)
	}
}

func TestValidateMergedAgent_AuditModeNoAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeAudit
	cfg.APIAllowlist = nil
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("audit mode without allowlist should be valid: %v", err)
	}
}

func TestValidateMergedAgent_StrictModeWithAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.example.com"}
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("strict mode with allowlist should be valid: %v", err)
	}
}

func TestValidateMergedAgent_RedirectProfileValidExec(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionBlock
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"handler": {Exec: []string{"/usr/bin/handler", "--arg1"}},
	}
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{
			Name:            "redirect-rule",
			Action:          config.ActionRedirect,
			RedirectProfile: "handler",
		},
	}
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("valid redirect config should pass: %v", err)
	}
}

func TestValidateMergedAgent_RuleNonRedirectAction(t *testing.T) {
	// Rule with block action should not require redirect_profile.
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionBlock
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "block-rule", Action: config.ActionBlock},
	}
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("block rule without redirect_profile should be valid: %v", err)
	}
}

func TestValidateMergedAgent_RuleWarnAction(t *testing.T) {
	// Rule with warn action should not require redirect_profile.
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionWarn
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "warn-rule", Action: config.ActionWarn},
	}
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("warn rule without redirect_profile should be valid: %v", err)
	}
}

func TestValidateMergedAgent_MultipleRedirectProfiles(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionBlock
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"handler-a": {Exec: []string{"/usr/bin/a"}},
		"handler-b": {Exec: []string{"/usr/bin/b", "--flag"}},
	}
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "rule-a", Action: config.ActionRedirect, RedirectProfile: "handler-a"},
		{Name: "rule-b", Action: config.ActionRedirect, RedirectProfile: "handler-b"},
	}
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("multiple valid redirect profiles should pass: %v", err)
	}
}

func TestValidateMergedAgent_MCPToolPolicyDisabledWithRedirectProfiles(t *testing.T) {
	// Disabled policy skips validation even with invalid profiles.
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = false
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"bad": {Exec: []string{}}, // would be invalid if enabled
	}
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Fatalf("disabled policy should skip redirect profile validation: %v", err)
	}
}

// --- deepCopyConfig coverage tests ---

func TestDeepCopyConfig_Independence(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.example.com", "api2.example.com"}

	cloned, err := deepCopyConfig(cfg)
	if err != nil {
		t.Fatalf("deepCopyConfig error: %v", err)
	}

	// Modify cloned config.
	cloned.Mode = config.ModeAudit
	cloned.APIAllowlist = append(cloned.APIAllowlist, "mutated.example.com")

	// Verify original is unchanged.
	if cfg.Mode != config.ModeStrict {
		t.Errorf("original mode was mutated: got %q, want %q", cfg.Mode, config.ModeStrict)
	}
	if len(cfg.APIAllowlist) != 2 {
		t.Errorf("original allowlist was mutated: got %d items, want 2", len(cfg.APIAllowlist))
	}
}

func TestDeepCopyConfig_NilFields(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = nil
	cfg.Enforce = nil
	cfg.Suppress = nil

	cloned, err := deepCopyConfig(cfg)
	if err != nil {
		t.Fatalf("deepCopyConfig with nil fields: %v", err)
	}
	if cloned == nil {
		t.Fatal("expected non-nil cloned config")
	}
	if cloned == cfg {
		t.Error("cloned config should not be same pointer as original")
	}
}

func TestDeepCopyConfig_EmptySlices(t *testing.T) {
	cfg := testConfig()
	cfg.APIAllowlist = []string{}
	cfg.DLP.Patterns = []config.DLPPattern{}

	cloned, err := deepCopyConfig(cfg)
	if err != nil {
		t.Fatalf("deepCopyConfig with empty slices: %v", err)
	}

	// Modify cloned to ensure independence.
	cloned.APIAllowlist = append(cloned.APIAllowlist, "added.com")
	if len(cfg.APIAllowlist) != 0 {
		t.Error("original empty slice was mutated")
	}
}

func TestDeepCopyConfig_DLPPatternsIndependent(t *testing.T) {
	cfg := testConfig()
	originalLen := len(cfg.DLP.Patterns)

	cloned, err := deepCopyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cloned.DLP.Patterns = append(cloned.DLP.Patterns, config.DLPPattern{
		Name:  "injected",
		Regex: "injected-.*",
	})

	if len(cfg.DLP.Patterns) != originalLen {
		t.Errorf("original DLP patterns mutated: got %d, want %d", len(cfg.DLP.Patterns), originalLen)
	}
}

func TestDeepCopyConfig_PreservesValues(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeBalanced
	cfg.FetchProxy.Listen = "127.0.0.1:9999"
	cfg.MetricsListen = testMetricsListen

	cloned, err := deepCopyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if cloned.Mode != config.ModeBalanced {
		t.Errorf("Mode = %q, want %q", cloned.Mode, config.ModeBalanced)
	}
	if cloned.FetchProxy.Listen != "127.0.0.1:9999" {
		t.Errorf("FetchProxy.Listen = %q, want 127.0.0.1:9999", cloned.FetchProxy.Listen)
	}
	if cloned.MetricsListen != testMetricsListen {
		t.Errorf("MetricsListen = %q, want :9090", cloned.MetricsListen)
	}
}

// --- MergeAgentProfile edge case: DLP dedup ---

func TestMergeAgentProfile_DLPDedup(t *testing.T) {
	cfg := testConfig()
	// Ensure there's at least one base pattern.
	if len(cfg.DLP.Patterns) == 0 {
		t.Skip("no base DLP patterns to test dedup against")
	}
	// Override a base pattern by name.
	overriddenName := cfg.DLP.Patterns[0].Name
	profile := &config.AgentProfile{
		DLP: &config.AgentDLP{
			Patterns: []config.DLPPattern{
				{Name: overriddenName, Regex: "overridden-regex-.*"},
			},
		},
	}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}

	// The overridden pattern should appear exactly once.
	count := 0
	for _, p := range merged.DLP.Patterns {
		if p.Name == overriddenName {
			count++
			if p.Regex != "overridden-regex-.*" {
				t.Errorf("expected overridden regex, got %q", p.Regex)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 occurrence of %q, got %d", overriddenName, count)
	}
}

// --- ValidateAgents: TrustedDomains on agent profile ---

func TestValidateAgents_TrustedDomainsInvalidPattern(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			TrustedDomains: []string{"*"},
		},
	}
	err := ValidateAgents(cfg)
	if err == nil {
		t.Fatal("expected error for bare wildcard in agent trusted_domains")
	}
}

func TestValidateAgents_TrustedDomainsValid(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			TrustedDomains: []string{"internal.corp", "*.dev.local"},
		},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("valid trusted_domains should pass: %v", err)
	}
}

// --- ValidateAgents: MetricsListen collision ---

func TestValidateAgents_ListenerCollidesWithMetrics(t *testing.T) {
	cfg := testConfig()
	cfg.MetricsListen = testMetricsListen
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {Listeners: []string{testMetricsListen}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for listener colliding with metrics_listen")
	}
}

// --- ValidateAgents: KillSwitch API collision ---

func TestValidateAgents_ListenerCollidesWithKillSwitchAPI(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIListen = ":7777"
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {Listeners: []string{":7777"}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for listener colliding with kill_switch.api_listen")
	}
}

// --- ValidateAgents: sandbox valid paths ---

func TestValidateAgents_SandboxValidPaths(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			Sandbox: &config.AgentSandboxOverride{
				FS: &config.SandboxFilesystem{
					AllowRead:  []string{"/var/data"},
					AllowWrite: []string{"/tmp/output"},
				},
			},
		},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("valid sandbox paths should pass: %v", err)
	}
}

// --- ValidateAgents: sandbox nil FS ---

func TestValidateAgents_SandboxNilFS(t *testing.T) {
	cfg := testConfig()
	enabled := true
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			Sandbox: &config.AgentSandboxOverride{
				Enabled: &enabled,
				FS:      nil, // explicit nil FS
			},
		},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("nil sandbox FS should pass validation: %v", err)
	}
}

// --- ValidateAgents: valid rate limit ---

func TestValidateAgents_ValidRateLimits(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			RateLimit: &config.AgentRateLimit{
				MaxRequestsPerMinute: 100,
				MaxDataPerMinute:     1024,
			},
		},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("valid rate limits should pass: %v", err)
	}
}

// --- ValidateAgents: zero rate limits (valid, means unlimited) ---

func TestValidateAgents_ZeroRateLimits(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			RateLimit: &config.AgentRateLimit{
				MaxRequestsPerMinute: 0,
				MaxDataPerMinute:     0,
			},
		},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("zero rate limits should pass (means unlimited): %v", err)
	}
}
