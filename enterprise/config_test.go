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
	tests := []struct {
		name          string
		fetchListen   string
		agentListener string
		wantCollision bool
	}{
		// IPv4: empty host and 0.0.0.0 are both "all interfaces"
		{"empty vs explicit ipv4", "0.0.0.0:8888", ":8888", true},
		{"explicit ipv4 vs empty", ":8888", "0.0.0.0:8888", true},

		// IPv6: [::] is "all interfaces" and conflicts with 0.0.0.0 on dual-stack
		{"ipv6 all vs empty", ":8888", "[::]:8888", true},
		{"ipv6 all vs ipv4 all", "0.0.0.0:8888", "[::]:8888", true},
		{"ipv4 all vs ipv6 all", "[::]:8888", "0.0.0.0:8888", true},

		// Verbose IPv6 zero forms
		{"verbose ipv6 zero", "0.0.0.0:8888", "[0:0:0:0:0:0:0:0]:8888", true},

		// Loopback addresses conflict with bind-all on the same port:
		// 0.0.0.0 grabs all interfaces including loopback.
		{"ipv4 loopback vs all", "0.0.0.0:8888", "127.0.0.1:8888", true},
		{"ipv6 loopback vs all", "0.0.0.0:8888", "[::1]:8888", true},

		// Different ports never collide
		{"same host different port", "0.0.0.0:8888", "0.0.0.0:9999", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.FetchProxy.Listen = tt.fetchListen
			cfg.Agents = map[string]config.AgentProfile{
				"agent-a": {Listeners: []string{tt.agentListener}},
			}
			err := ValidateAgents(cfg)
			if tt.wantCollision && err == nil {
				t.Fatalf("expected collision: %s vs %s", tt.fetchListen, tt.agentListener)
			}
			if !tt.wantCollision && err != nil {
				t.Fatalf("unexpected collision: %v", err)
			}
		})
	}
}

func TestCanonicalizeAddr(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty host", ":8888", "0.0.0.0:8888"},
		{"ipv4 all", "0.0.0.0:8888", "0.0.0.0:8888"},
		{"ipv6 all", "[::]:8888", "0.0.0.0:8888"},
		{"verbose ipv6 zero", "[0:0:0:0:0:0:0:0]:8888", "0.0.0.0:8888"},
		{"ipv4 loopback", "127.0.0.1:8888", "127.0.0.1:8888"},
		{"ipv6 loopback", "[::1]:8888", "[::1]:8888"},
		{"non-canonical ipv6", "[0000::1]:8888", "[::1]:8888"},
		{"invalid", "not-valid", "not-valid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalizeAddr(tt.input)
			if got != tt.want {
				t.Errorf("canonicalizeAddr(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateAgents_WildcardVsSpecificCollision(t *testing.T) {
	tests := []struct {
		name          string
		fetchListen   string
		agentListener string
		wantErr       bool
	}{
		// Wildcard main + specific agent: conflict
		{"wildcard main loopback agent", "0.0.0.0:8888", "127.0.0.1:8888", true},
		{"wildcard main ipv6 loopback agent", "0.0.0.0:8888", "[::1]:8888", true},
		// Specific main + wildcard agent: conflict
		{"loopback main wildcard agent", "127.0.0.1:8888", "0.0.0.0:8888", true},
		// Different ports: no conflict
		{"wildcard main loopback agent different port", "0.0.0.0:8888", "127.0.0.1:9999", false},
		// Two specific addresses on same port: no conflict
		{"two specific same port", "127.0.0.1:8888", "127.0.0.2:8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.FetchProxy.Listen = tt.fetchListen
			cfg.Agents = map[string]config.AgentProfile{
				"agent-a": {Listeners: []string{tt.agentListener}},
			}
			err := ValidateAgents(cfg)
			if tt.wantErr && err == nil {
				t.Fatalf("expected collision between %s and %s", tt.fetchListen, tt.agentListener)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateAgents_WildcardVsSpecificBetweenAgents(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Listen = "127.0.0.1:7777" // avoid collision with agents
	cfg.Agents = map[string]config.AgentProfile{
		"agent-a": {Listeners: []string{"0.0.0.0:9001"}},
		"agent-b": {Listeners: []string{"127.0.0.1:9001"}},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected collision: 0.0.0.0:9001 vs 127.0.0.1:9001")
	}
}

func TestWildcardPortConflict(t *testing.T) {
	tests := []struct {
		name     string
		canon    string
		reserved map[string]string
		wantHit  bool
	}{
		{
			"wildcard vs specific same port",
			"0.0.0.0:8888",
			map[string]string{"127.0.0.1:8888": "main"},
			true,
		},
		{
			"specific vs wildcard same port",
			"127.0.0.1:8888",
			map[string]string{"0.0.0.0:8888": "main"},
			true,
		},
		{
			"different ports",
			"0.0.0.0:8888",
			map[string]string{"127.0.0.1:9999": "main"},
			false,
		},
		{
			"two wildcards same port (caught by exact match)",
			"0.0.0.0:8888",
			map[string]string{"0.0.0.0:8888": "main"},
			false, // both wildcard, not a wildcard-vs-specific
		},
		{
			"two specifics same port",
			"127.0.0.1:8888",
			map[string]string{"127.0.0.2:8888": "main"},
			false,
		},
		{
			"invalid canon",
			"not-valid",
			map[string]string{"0.0.0.0:8888": "main"},
			false,
		},
		{
			"empty reserved",
			"0.0.0.0:8888",
			map[string]string{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wildcardPortConflict(tt.canon, tt.reserved)
			if tt.wantHit && got == "" {
				t.Error("expected conflict, got none")
			}
			if !tt.wantHit && got != "" {
				t.Errorf("unexpected conflict: %s", got)
			}
		})
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

func TestValidateAgents_DLPMissingName(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			DLP: &config.AgentDLP{
				Patterns: []config.DLPPattern{{Name: "", Regex: "foo"}},
			},
		},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for DLP pattern with missing name")
	}
}

func TestValidateAgents_DLPMissingRegex(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			DLP: &config.AgentDLP{
				Patterns: []config.DLPPattern{{Name: "test", Regex: ""}},
			},
		},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for DLP pattern with missing regex")
	}
}

func TestValidateAgents_NegativeRateDataPerMinute(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			RateLimit: &config.AgentRateLimit{MaxDataPerMinute: -1},
		},
	}
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("expected error for negative max_data_per_minute")
	}
}

func TestValidateAgents_ValidDLPPatterns(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"agent": {
			DLP: &config.AgentDLP{
				Patterns: []config.DLPPattern{
					{Name: "custom-key", Regex: "sk-[a-z]+"},
				},
			},
		},
	}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatalf("expected valid DLP patterns: %v", err)
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

func TestValidateMergedAgent_InvalidAnomalyAction(t *testing.T) {
	cfg := testConfig()
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.AnomalyAction = "invalid"
	if err := ValidateMergedAgent("test", cfg); err == nil {
		t.Fatal("expected error for invalid anomaly_action")
	}
}

func TestValidateMergedAgent_ValidAnomalyAction(t *testing.T) {
	cfg := testConfig()
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.AnomalyAction = config.ActionWarn
	if err := ValidateMergedAgent("test", cfg); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestValidateMergedAgent_InvalidMCPToolPolicyAction(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = "invalid"
	if err := ValidateMergedAgent("test", cfg); err == nil {
		t.Fatal("expected error for invalid mcp_tool_policy.action")
	}
}

func TestValidateMergedAgent_ValidMCPToolPolicyAction(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionBlock
	if err := ValidateMergedAgent("test", cfg); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestMergeAgentProfile_EnforceOverride(t *testing.T) {
	cfg := testConfig()
	cfg.Enforce = nil
	enforceVal := true
	profile := &config.AgentProfile{Enforce: &enforceVal}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Enforce == nil || !*merged.Enforce {
		t.Error("expected enforce=true after merge")
	}
}

func TestMergeAgentProfile_APIAllowlistOverride(t *testing.T) {
	cfg := testConfig()
	cfg.APIAllowlist = []string{"base.example.com"}
	profile := &config.AgentProfile{APIAllowlist: []string{"agent.example.com"}}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.APIAllowlist) != 1 || merged.APIAllowlist[0] != "agent.example.com" {
		t.Errorf("expected agent allowlist, got %v", merged.APIAllowlist)
	}
}

func TestMergeAgentProfile_RateLimitOverride(t *testing.T) {
	cfg := testConfig()
	profile := &config.AgentProfile{
		RateLimit: &config.AgentRateLimit{
			MaxRequestsPerMinute: 42,
			MaxDataPerMinute:     1024,
		},
	}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if merged.FetchProxy.Monitoring.MaxReqPerMinute != 42 {
		t.Errorf("max_req_per_minute = %d, want 42", merged.FetchProxy.Monitoring.MaxReqPerMinute)
	}
	if merged.FetchProxy.Monitoring.MaxDataPerMinute != 1024 {
		t.Errorf("max_data_per_minute = %d, want 1024", merged.FetchProxy.Monitoring.MaxDataPerMinute)
	}
}

func TestMergeAgentProfile_SessionProfilingOverride(t *testing.T) {
	cfg := testConfig()
	profile := &config.AgentProfile{
		SessionProfiling: &config.AgentSessionProf{
			DomainBurst:      10,
			AnomalyAction:    config.ActionBlock,
			VolumeSpikeRatio: 5.0,
		},
	}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if merged.SessionProfiling.DomainBurst != 10 {
		t.Errorf("domain_burst = %d, want 10", merged.SessionProfiling.DomainBurst)
	}
	if merged.SessionProfiling.AnomalyAction != config.ActionBlock {
		t.Errorf("anomaly_action = %q, want block", merged.SessionProfiling.AnomalyAction)
	}
	if merged.SessionProfiling.VolumeSpikeRatio != 5.0 {
		t.Errorf("volume_spike_ratio = %f, want 5.0", merged.SessionProfiling.VolumeSpikeRatio)
	}
}

func TestMergeAgentProfile_MCPToolPolicyOverride(t *testing.T) {
	cfg := testConfig()
	profile := &config.AgentProfile{
		MCPToolPolicy: &config.MCPToolPolicy{
			Enabled: true,
			Action:  config.ActionBlock,
		},
	}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.MCPToolPolicy.Enabled {
		t.Error("expected mcp_tool_policy.enabled=true")
	}
	if merged.MCPToolPolicy.Action != config.ActionBlock {
		t.Errorf("action = %q, want block", merged.MCPToolPolicy.Action)
	}
}

func TestMergeAgentProfile_MCPToolPolicyRedirectProfiles(t *testing.T) {
	cfg := testConfig()
	profile := &config.AgentProfile{
		MCPToolPolicy: &config.MCPToolPolicy{
			Enabled: true,
			Action:  config.ActionRedirect,
			RedirectProfiles: map[string]config.RedirectProfile{
				"safe-fetch": {Exec: []string{"/usr/bin/safe-fetch"}, Reason: "audited"},
			},
			Rules: []config.ToolPolicyRule{
				{Name: "redirect-curl", ToolPattern: "bash", Action: config.ActionRedirect, RedirectProfile: "safe-fetch"},
			},
		},
	}
	merged, err := MergeAgentProfile(cfg, profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.MCPToolPolicy.RedirectProfiles) != 1 {
		t.Fatalf("redirect_profiles count = %d, want 1", len(merged.MCPToolPolicy.RedirectProfiles))
	}
	p, ok := merged.MCPToolPolicy.RedirectProfiles["safe-fetch"]
	if !ok {
		t.Fatal("expected safe-fetch profile")
	}
	if len(p.Exec) != 1 || p.Exec[0] != "/usr/bin/safe-fetch" {
		t.Errorf("exec = %v, want [/usr/bin/safe-fetch]", p.Exec)
	}
	if merged.MCPToolPolicy.Rules[0].RedirectProfile != "safe-fetch" {
		t.Errorf("rule redirect_profile = %q, want safe-fetch", merged.MCPToolPolicy.Rules[0].RedirectProfile)
	}
}

func TestValidateMergedAgent_RedirectActionValid(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionRedirect
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"safe-fetch": {Exec: []string{"/usr/bin/safe-fetch"}, Reason: "audited"},
	}
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "test", ToolPattern: "bash", RedirectProfile: "safe-fetch"},
	}
	if err := ValidateMergedAgent("test-agent", cfg); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func TestValidateMergedAgent_RedirectMissingProfile(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionRedirect
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"safe-fetch": {Exec: []string{"/usr/bin/safe-fetch"}, Reason: "audited"},
	}
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "test", ToolPattern: "bash"}, // inherits redirect but no redirect_profile
	}
	if err := ValidateMergedAgent("test-agent", cfg); err == nil {
		t.Error("expected error for redirect rule without redirect_profile")
	}
}

func TestValidateMergedAgent_RedirectUnknownProfile(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionWarn
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"safe-fetch": {Exec: []string{"/usr/bin/safe-fetch"}, Reason: "audited"},
	}
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "test", ToolPattern: "bash", Action: config.ActionRedirect, RedirectProfile: "nonexistent"},
	}
	if err := ValidateMergedAgent("test-agent", cfg); err == nil {
		t.Error("expected error for redirect rule referencing unknown profile")
	}
}

func TestValidateMergedAgent_RedirectEmptyExec(t *testing.T) {
	cfg := testConfig()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionWarn
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"bad": {Exec: []string{""}, Reason: "empty string exec"},
	}
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "test", ToolPattern: "bash"},
	}
	if err := ValidateMergedAgent("test-agent", cfg); err == nil {
		t.Error("expected error for redirect_profile with empty exec in merged agent")
	}
}

func TestResolvePublicKey_InvalidHex(t *testing.T) {
	cfg := testConfig()
	cfg.LicensePublicKey = "not-valid-hex"
	key := resolvePublicKey(cfg)
	if key != nil {
		t.Error("expected nil for invalid hex")
	}
}

func TestResolvePublicKey_WrongLength(t *testing.T) {
	cfg := testConfig()
	cfg.LicensePublicKey = hex.EncodeToString([]byte("too-short"))
	key := resolvePublicKey(cfg)
	if key != nil {
		t.Error("expected nil for wrong key length")
	}
}

func TestResolvePublicKey_Empty(t *testing.T) {
	cfg := testConfig()
	cfg.LicensePublicKey = ""
	key := resolvePublicKey(cfg)
	if key != nil {
		t.Error("expected nil when no key configured")
	}
}

func TestEnforceLicenseGate_NoPublicKey(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	cfg.LicenseKey = "some-token"
	cfg.LicensePublicKey = ""
	EnforceLicenseGate(cfg)
	if cfg.Agents != nil {
		t.Error("expected agents disabled when no public key")
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
