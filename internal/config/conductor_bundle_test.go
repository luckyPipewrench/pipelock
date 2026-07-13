// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestPreserveConductorBundleLocalRuntimeStateNilInputs(t *testing.T) {
	t.Parallel()

	if err := PreserveConductorBundleLocalRuntimeState(nil, &Config{}, ""); err != nil {
		t.Fatalf("nil new config error = %v", err)
	}
	if err := PreserveConductorBundleLocalRuntimeState(&Config{}, nil, ""); err != nil {
		t.Fatalf("nil old config error = %v", err)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateCopiesFollowerLocalFields(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{
		FetchProxy:           FetchProxy{Listen: "127.0.0.1:18080", TimeoutSeconds: 12},
		MetricsListen:        "127.0.0.1:19090",
		Internal:             []string{"10.0.0.0/8"},
		TrustedDomains:       []string{"trusted.example"},
		Suppress:             []SuppressEntry{{Rule: "body_dlp", Path: "api.example/*", Reason: "fixture"}},
		Agents:               map[string]AgentProfile{"builder": {Sandbox: &AgentSandboxOverride{Enabled: boolPtr(true)}}},
		LicenseKey:           "license-token",
		LicenseFile:          "/run/pipelock/license",
		DefaultAgentIdentity: "builder",
	}
	newCfg := &Config{
		FetchProxy:           FetchProxy{Listen: "127.0.0.1:28080"},
		MetricsListen:        "127.0.0.1:29090",
		Internal:             []string{"192.168.0.0/16"},
		TrustedDomains:       []string{"other.example"},
		Suppress:             []SuppressEntry{{Rule: "old", Path: "old.example/*"}},
		Agents:               map[string]AgentProfile{"other": {}},
		LicenseKey:           "new-license-token",
		LicenseFile:          "/tmp/new-license",
		DefaultAgentIdentity: "other",
		Conductor:            Conductor{Enabled: true, FleetID: "fleet-from-bundle"},
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, "mode: strict\n"); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}

	if newCfg.FetchProxy.Listen != oldCfg.FetchProxy.Listen {
		t.Fatalf("FetchProxy.Listen = %q, want %q", newCfg.FetchProxy.Listen, oldCfg.FetchProxy.Listen)
	}
	if newCfg.MetricsListen != oldCfg.MetricsListen {
		t.Fatalf("MetricsListen = %q, want %q", newCfg.MetricsListen, oldCfg.MetricsListen)
	}
	if !reflect.DeepEqual(newCfg.Internal, oldCfg.Internal) {
		t.Fatalf("Internal = %#v, want %#v", newCfg.Internal, oldCfg.Internal)
	}
	if !reflect.DeepEqual(newCfg.TrustedDomains, oldCfg.TrustedDomains) {
		t.Fatalf("TrustedDomains = %#v, want %#v", newCfg.TrustedDomains, oldCfg.TrustedDomains)
	}
	if !reflect.DeepEqual(newCfg.Suppress, oldCfg.Suppress) {
		t.Fatalf("Suppress = %#v, want %#v", newCfg.Suppress, oldCfg.Suppress)
	}
	if newCfg.LicenseKey != oldCfg.LicenseKey || newCfg.LicenseFile != oldCfg.LicenseFile {
		t.Fatalf("license fields = (%q, %q), want (%q, %q)", newCfg.LicenseKey, newCfg.LicenseFile, oldCfg.LicenseKey, oldCfg.LicenseFile)
	}
	if newCfg.DefaultAgentIdentity != oldCfg.DefaultAgentIdentity {
		t.Fatalf("DefaultAgentIdentity = %q, want %q", newCfg.DefaultAgentIdentity, oldCfg.DefaultAgentIdentity)
	}
	if !reflect.DeepEqual(newCfg.Agents, oldCfg.Agents) {
		t.Fatalf("Agents = %#v, want %#v", newCfg.Agents, oldCfg.Agents)
	}
	if !newCfg.Conductor.Enabled || newCfg.Conductor.FleetID != "fleet-from-bundle" {
		t.Fatalf("Conductor should remain bundle-owned, got %#v", newCfg.Conductor)
	}

	oldCfg.Internal[0] = "172.16.0.0/12"
	oldCfg.TrustedDomains[0] = "mutated.example"
	oldCfg.Suppress[0].Path = "mutated.example/*"
	oldCfg.Agents["builder"] = AgentProfile{Sandbox: &AgentSandboxOverride{Enabled: boolPtr(false)}}
	if newCfg.Internal[0] == oldCfg.Internal[0] {
		t.Fatal("Internal slice aliases old config")
	}
	if newCfg.TrustedDomains[0] == oldCfg.TrustedDomains[0] {
		t.Fatal("TrustedDomains slice aliases old config")
	}
	if newCfg.Suppress[0].Path == oldCfg.Suppress[0].Path {
		t.Fatal("Suppress slice aliases old config")
	}
	if reflect.DeepEqual(newCfg.Agents["builder"], oldCfg.Agents["builder"]) {
		t.Fatal("Agents map aliases old config")
	}
}

func TestPreserveConductorBundleLocalRuntimeStateAdditiveDLPPatterns(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{DLP: DLP{
		ScanEnv:         true,
		IncludeDefaults: boolPtr(true),
		Patterns: []DLPPattern{{
			Name:     "local-secret",
			Regex:    `LOCAL_SECRET_[A-Z]+`,
			Severity: SeverityHigh,
		}},
	}}
	newCfg := &Config{DLP: DLP{
		ScanEnv:         false,
		IncludeDefaults: boolPtr(false),
		Patterns: []DLPPattern{{
			Name:     "bundle-secret",
			Regex:    `BUNDLE_SECRET_[A-Z]+`,
			Severity: SeverityCritical,
		}},
	}}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, strings.Join([]string{
		"dlp:",
		"  patterns:",
		"    - name: bundle-secret",
		"      regex: BUNDLE_SECRET_[A-Z]+",
		"      severity: critical",
		"",
	}, "\n")); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}

	if !newCfg.DLP.ScanEnv {
		t.Fatal("bundle dlp.scan_env disabled local baseline")
	}
	if newCfg.DLP.IncludeDefaults == nil || !*newCfg.DLP.IncludeDefaults {
		t.Fatalf("DLP.IncludeDefaults = %v, want local true", newCfg.DLP.IncludeDefaults)
	}
	if names := dlpPatternNames(newCfg.DLP.Patterns); !reflect.DeepEqual(names, []string{"local-secret", "bundle-secret"}) {
		t.Fatalf("DLP pattern names = %v", names)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateDLPDuplicateDefaultDedupes(t *testing.T) {
	t.Parallel()

	defaultPattern := Defaults().DLP.Patterns[0]
	oldCfg := &Config{DLP: DLP{Patterns: []DLPPattern{defaultPattern}}}
	newCfg := &Config{DLP: DLP{Patterns: []DLPPattern{defaultPattern}}}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, "dlp:\n  patterns: []\n"); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if len(newCfg.DLP.Patterns) != 1 {
		t.Fatalf("DLP pattern count = %d, want 1", len(newCfg.DLP.Patterns))
	}
	if newCfg.DLP.Patterns[0].Name != defaultPattern.Name {
		t.Fatalf("DLP pattern[0] = %q, want %q", newCfg.DLP.Patterns[0].Name, defaultPattern.Name)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateDLPConflictRejected(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{DLP: DLP{Patterns: []DLPPattern{{
		Name:     "local-secret",
		Regex:    `LOCAL_SECRET_[A-Z]+`,
		Severity: SeverityHigh,
	}}}}
	newCfg := &Config{DLP: DLP{Patterns: []DLPPattern{{
		Name:     "local-secret",
		Regex:    `BUNDLE_SECRET_[A-Z]+`,
		Severity: SeverityHigh,
	}}}}

	err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, strings.Join([]string{
		"dlp:",
		"  patterns:",
		"    - name: local-secret",
		"      regex: BUNDLE_SECRET_[A-Z]+",
		"      severity: high",
		"",
	}, "\n"))
	if err == nil || !strings.Contains(err.Error(), `cannot redefine local dlp.patterns item "local-secret"`) {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v, want dlp conflict", err)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateDLPUsesNormalizedRawDomains(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{DLP: DLP{Patterns: []DLPPattern{{
		Name:          "local-secret",
		Regex:         `LOCAL_SECRET_[A-Z]+`,
		Severity:      SeverityHigh,
		ExemptDomains: []string{"api.vendor.example"},
	}}}}
	rawBundleYAML := strings.Join([]string{
		"dlp:",
		"  include_defaults: false",
		"  patterns:",
		"    - name: local-secret",
		"      regex: LOCAL_SECRET_[A-Z]+",
		"      severity: high",
		"      exempt_domains:",
		"        - ' API.VENDOR.EXAMPLE. '",
		"",
	}, "\n")
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if got := dlpPatternNames(newCfg.DLP.Patterns); !reflect.DeepEqual(got, []string{"local-secret"}) {
		t.Fatalf("DLP pattern names = %v", got)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateDLPIncludeDefaultsFalseKeepsLocalDefaults(t *testing.T) {
	t.Parallel()

	localDefaults := Defaults().DLP.Patterns
	oldCfg := &Config{DLP: DLP{IncludeDefaults: boolPtr(true), Patterns: localDefaults}}
	newCfg := &Config{DLP: DLP{
		IncludeDefaults: boolPtr(false),
		Patterns: []DLPPattern{{
			Name:     "bundle-only-secret",
			Regex:    `BUNDLE_ONLY_[A-Z]+`,
			Severity: SeverityHigh,
		}},
	}}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, strings.Join([]string{
		"dlp:",
		"  include_defaults: false",
		"  patterns:",
		"    - name: bundle-only-secret",
		"      regex: BUNDLE_ONLY_[A-Z]+",
		"      severity: high",
		"",
	}, "\n")); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if len(newCfg.DLP.Patterns) != len(localDefaults)+1 {
		t.Fatalf("DLP pattern count = %d, want local defaults plus bundle item %d", len(newCfg.DLP.Patterns), len(localDefaults)+1)
	}
	if !hasDLPPattern(newCfg.DLP.Patterns, localDefaults[0].Name) {
		t.Fatalf("local default pattern %q missing after include_defaults:false bundle", localDefaults[0].Name)
	}
	if !hasDLPPattern(newCfg.DLP.Patterns, "bundle-only-secret") {
		t.Fatal("bundle-added pattern missing")
	}
}

func TestPreserveConductorBundleLocalRuntimeStateEmptyBundleSectionNoop(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{DLP: DLP{Patterns: []DLPPattern{{Name: "local-secret", Regex: `LOCAL_[A-Z]+`, Severity: SeverityHigh}}}}
	newCfg := &Config{}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, "dlp: {}\n"); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if !reflect.DeepEqual(newCfg.DLP, oldCfg.DLP) {
		t.Fatalf("DLP = %+v, want local %+v", newCfg.DLP, oldCfg.DLP)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateEmptyDLPSectionDoesNotImportLoadedDefaults(t *testing.T) {
	t.Parallel()

	defaultPattern := Defaults().DLP.Patterns[0]
	oldCfg := &Config{DLP: DLP{Patterns: []DLPPattern{{
		Name:     defaultPattern.Name,
		Regex:    `LOCAL_OVERRIDE_[A-Z]+`,
		Severity: SeverityHigh,
	}}}}
	rawBundleYAML := "dlp:\n  patterns: []\n"
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if !reflect.DeepEqual(newCfg.DLP, oldCfg.DLP) {
		t.Fatalf("DLP = %+v, want local-only %+v", newCfg.DLP, oldCfg.DLP)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateEmptyResponseSectionDoesNotImportLoadedDefaults(t *testing.T) {
	t.Parallel()

	defaultPattern := Defaults().ResponseScanning.Patterns[0]
	oldCfg := &Config{ResponseScanning: ResponseScanning{
		Enabled: true,
		Action:  ActionBlock,
		Patterns: []ResponseScanPattern{{
			Name:  defaultPattern.Name,
			Regex: `LOCAL_RESPONSE_OVERRIDE`,
		}},
	}}
	rawBundleYAML := "response_scanning:\n  enabled: true\n"
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if !reflect.DeepEqual(newCfg.ResponseScanning, oldCfg.ResponseScanning) {
		t.Fatalf("ResponseScanning = %+v, want local-only %+v", newCfg.ResponseScanning, oldCfg.ResponseScanning)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateOmittedSectionDoesNotImportResolvedDefaults(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{DLP: DLP{Patterns: []DLPPattern{{Name: "local-secret", Regex: `LOCAL_[A-Z]+`, Severity: SeverityHigh}}}}
	newCfg := &Config{DLP: Defaults().DLP}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, "mode: strict\n"); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if !reflect.DeepEqual(newCfg.DLP, oldCfg.DLP) {
		t.Fatalf("DLP = %+v, want local-only %+v", newCfg.DLP, oldCfg.DLP)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateAdditiveCanaryTokens(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{CanaryTokens: CanaryTokens{
		Enabled: false,
		Tokens:  []CanaryToken{{Name: "local", Value: "local-canary-token"}},
	}}
	newCfg := &Config{CanaryTokens: CanaryTokens{
		Enabled: true,
		Tokens:  []CanaryToken{{Name: "bundle", Value: "bundle-canary-token"}},
	}}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, strings.Join([]string{
		"canary_tokens:",
		"  enabled: true",
		"  tokens:",
		"    - name: bundle",
		"      value: bundle-canary-token",
		"",
	}, "\n")); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if !newCfg.CanaryTokens.Enabled {
		t.Fatal("bundle canary_tokens.enabled=true should enable additive canary coverage")
	}
	if got := canaryTokenNames(newCfg.CanaryTokens.Tokens); !reflect.DeepEqual(got, []string{"local", "bundle"}) {
		t.Fatalf("canary token names = %v", got)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateCanariesUseNormalizedRawItems(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{CanaryTokens: CanaryTokens{
		Enabled: true,
		Tokens: []CanaryToken{{
			Name:   "local",
			Value:  "local-canary-token",
			EnvVar: "LOCAL_CANARY",
		}},
	}}
	rawBundleYAML := strings.Join([]string{
		"canary_tokens:",
		"  enabled: true",
		"  tokens:",
		"    - name: ' local '",
		"      value: ' local-canary-token '",
		"      env_var: ' LOCAL_CANARY '",
		"",
	}, "\n")
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if got := canaryTokenNames(newCfg.CanaryTokens.Tokens); !reflect.DeepEqual(got, []string{"local"}) {
		t.Fatalf("canary token names = %v", got)
	}
	if !reflect.DeepEqual(newCfg.CanaryTokens.Tokens, oldCfg.CanaryTokens.Tokens) {
		t.Fatalf("canary tokens = %+v, want normalized local-only %+v", newCfg.CanaryTokens.Tokens, oldCfg.CanaryTokens.Tokens)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateResponseAndToolRulesAdditive(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{
		ResponseScanning: ResponseScanning{
			Enabled: true,
			Action:  ActionBlock,
			Patterns: []ResponseScanPattern{{
				Name:  "local-response",
				Regex: `LOCAL_RESPONSE`,
			}},
		},
		MCPToolPolicy: MCPToolPolicy{
			Enabled: true,
			Action:  ActionBlock,
			Rules: []ToolPolicyRule{{
				Name:        "local-tool",
				ToolPattern: `^local_`,
				Action:      ActionBlock,
			}},
		},
	}
	newCfg := &Config{
		ResponseScanning: ResponseScanning{
			Enabled: false,
			Action:  ActionWarn,
			Patterns: []ResponseScanPattern{{
				Name:  "bundle-response",
				Regex: `BUNDLE_RESPONSE`,
			}},
		},
		MCPToolPolicy: MCPToolPolicy{
			Enabled: false,
			Action:  ActionWarn,
			Rules: []ToolPolicyRule{{
				Name:        "bundle-tool",
				ToolPattern: `^bundle_`,
				Action:      ActionWarn,
			}},
		},
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, strings.Join([]string{
		"response_scanning:",
		"  patterns:",
		"    - name: bundle-response",
		"      regex: BUNDLE_RESPONSE",
		"mcp_tool_policy:",
		"  rules:",
		"    - name: bundle-tool",
		"      tool_pattern: ^bundle_",
		"      action: warn",
		"",
	}, "\n")); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if !newCfg.ResponseScanning.Enabled || newCfg.ResponseScanning.Action != ActionBlock {
		t.Fatalf("response scalar fields = enabled %v action %q, want local true/block", newCfg.ResponseScanning.Enabled, newCfg.ResponseScanning.Action)
	}
	if got := responsePatternNames(newCfg.ResponseScanning.Patterns); !reflect.DeepEqual(got, []string{"local-response", "bundle-response"}) {
		t.Fatalf("response pattern names = %v", got)
	}
	if !newCfg.MCPToolPolicy.Enabled || newCfg.MCPToolPolicy.Action != ActionBlock {
		t.Fatalf("tool policy scalar fields = enabled %v action %q, want local true/block", newCfg.MCPToolPolicy.Enabled, newCfg.MCPToolPolicy.Action)
	}
	if got := toolPolicyRuleNames(newCfg.MCPToolPolicy.Rules); !reflect.DeepEqual(got, []string{"local-tool", "bundle-tool"}) {
		t.Fatalf("tool policy rule names = %v", got)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateDetectionConflictsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oldCfg  *Config
		yaml    string
		wantErr string
	}{
		{
			name: "canary token",
			oldCfg: &Config{CanaryTokens: CanaryTokens{Tokens: []CanaryToken{{
				Name:  "shared-canary",
				Value: "local-token",
			}}}},
			yaml: strings.Join([]string{
				"canary_tokens:",
				"  tokens:",
				"    - name: shared-canary",
				"      value: bundle-token",
				"",
			}, "\n"),
			wantErr: `conductor policy bundle cannot redefine local canary_tokens.tokens item "shared-canary"`,
		},
		{
			name: "response pattern",
			oldCfg: &Config{ResponseScanning: ResponseScanning{Patterns: []ResponseScanPattern{{
				Name:  "shared-response",
				Regex: "LOCAL_RESPONSE",
			}}}},
			yaml: strings.Join([]string{
				"response_scanning:",
				"  patterns:",
				"    - name: shared-response",
				"      regex: BUNDLE_RESPONSE",
				"",
			}, "\n"),
			wantErr: `conductor policy bundle cannot redefine local response_scanning.patterns item "shared-response"`,
		},
		{
			name: "tool policy rule",
			oldCfg: &Config{MCPToolPolicy: MCPToolPolicy{Rules: []ToolPolicyRule{{
				Name:        "shared-tool",
				ToolPattern: "^local_",
				Action:      ActionBlock,
			}}}},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  rules:",
				"    - name: shared-tool",
				"      tool_pattern: ^bundle_",
				"      action: warn",
				"",
			}, "\n"),
			wantErr: `conductor policy bundle cannot redefine local mcp_tool_policy.rules item "shared-tool"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			newCfg, err := LoadBytes([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("LoadBytes() error = %v", err)
			}

			err = PreserveConductorBundleLocalRuntimeState(newCfg, tt.oldCfg, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestPreserveConductorBundleLocalRuntimeStateRejectsDormantInvalidResponsePattern(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{ResponseScanning: ResponseScanning{
		Enabled: true,
		Action:  ActionBlock,
		Patterns: []ResponseScanPattern{{
			Name:  "local-response",
			Regex: `LOCAL_RESPONSE`,
		}},
	}}
	rawBundleYAML := strings.Join([]string{
		"response_scanning:",
		"  enabled: false",
		"  patterns:",
		"    - name: dormant-invalid",
		"      regex: '['",
		"",
	}, "\n")
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	err = PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML)
	if err == nil || !strings.Contains(err.Error(), `response scanning pattern "dormant-invalid" has invalid regex`) {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v, want dormant response regex rejection", err)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateRejectsDormantInvalidToolPolicyRule(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{MCPToolPolicy: MCPToolPolicy{
		Enabled: false,
		Action:  ActionBlock,
		Rules: []ToolPolicyRule{{
			Name:        "local-tool",
			ToolPattern: `^local_`,
			Action:      ActionBlock,
		}},
	}}
	rawBundleYAML := strings.Join([]string{
		"mcp_tool_policy:",
		"  enabled: false",
		"  rules:",
		"    - name: dormant-invalid",
		"      tool_pattern: '['",
		"      action: block",
		"",
	}, "\n")
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	err = PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML)
	if err == nil || !strings.Contains(err.Error(), `mcp_tool_policy rule "dormant-invalid" has invalid tool_pattern`) {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v, want dormant tool policy regex rejection", err)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateRejectsDormantInvalidToolPolicyRedirect(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{MCPToolPolicy: MCPToolPolicy{
		Enabled: true,
		Action:  ActionBlock,
		Rules: []ToolPolicyRule{{
			Name:        "local-tool",
			ToolPattern: `^local_`,
			Action:      ActionBlock,
		}},
	}}
	rawBundleYAML := strings.Join([]string{
		"mcp_tool_policy:",
		"  enabled: false",
		"  rules:",
		"    - name: dormant-redirect",
		"      tool_pattern: ^bundle_",
		"      action: redirect",
		"",
	}, "\n")
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	err = PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML)
	if err == nil || !strings.Contains(err.Error(), `mcp_tool_policy rule "dormant-redirect" has action=redirect but no redirect_profile`) {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v, want dormant redirect rejection", err)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateRejectsDormantToolPolicyActionRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oldCfg  *Config
		yaml    string
		wantErr string
	}{
		{
			name: "unknown redirect profile",
			oldCfg: &Config{MCPToolPolicy: MCPToolPolicy{
				Enabled: false,
				Action:  ActionBlock,
				Rules: []ToolPolicyRule{{
					Name:        "local-tool",
					ToolPattern: `^local_`,
					Action:      ActionBlock,
				}},
			}},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-redirect",
				"      tool_pattern: ^bundle_",
				"      action: redirect",
				"      redirect_profile: missing",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-redirect" references unknown redirect_profile "missing"`,
		},
		{
			name: "inherited redirect action requires profile",
			oldCfg: &Config{MCPToolPolicy: MCPToolPolicy{
				Enabled: false,
				Action:  ActionRedirect,
				RedirectProfiles: map[string]RedirectProfile{
					"safe-fetch": {Exec: []string{"/usr/bin/safe-fetch"}},
				},
				Rules: []ToolPolicyRule{{
					Name:            "local-tool",
					ToolPattern:     `^local_`,
					RedirectProfile: "safe-fetch",
				}},
			}},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-inherited-redirect",
				"      tool_pattern: ^bundle_",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-inherited-redirect" has action=redirect but no redirect_profile`,
		},
		{
			name: "redirect profile empty exec",
			oldCfg: &Config{MCPToolPolicy: MCPToolPolicy{
				Enabled: false,
				Action:  ActionBlock,
				RedirectProfiles: map[string]RedirectProfile{
					"bad-fetch": {Exec: nil},
				},
				Rules: []ToolPolicyRule{{
					Name:        "local-tool",
					ToolPattern: `^local_`,
					Action:      ActionBlock,
				}},
			}},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-redirect",
				"      tool_pattern: ^bundle_",
				"      action: redirect",
				"      redirect_profile: bad-fetch",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy redirect_profile "bad-fetch" has empty exec`,
		},
		{
			name: "redirect profile relative exec with absolute matching",
			oldCfg: &Config{MCPToolPolicy: MCPToolPolicy{
				Enabled: false,
				Action:  ActionBlock,
				RedirectProfiles: map[string]RedirectProfile{
					"bad-fetch": {Exec: []string{"relative-fetch"}, MatchAbsPath: true},
				},
				Rules: []ToolPolicyRule{{
					Name:        "local-tool",
					ToolPattern: `^local_`,
					Action:      ActionBlock,
				}},
			}},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-redirect",
				"      tool_pattern: ^bundle_",
				"      action: redirect",
				"      redirect_profile: bad-fetch",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy redirect_profile "bad-fetch": match_abs_path is true but exec[0] "relative-fetch" is not absolute`,
		},
		{
			name: "inherited invalid action",
			oldCfg: &Config{MCPToolPolicy: MCPToolPolicy{
				Enabled: false,
				Action:  ActionStrip,
				Rules: []ToolPolicyRule{{
					Name:        "local-tool",
					ToolPattern: `^local_`,
					Action:      ActionBlock,
				}},
			}},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-inherited-invalid",
				"      tool_pattern: ^bundle_",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-inherited-invalid" inherits invalid action "strip": must be warn, block, redirect, or defer`,
		},
		{
			name: "defer while defer disabled",
			oldCfg: &Config{
				Defer: DeferConfig{Enabled: false},
				MCPToolPolicy: MCPToolPolicy{
					Enabled: false,
					Action:  ActionBlock,
					Rules: []ToolPolicyRule{{
						Name:        "local-tool",
						ToolPattern: `^local_`,
						Action:      ActionBlock,
					}},
				},
			},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-defer",
				"      tool_pattern: ^bundle_",
				"      action: defer",
				"      resolution_policy:",
				"        allow_on:",
				"          tool_inventory_baseline: true",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-defer" has action=defer but defer.enabled is false`,
		},
		{
			name: "defer missing affirmative resolution",
			oldCfg: &Config{
				Defer: DeferConfig{Enabled: true},
				MCPToolPolicy: MCPToolPolicy{
					Enabled: false,
					Action:  ActionBlock,
					Rules: []ToolPolicyRule{{
						Name:        "local-tool",
						ToolPattern: `^local_`,
						Action:      ActionBlock,
					}},
				},
			},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-defer",
				"      tool_pattern: ^bundle_",
				"      action: defer",
				"      resolution_policy:",
				"        resolver_profile: approve",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-defer" has action=defer but no affirmative resolution_policy`,
		},
		{
			name: "defer missing resolution policy",
			oldCfg: &Config{
				Defer: DeferConfig{Enabled: true},
				MCPToolPolicy: MCPToolPolicy{
					Enabled: false,
					Action:  ActionBlock,
					Rules: []ToolPolicyRule{{
						Name:        "local-tool",
						ToolPattern: `^local_`,
						Action:      ActionBlock,
					}},
				},
			},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-defer",
				"      tool_pattern: ^bundle_",
				"      action: defer",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-defer" has action=defer but no affirmative resolution_policy`,
		},
		{
			name: "defer policy permits unsupported",
			oldCfg: &Config{
				Defer: DeferConfig{Enabled: true},
				MCPToolPolicy: MCPToolPolicy{
					Enabled: false,
					Action:  ActionBlock,
					Rules: []ToolPolicyRule{{
						Name:        "local-tool",
						ToolPattern: `^local_`,
						Action:      ActionBlock,
					}},
				},
			},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-defer",
				"      tool_pattern: ^bundle_",
				"      action: defer",
				"      resolution_policy:",
				"        allow_on:",
				"          policy_permits: true",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-defer" has resolution_policy.allow_on.policy_permits but policy_reload cannot fire on supported defer transports yet`,
		},
		{
			name: "defer approval missing resolver profile",
			oldCfg: &Config{
				Defer: DeferConfig{Enabled: true},
				MCPToolPolicy: MCPToolPolicy{
					Enabled: false,
					Action:  ActionBlock,
					Rules: []ToolPolicyRule{{
						Name:        "local-tool",
						ToolPattern: `^local_`,
						Action:      ActionBlock,
					}},
				},
			},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-defer-approval",
				"      tool_pattern: ^bundle_",
				"      action: defer",
				"      resolution_policy:",
				"        allow_on:",
				"          approval: true",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-defer-approval" uses approval resolution but has no resolution_policy.resolver_profile`,
		},
		{
			name: "defer approval unknown resolver profile",
			oldCfg: &Config{
				Defer: DeferConfig{Enabled: true},
				MCPToolPolicy: MCPToolPolicy{
					Enabled: false,
					Action:  ActionBlock,
					Rules: []ToolPolicyRule{{
						Name:        "local-tool",
						ToolPattern: `^local_`,
						Action:      ActionBlock,
					}},
				},
			},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-defer-approval",
				"      tool_pattern: ^bundle_",
				"      action: defer",
				"      resolution_policy:",
				"        resolver_profile: missing",
				"        allow_on:",
				"          approval: true",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy rule "dormant-defer-approval" references unknown defer resolver profile "missing"`,
		},
		{
			name: "defer resolver profile empty exec",
			oldCfg: &Config{
				Defer: DeferConfig{Enabled: true},
				MCPToolPolicy: MCPToolPolicy{
					Enabled: false,
					Action:  ActionBlock,
					DeferResolverProfiles: map[string]DeferResolverProfile{
						"approve": {Exec: []string{""}},
					},
					Rules: []ToolPolicyRule{{
						Name:        "local-tool",
						ToolPattern: `^local_`,
						Action:      ActionBlock,
					}},
				},
			},
			yaml: strings.Join([]string{
				"mcp_tool_policy:",
				"  enabled: false",
				"  rules:",
				"    - name: dormant-defer-approval",
				"      tool_pattern: ^bundle_",
				"      action: defer",
				"      resolution_policy:",
				"        resolver_profile: approve",
				"        allow_on:",
				"          approval: true",
				"",
			}, "\n"),
			wantErr: `mcp_tool_policy defer_resolver_profile "approve" has empty exec`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			newCfg, err := LoadBytes([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("LoadBytes() error = %v", err)
			}

			err = PreserveConductorBundleLocalRuntimeState(newCfg, tt.oldCfg, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestPreserveConductorBundleLocalRuntimeStateAcceptsDormantValidToolPolicyActions(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{
		Defer: DeferConfig{Enabled: true},
		MCPToolPolicy: MCPToolPolicy{
			Enabled: false,
			Action:  ActionBlock,
			RedirectProfiles: map[string]RedirectProfile{
				"safe-fetch": {Exec: []string{"/usr/bin/safe-fetch"}, MatchAbsPath: true},
			},
			DeferResolverProfiles: map[string]DeferResolverProfile{
				"approve": {Exec: []string{"/usr/bin/approve-tool"}, MatchAbsPath: true},
			},
			Rules: []ToolPolicyRule{{
				Name:        "local-tool",
				ToolPattern: `^local_`,
				Action:      ActionBlock,
			}},
		},
	}
	rawBundleYAML := strings.Join([]string{
		"mcp_tool_policy:",
		"  enabled: false",
		"  rules:",
		"    - name: dormant-redirect",
		"      tool_pattern: ^fetch_",
		"      action: redirect",
		"      redirect_profile: safe-fetch",
		"    - name: dormant-defer",
		"      tool_pattern: ^write_",
		"      action: defer",
		"      resolution_policy:",
		"        resolver_profile: approve",
		"        allow_on:",
		"          approval: true",
		"    - name: dormant-baseline-defer",
		"      tool_pattern: ^baseline_",
		"      action: defer",
		"      resolution_policy:",
		"        allow_on:",
		"          tool_inventory_baseline: true",
		"",
	}, "\n")
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}
	if newCfg.MCPToolPolicy.Enabled {
		t.Fatal("bundle action validation should not enable local dormant tool policy")
	}
	if got := toolPolicyRuleNames(newCfg.MCPToolPolicy.Rules); !reflect.DeepEqual(got, []string{"local-tool", "dormant-redirect", "dormant-defer", "dormant-baseline-defer"}) {
		t.Fatalf("tool policy rule names = %v", got)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateRejectsTrailingEmptyYAMLDocument(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{}
	newCfg := &Config{}

	err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, "mode: strict\n---\n")
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v, want multi-document rejection", err)
	}
}

func TestPreserveConductorBundleLocalRuntimeStateTopLevelMergeKeySections(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{
		DLP: DLP{Patterns: []DLPPattern{{
			Name:     "local-secret",
			Regex:    `LOCAL_SECRET_[A-Z]+`,
			Severity: SeverityHigh,
		}}},
		CanaryTokens: CanaryTokens{Tokens: []CanaryToken{{
			Name:  "local-canary",
			Value: "local-canary-token",
		}}},
		ResponseScanning: ResponseScanning{
			Enabled: true,
			Action:  ActionBlock,
			Patterns: []ResponseScanPattern{{
				Name:  "local-response",
				Regex: `LOCAL_RESPONSE`,
			}},
		},
		MCPToolPolicy: MCPToolPolicy{
			Enabled: true,
			Action:  ActionBlock,
			Rules: []ToolPolicyRule{{
				Name:        "local-tool",
				ToolPattern: `^local_`,
				Action:      ActionBlock,
			}},
		},
	}
	rawBundleYAML := strings.Join([]string{
		"<<:",
		"  - &bundle_sections",
		"    dlp:",
		"      include_defaults: false",
		"      patterns:",
		"        - name: bundle-secret",
		"          regex: BUNDLE_SECRET_[A-Z]+",
		"          severity: high",
		"    canary_tokens:",
		"      enabled: true",
		"      tokens:",
		"        - name: bundle-canary",
		"          value: bundle-canary-token",
		"    response_scanning:",
		"      enabled: true",
		"      include_defaults: false",
		"      patterns:",
		"        - name: bundle-response",
		"          regex: BUNDLE_RESPONSE",
		"    mcp_tool_policy:",
		"      enabled: true",
		"      action: warn",
		"      rules:",
		"        - name: bundle-tool",
		"          tool_pattern: ^bundle_",
		"          action: warn",
		"  - *bundle_sections",
		"mode: strict",
		"api_allowlist:",
		"  - api.vendor.example",
		"",
	}, "\n")
	newCfg, err := LoadBytes([]byte(rawBundleYAML))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if err := PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg, rawBundleYAML); err != nil {
		t.Fatalf("PreserveConductorBundleLocalRuntimeState() error = %v", err)
	}

	if got := dlpPatternNames(newCfg.DLP.Patterns); !reflect.DeepEqual(got, []string{"local-secret", "bundle-secret"}) {
		t.Fatalf("DLP pattern names = %v", got)
	}
	if !newCfg.CanaryTokens.Enabled {
		t.Fatal("merged top-level canary_tokens.enabled=true did not enable canary coverage")
	}
	if got := canaryTokenNames(newCfg.CanaryTokens.Tokens); !reflect.DeepEqual(got, []string{"local-canary", "bundle-canary"}) {
		t.Fatalf("canary token names = %v", got)
	}
	if got := responsePatternNames(newCfg.ResponseScanning.Patterns); !reflect.DeepEqual(got, []string{"local-response", "bundle-response"}) {
		t.Fatalf("response pattern names = %v", got)
	}
	if got := toolPolicyRuleNames(newCfg.MCPToolPolicy.Rules); !reflect.DeepEqual(got, []string{"local-tool", "bundle-tool"}) {
		t.Fatalf("tool policy rule names = %v", got)
	}
}

func dlpPatternNames(patterns []DLPPattern) []string {
	names := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		names = append(names, pattern.Name)
	}
	return names
}

func hasDLPPattern(patterns []DLPPattern, name string) bool {
	for _, pattern := range patterns {
		if pattern.Name == name {
			return true
		}
	}
	return false
}

func canaryTokenNames(tokens []CanaryToken) []string {
	names := make([]string, 0, len(tokens))
	for _, token := range tokens {
		names = append(names, token.Name)
	}
	return names
}

func responsePatternNames(patterns []ResponseScanPattern) []string {
	names := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		names = append(names, pattern.Name)
	}
	return names
}

func toolPolicyRuleNames(rules []ToolPolicyRule) []string {
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.Name)
	}
	return names
}
