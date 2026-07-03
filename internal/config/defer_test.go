// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDeferMCPToolPolicy(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionDefer
	cfg.MCPToolPolicy.DeferResolverProfiles = map[string]DeferResolverProfile{
		"approve": {Exec: []string{"/bin/echo", "allow"}},
	}
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		ResolutionPolicy: &DeferResolutionPolicy{
			ResolverProfile: "approve",
			AllowOn:         DeferAllowOn{Approval: true},
		},
	}}
	if _, err := cfg.ValidateWithWarnings(); err != nil {
		t.Fatalf("ValidateWithWarnings() = %v", err)
	}
}

func TestValidateDeferMCPToolPolicyRequiresResolutionPolicy(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionDefer
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{Name: "hold-write", ToolPattern: "^write_"}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "no affirmative resolution_policy") {
		t.Fatalf("ValidateWithWarnings() error = %v, want resolution_policy error", err)
	}
}

func TestValidateDeferRuleMissingResolutionPolicyDoesNotPanic(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionWarn
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		Action:      ActionDefer,
	}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "no affirmative resolution_policy") {
		t.Fatalf("ValidateWithWarnings() error = %v, want resolution_policy validation error", err)
	}
}

func TestValidateDeferSettingsRejectInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{
			name: "timeout",
			mut:  func(c *Config) { c.Defer.TimeoutSeconds = 0 },
			want: "defer.timeout_seconds must be positive",
		},
		{
			name: "max pending",
			mut:  func(c *Config) { c.Defer.MaxPending = 0 },
			want: "defer.max_pending must be positive",
		},
		{
			name: "max pending per session",
			mut:  func(c *Config) { c.Defer.MaxPendingPerSession = 0 },
			want: "defer.max_pending_per_session must be positive",
		},
		{
			name: "max pending bytes",
			mut:  func(c *Config) { c.Defer.MaxPendingBytes = 0 },
			want: "defer.max_pending_bytes must be positive",
		},
		{
			name: "max cascade depth",
			mut:  func(c *Config) { c.Defer.MaxCascadeDepth = -1 },
			want: "defer.max_cascade_depth must be >= 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mut(cfg)
			_, err := cfg.ValidateWithWarnings()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateWithWarnings() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestDeferMaxCascadeDepthDefaultsAndReloadStates(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want int
	}{
		{
			name: "omitted",
			yaml: "mode: balanced\n",
			want: 8,
		},
		{
			name: "yaml null blank",
			yaml: "mode: balanced\ndefer:\n  max_cascade_depth:\n",
			want: 8,
		},
		{
			name: "explicit zero",
			yaml: "mode: balanced\ndefer:\n  max_cascade_depth: 0\n",
			want: 8,
		},
		{
			name: "explicit value",
			yaml: "mode: balanced\ndefer:\n  max_cascade_depth: 5\n",
			want: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadDeferYAML(t, tt.yaml)
			if cfg.Defer.MaxCascadeDepth != tt.want {
				t.Fatalf("MaxCascadeDepth = %d, want %d", cfg.Defer.MaxCascadeDepth, tt.want)
			}
		})
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	writeConfigYAML(t, path, "mode: balanced\ndefer:\n  max_cascade_depth: 4\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load initial: %v", err)
	}
	if cfg.Defer.MaxCascadeDepth != 4 {
		t.Fatalf("initial MaxCascadeDepth = %d, want 4", cfg.Defer.MaxCascadeDepth)
	}
	writeConfigYAML(t, path, "mode: balanced\ndefer:\n  max_cascade_depth: 6\n")
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load changed: %v", err)
	}
	if cfg.Defer.MaxCascadeDepth != 6 {
		t.Fatalf("changed MaxCascadeDepth = %d, want 6", cfg.Defer.MaxCascadeDepth)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load unchanged: %v", err)
	}
	if cfg.Defer.MaxCascadeDepth != 6 {
		t.Fatalf("unchanged MaxCascadeDepth = %d, want 6", cfg.Defer.MaxCascadeDepth)
	}
}

func TestValidateDeferMaxCascadeDepthWarnsWhenDisabled(t *testing.T) {
	cfg := loadDeferYAML(t, "mode: balanced\ndefer:\n  enabled: false\n  max_cascade_depth: 4\n")
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings() error = %v", err)
	}
	if !hasDeferWarning(warnings, "defer.max_cascade_depth") {
		t.Fatalf("warnings = %+v, want defer.max_cascade_depth warning", warnings)
	}

	cfg = loadDeferYAML(t, "mode: balanced\ndefer:\n  enabled: false\n")
	warnings, err = cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings() without explicit value error = %v", err)
	}
	if hasDeferWarning(warnings, "defer.max_cascade_depth") {
		t.Fatalf("warnings = %+v, want no max_cascade_depth warning", warnings)
	}
}

func TestValidateDeferNoCascadeDepthWarningFromDefaults(t *testing.T) {
	// Programmatic configs have no raw YAML; the resolved default depth must
	// not be mistaken for an operator-set value.
	cfg := Defaults()
	cfg.Defer.Enabled = false
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings() error = %v", err)
	}
	if hasDeferWarning(warnings, "defer.max_cascade_depth") {
		t.Fatalf("warnings = %+v, want no max_cascade_depth warning from Defaults()", warnings)
	}
}

func loadDeferYAML(t *testing.T, src string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	writeConfigYAML(t, path, src)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q): %v", src, err)
	}
	return cfg
}

func writeConfigYAML(t *testing.T, path, src string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func hasDeferWarning(warnings []Warning, field string) bool {
	for _, warning := range warnings {
		if warning.Field == field {
			return true
		}
	}
	return false
}

func TestValidateDeferMCPToolPolicyRejectsInvalidResolverProfiles(t *testing.T) {
	tests := []struct {
		name    string
		profile DeferResolverProfile
		want    string
	}{
		{
			name:    "empty exec",
			profile: DeferResolverProfile{},
			want:    "has empty exec",
		},
		{
			name:    "relative match path",
			profile: DeferResolverProfile{Exec: []string{"bin/approve"}, MatchAbsPath: true},
			want:    "match_abs_path is true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.MCPToolPolicy.Enabled = true
			cfg.MCPToolPolicy.Action = ActionWarn
			cfg.MCPToolPolicy.DeferResolverProfiles = map[string]DeferResolverProfile{
				"approve": tt.profile,
			}
			cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
				Name:        "warn-write",
				ToolPattern: "^write_",
				Action:      ActionWarn,
			}}
			_, err := cfg.ValidateWithWarnings()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateWithWarnings() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateDeferMCPToolPolicyRejectsInvalidActionAndDisabledRuleDefer(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = "hold"
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
	}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), `invalid mcp_tool_policy action "hold"`) {
		t.Fatalf("ValidateWithWarnings() error = %v, want invalid action error", err)
	}

	cfg = Defaults()
	cfg.Defer.Enabled = false
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionWarn
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		Action:      ActionDefer,
	}}
	_, err = cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "action=defer but defer.enabled is false") {
		t.Fatalf("ValidateWithWarnings() error = %v, want disabled defer rule error", err)
	}
}

func TestValidateDeferMCPToolPolicyRejectsPolicyPermits(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionDefer
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		ResolutionPolicy: &DeferResolutionPolicy{
			AllowOn: DeferAllowOn{PolicyPermits: true},
		},
	}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "policy_reload cannot fire") {
		t.Fatalf("ValidateWithWarnings() error = %v, want policy_permits unsupported error", err)
	}
}

func TestValidateDeferMCPToolPolicyRejectsUnknownResolverProfile(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionDefer
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		ResolutionPolicy: &DeferResolutionPolicy{
			ResolverProfile: "missing",
			AllowOn:         DeferAllowOn{Approval: true},
		},
	}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "unknown defer resolver profile") {
		t.Fatalf("ValidateWithWarnings() error = %v, want unknown resolver profile error", err)
	}
}

func TestValidateDeferMCPToolPolicyAllowsToolInventoryBaseline(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionDefer
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		ResolutionPolicy: &DeferResolutionPolicy{
			AllowOn: DeferAllowOn{ToolInventoryBaseline: true},
		},
	}}
	if _, err := cfg.ValidateWithWarnings(); err != nil {
		t.Fatalf("ValidateWithWarnings() = %v", err)
	}
}

func TestValidateDeferMCPToolPolicyRejectsApprovalWithoutProfile(t *testing.T) {
	cfg := Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionDefer
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		ResolutionPolicy: &DeferResolutionPolicy{
			AllowOn: DeferAllowOn{Approval: true},
		},
	}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "no resolution_policy.resolver_profile") {
		t.Fatalf("ValidateWithWarnings() error = %v, want missing resolver profile error", err)
	}
}

func TestValidateDeferDisabledRejectsMCPToolPolicy(t *testing.T) {
	cfg := Defaults()
	cfg.Defer.Enabled = false
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = ActionDefer
	cfg.MCPToolPolicy.DeferResolverProfiles = map[string]DeferResolverProfile{
		"approve": {Exec: []string{"/bin/echo", "allow"}},
	}
	cfg.MCPToolPolicy.Rules = []ToolPolicyRule{{
		Name:        "hold-write",
		ToolPattern: "^write_",
		ResolutionPolicy: &DeferResolutionPolicy{
			ResolverProfile: "approve",
			AllowOn:         DeferAllowOn{Approval: true},
		},
	}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "defer.enabled must be true") {
		t.Fatalf("ValidateWithWarnings() error = %v, want defer.enabled error", err)
	}
}

func TestDeferResolutionTriggersFieldRemoved(t *testing.T) {
	// A config that sets defer.resolution_triggers must fail the strict
	// unknown-field decode, proving the vestigial field has been removed.
	yaml := []byte("mode: balanced\ndefer:\n  resolution_triggers:\n    - tool_inventory_updated\n")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("Load() succeeded, want error for unknown field resolution_triggers")
	}
	if !strings.Contains(err.Error(), "resolution_triggers") {
		t.Fatalf("Load() error = %v, want error mentioning resolution_triggers", err)
	}
}

func TestValidateRequestPolicyRejectsDefer(t *testing.T) {
	cfg := Defaults()
	cfg.RequestPolicy.Enabled = true
	cfg.RequestPolicy.Rules = []RequestPolicyRule{{
		Name:   "no-defer",
		Action: ActionDefer,
		Route:  RequestPolicyRoute{Hosts: []string{"api.example.com"}},
	}}
	_, err := cfg.ValidateWithWarnings()
	if err == nil || !strings.Contains(err.Error(), "must be block or warn") {
		t.Fatalf("ValidateWithWarnings() error = %v, want request_policy action rejection", err)
	}
}
