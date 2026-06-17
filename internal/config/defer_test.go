// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
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
			name: "unknown resolution trigger",
			mut:  func(c *Config) { c.Defer.ResolutionTriggers = []string{"unknown"} },
			want: "invalid defer resolution_triggers value",
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
