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
