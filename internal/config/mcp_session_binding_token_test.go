// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMCPSessionBinding_RequiresListenerStateTokenYAMLStates(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted", yaml: "{}\n", want: false},
		{name: "null", yaml: "listener_require_state_token: ~\n", want: false},
		{name: "blank", yaml: "listener_require_state_token:\n", want: false},
		{name: "explicit_false", yaml: "listener_require_state_token: false\n", want: false},
		{name: "explicit_true", yaml: "listener_require_state_token: true\n", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var binding MCPSessionBinding
			if err := yaml.Unmarshal([]byte(tc.yaml), &binding); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := binding.RequiresListenerStateToken(); got != tc.want {
				t.Fatalf("RequiresListenerStateToken() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestMCPSessionBinding_RequiresListenerStateTokenReload(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		initialYAML string
		updatedYAML string
		wantInitial bool
		wantUpdated bool
	}{
		{name: "omitted_to_false", initialYAML: "{}\n", updatedYAML: "listener_require_state_token: false\n", wantInitial: false, wantUpdated: false},
		{name: "null_to_false", initialYAML: "listener_require_state_token: ~\n", updatedYAML: "listener_require_state_token: false\n", wantInitial: false, wantUpdated: false},
		{name: "false_to_true", initialYAML: "listener_require_state_token: false\n", updatedYAML: "listener_require_state_token: true\n", wantInitial: false, wantUpdated: true},
		{name: "true_to_false", initialYAML: "listener_require_state_token: true\n", updatedYAML: "listener_require_state_token: false\n", wantInitial: true, wantUpdated: false},
		{name: "true_to_true", initialYAML: "listener_require_state_token: true\n", updatedYAML: "listener_require_state_token: true\n", wantInitial: true, wantUpdated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var initial, updated MCPSessionBinding
			if err := yaml.Unmarshal([]byte(tc.initialYAML), &initial); err != nil {
				t.Fatalf("initial unmarshal: %v", err)
			}
			if err := yaml.Unmarshal([]byte(tc.updatedYAML), &updated); err != nil {
				t.Fatalf("updated unmarshal: %v", err)
			}
			if got := initial.RequiresListenerStateToken(); got != tc.wantInitial {
				t.Fatalf("initial token requirement = %t, want %t", got, tc.wantInitial)
			}
			if got := updated.RequiresListenerStateToken(); got != tc.wantUpdated {
				t.Fatalf("reload token requirement = %t, want %t", got, tc.wantUpdated)
			}
		})
	}
}

func TestValidateReload_MCPSessionBindingListenerRequireStateToken(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		oldYAML       string
		updatedYAML   string
		oldParent     bool
		updatedParent bool
		wantWarning   bool
	}{
		{name: "omitted_to_true", oldYAML: "{}\n", updatedYAML: "listener_require_state_token: true\n", oldParent: true, updatedParent: true},
		{name: "null_to_true", oldYAML: "listener_require_state_token: ~\n", updatedYAML: "listener_require_state_token: true\n", oldParent: true, updatedParent: true},
		{name: "false_to_true", oldYAML: "listener_require_state_token: false\n", updatedYAML: "listener_require_state_token: true\n", oldParent: true, updatedParent: true},
		{name: "true_to_false", oldYAML: "listener_require_state_token: true\n", updatedYAML: "listener_require_state_token: false\n", oldParent: true, updatedParent: true, wantWarning: true},
		{name: "true_to_null", oldYAML: "listener_require_state_token: true\n", updatedYAML: "listener_require_state_token: ~\n", oldParent: true, updatedParent: true, wantWarning: true},
		{name: "true_to_omitted", oldYAML: "listener_require_state_token: true\n", updatedYAML: "{}\n", oldParent: true, updatedParent: true, wantWarning: true},
		{name: "true_to_true", oldYAML: "listener_require_state_token: true\n", updatedYAML: "listener_require_state_token: true\n", oldParent: true, updatedParent: true},
		{name: "disabled_parent", oldYAML: "listener_require_state_token: true\n", updatedYAML: "listener_require_state_token: false\n", oldParent: false, updatedParent: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var oldBinding, updatedBinding MCPSessionBinding
			if err := yaml.Unmarshal([]byte(tc.oldYAML), &oldBinding); err != nil {
				t.Fatalf("old unmarshal: %v", err)
			}
			if err := yaml.Unmarshal([]byte(tc.updatedYAML), &updatedBinding); err != nil {
				t.Fatalf("updated unmarshal: %v", err)
			}

			old, updated := Defaults(), Defaults()
			old.MCPSessionBinding = oldBinding
			updated.MCPSessionBinding = updatedBinding
			old.MCPSessionBinding.Enabled = tc.oldParent
			updated.MCPSessionBinding.Enabled = tc.updatedParent

			gotWarning := false
			for _, warning := range ValidateReload(old, updated) {
				if warning.Field == "mcp_session_binding.listener_require_state_token" {
					gotWarning = true
				}
			}
			if gotWarning != tc.wantWarning {
				t.Fatalf("state-token downgrade warning = %t, want %t", gotWarning, tc.wantWarning)
			}
		})
	}
}
