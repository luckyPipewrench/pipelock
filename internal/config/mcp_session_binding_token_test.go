// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMCPSessionBinding_RequiresListenerStateTokenYAMLStates(t *testing.T) {
	t.Parallel()

	t.Run("omitted", func(t *testing.T) {
		var binding MCPSessionBinding
		if err := yaml.Unmarshal([]byte("{}\n"), &binding); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if binding.RequiresListenerStateToken() {
			t.Fatal("omitted listener_require_state_token defaulted on")
		}
	})

	t.Run("null", func(t *testing.T) {
		var binding MCPSessionBinding
		if err := yaml.Unmarshal([]byte("listener_require_state_token: ~\n"), &binding); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if binding.RequiresListenerStateToken() {
			t.Fatal("YAML null listener_require_state_token defaulted on")
		}
	})

	t.Run("blank", func(t *testing.T) {
		var binding MCPSessionBinding
		if err := yaml.Unmarshal([]byte("listener_require_state_token:\n"), &binding); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if binding.RequiresListenerStateToken() {
			t.Fatal("YAML blank listener_require_state_token defaulted on")
		}
	})

	t.Run("explicit_false", func(t *testing.T) {
		var binding MCPSessionBinding
		if err := yaml.Unmarshal([]byte("listener_require_state_token: false\n"), &binding); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if binding.RequiresListenerStateToken() {
			t.Fatal("explicit false was treated as required")
		}
	})

	t.Run("explicit_true", func(t *testing.T) {
		var binding MCPSessionBinding
		if err := yaml.Unmarshal([]byte("listener_require_state_token: true\n"), &binding); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !binding.RequiresListenerStateToken() {
			t.Fatal("explicit true was ignored")
		}
	})
}

func TestMCPSessionBinding_RequiresListenerStateTokenReload(t *testing.T) {
	t.Parallel()

	var initial MCPSessionBinding
	if err := yaml.Unmarshal([]byte("listener_require_state_token: false\n"), &initial); err != nil {
		t.Fatalf("initial unmarshal: %v", err)
	}
	if initial.RequiresListenerStateToken() {
		t.Fatal("initial load required a listener token")
	}

	var changed MCPSessionBinding
	if err := yaml.Unmarshal([]byte("listener_require_state_token: true\n"), &changed); err != nil {
		t.Fatalf("reload-with-change: %v", err)
	}
	if !changed.RequiresListenerStateToken() {
		t.Fatal("reload-with-change did not enable the requirement")
	}

	var unchanged MCPSessionBinding
	if err := yaml.Unmarshal([]byte("listener_require_state_token: true\n"), &unchanged); err != nil {
		t.Fatalf("reload-without-change: %v", err)
	}
	if !unchanged.RequiresListenerStateToken() {
		t.Fatal("reload-without-change dropped the requirement")
	}
}
