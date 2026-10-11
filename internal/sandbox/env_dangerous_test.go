// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/envcontrol"
)

func TestIsDangerousEnvKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		// Known dangerous keys.
		{name: "LD_PRELOAD", key: "LD_PRELOAD", want: true},
		{name: "LD_LIBRARY_PATH", key: "LD_LIBRARY_PATH", want: true},
		{name: "NODE_OPTIONS", key: "NODE_OPTIONS", want: true},
		{name: "PYTHONSTARTUP", key: "PYTHONSTARTUP", want: true},
		{name: "PYTHONPATH", key: "PYTHONPATH", want: true},
		{name: "RUBYOPT", key: "RUBYOPT", want: true},
		{name: "PERL5OPT", key: "PERL5OPT", want: true},
		{name: "BASH_ENV", key: "BASH_ENV", want: true},
		{name: "ENV", key: "ENV", want: true},
		{name: "CDPATH", key: "CDPATH", want: true},
		{name: "HTTP_PROXY", key: "HTTP_PROXY", want: true},
		{name: "mixed-case proxy", key: "Http_Proxy", want: true},
		{name: "NO_PROXY", key: "NO_PROXY", want: true},

		// Safe keys that should NOT be flagged.
		{name: "PATH is sandbox-owned", key: "PATH", want: true},
		{name: "HOME is sandbox-owned", key: "HOME", want: true},
		{name: "USER is safe", key: "USER", want: false},
		{name: "LANG is safe", key: "LANG", want: false},
		{name: "TZ is safe", key: "TZ", want: false},
		{name: "MY_APP_KEY is safe", key: "MY_APP_KEY", want: false},
		{name: "empty string is safe", key: "", want: false},
		{name: "OPENAI_API_KEY is safe", key: "OPENAI_API_KEY", want: false},

		// Match the MCP override policy in every casing.
		{name: "lowercase ld_preload", key: "ld_preload", want: true},
		{name: "mixed case Node_Options", key: "Node_Options", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDangerousEnvKey(tt.key)
			if got != tt.want {
				t.Errorf("IsDangerousEnvKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestIsDangerousEnvKey_AllKeysInMap(t *testing.T) {
	// Verify every key in the sandboxOwnedEnvKeys map returns true.
	for key := range sandboxOwnedEnvKeys {
		if !IsDangerousEnvKey(key) {
			t.Errorf("IsDangerousEnvKey(%q) = false, want true (key is in sandboxOwnedEnvKeys map)", key)
		}
	}
}

// TestIsDangerousEnvKey_RefusesSharedCodeLoadingList keeps the sandbox --env
// filter in step with the MCP proxy filter and the verified local service
// check: all three refuse every name on the shared code-loading list.
func TestIsDangerousEnvKey_RefusesSharedCodeLoadingList(t *testing.T) {
	for _, key := range envcontrol.CodeLoadingNames() {
		if !IsDangerousEnvKey(key) {
			t.Errorf("IsDangerousEnvKey(%q) = false; the shared code-loading list must be refused", key)
		}
	}
	// Variables that change behavior without choosing code stay passable.
	for _, key := range []string{"NODE_EXTRA_CA_CERTS", "LD_PROFILE"} {
		if IsDangerousEnvKey(key) {
			t.Errorf("IsDangerousEnvKey(%q) = true; it loads no code and must remain passable", key)
		}
	}
}
