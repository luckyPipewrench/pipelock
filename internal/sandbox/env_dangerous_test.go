// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import "testing"

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

		// Safe keys that should NOT be flagged.
		{name: "PATH is safe", key: "PATH", want: false},
		{name: "HOME is safe", key: "HOME", want: false},
		{name: "USER is safe", key: "USER", want: false},
		{name: "LANG is safe", key: "LANG", want: false},
		{name: "TZ is safe", key: "TZ", want: false},
		{name: "MY_APP_KEY is safe", key: "MY_APP_KEY", want: false},
		{name: "empty string is safe", key: "", want: false},
		{name: "OPENAI_API_KEY is safe", key: "OPENAI_API_KEY", want: false},

		// Case sensitivity: map keys are exact match.
		{name: "lowercase ld_preload is safe", key: "ld_preload", want: false},
		{name: "mixed case Node_Options is safe", key: "Node_Options", want: false},
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
	// Verify every key in the dangerousEnvKeys map returns true.
	for key := range dangerousEnvKeys {
		if !IsDangerousEnvKey(key) {
			t.Errorf("IsDangerousEnvKey(%q) = false, want true (key is in dangerousEnvKeys map)", key)
		}
	}
}

func TestIsDangerousEnvKey_Count(t *testing.T) {
	// Verify the expected number of dangerous keys to catch accidental
	// removal or additions that aren't tested.
	const expectedCount = 10
	if len(dangerousEnvKeys) != expectedCount {
		t.Errorf("dangerousEnvKeys has %d entries, expected %d — update tests if keys were added or removed",
			len(dangerousEnvKeys), expectedCount)
	}
}
