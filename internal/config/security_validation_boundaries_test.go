// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// Exercise the public validator as used after operator configuration changes,
// with a valid control for every family of settings.
func TestSecurityValidationRejectsInvalidBoundaries(t *testing.T) {
	t.Parallel()
	base, err := LoadPolicyBundleBytes([]byte(`tool_chain_detection:
  enabled: true
cross_request_detection:
  enabled: true
  fragment_reassembly:
    enabled: true
address_protection:
  enabled: true
git_protection:
  enabled: true
`))
	if err != nil {
		t.Fatalf("load valid security configuration: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{name: "valid defaults", edit: func(*Config) {}},
		{name: "chain action", edit: func(c *Config) { c.ToolChainDetection.Action = ActionAllow }, want: "invalid tool_chain_detection.action"},
		{name: "zero chain window size", edit: func(c *Config) { c.ToolChainDetection.WindowSize = 0 }, want: "tool_chain_detection.window_size must be positive"},
		{name: "negative chain window size", edit: func(c *Config) { c.ToolChainDetection.WindowSize = -1 }, want: "tool_chain_detection.window_size must be positive"},
		{name: "zero chain window seconds", edit: func(c *Config) { c.ToolChainDetection.WindowSeconds = 0 }, want: "tool_chain_detection.window_seconds must be positive"},
		{name: "empty sensitivity patterns", edit: func(c *Config) { c.ToolChainDetection.SensitivityLabels = map[string][]string{"external_sink": {}} }, want: "must contain at least one pattern"},
		{name: "valid sensitivity pattern", edit: func(c *Config) {
			c.ToolChainDetection.SensitivityLabels = map[string][]string{"external_sink": {"send_*"}}
		}},
		{name: "negative taint history", edit: func(c *Config) { c.Taint.RecentSources = -1 }, want: "taint.recent_sources must be >= 0"},
		{name: "empty elevated path", edit: func(c *Config) { c.Taint.ElevatedPaths = []string{""} }, want: "taint.elevated_paths[0] must not be empty"},
		{name: "valid elevated path", edit: func(c *Config) { c.Taint.ElevatedPaths = []string{"/workspace/private/*"} }},
		{name: "empty protected path", edit: func(c *Config) { c.Taint.ProtectedPaths = []string{""} }, want: "taint.protected_paths[0] must not be empty"},
		{name: "body disabled pattern name", edit: func(c *Config) { c.RequestBodyScanning.DisablePatterns = []string{""} }, want: "request_body_scanning.disable_patterns[0] must not be empty"},
		{name: "body action empty name", edit: func(c *Config) { c.RequestBodyScanning.PatternActions = map[string]string{"": ActionBlock} }, want: "request_body_scanning.pattern_actions contains an empty pattern name"},
		{name: "cross request action", edit: func(c *Config) { c.CrossRequestDetection.Action = ActionAllow }, want: "invalid cross_request_detection.action"},
		{name: "fragment window", edit: func(c *Config) { c.CrossRequestDetection.FragmentReassembly.WindowMinutes = 0 }, want: "fragment_reassembly.window_minutes must be > 0"},
		{name: "address similarity suffix", edit: func(c *Config) { c.AddressProtection.Similarity.SuffixLength = 0 }, want: "address_protection.similarity.suffix_length must be positive"},
		{name: "push repository glob", edit: func(c *Config) { c.GitProtection.AllowedPushRepos = []string{"git.vendor.example/team/["} }, want: "invalid allowed_push_repos glob pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base.Clone()
			tt.edit(c)
			err := c.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("valid security configuration: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want %q", err, tt.want)
			}
		})
	}
}
