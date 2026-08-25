// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestLoadBytesRejectsCoreFloorSuppressions(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		remediation string
	}{
		{name: "DLP exact name", rule: "AWS Access ID", remediation: "dlp.patterns[].exempt_domains"},
		{name: "DLP case variant", rule: "aws access id", remediation: "dlp.patterns[].exempt_domains"},
		{name: "response exact name", rule: "Prompt Injection", remediation: "tighten the response pattern"},
		{name: "response case variant", rule: "prompt injection", remediation: "tighten the response pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := "version: 1\nsuppress:\n  - rule: \"" + tt.rule + "\"\n    path: \"*\"\n"
			_, err := LoadBytes([]byte(yaml))
			if err == nil {
				t.Fatalf("LoadBytes accepted core floor suppression for %q", tt.rule)
			}
			for _, want := range []string{tt.rule, "core floor patterns cannot be suppressed", tt.remediation} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("LoadBytes error = %q, want substring %q", err, want)
				}
			}
		})
	}
}

func TestLoadBytesAllowsNonCoreSuppression(t *testing.T) {
	const yaml = "version: 1\nsuppress:\n  - rule: \"Anthropic API Key\"\n    path: \"*.anthropic.com*\"\n"
	if _, err := LoadBytes([]byte(yaml)); err != nil {
		t.Fatalf("LoadBytes rejected non-core suppression: %v", err)
	}
}
