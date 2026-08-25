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

func TestValidateSuppressionsRejectsInMemoryCoreEntry(t *testing.T) {
	cfg := Defaults()
	cfg.Suppress = []SuppressEntry{{Rule: "AWS Access ID", Path: "*"}}
	if err := cfg.ValidateSuppressions(); err == nil {
		t.Fatal("ValidateSuppressions accepted in-memory core floor suppression")
	}

	cfg.Suppress = []SuppressEntry{{Rule: "Anthropic API Key", Path: "*"}}
	if err := cfg.ValidateSuppressions(); err != nil {
		t.Fatalf("ValidateSuppressions rejected non-core suppression: %v", err)
	}
}

func TestCoreResponsePatternNamesReturnsCopy(t *testing.T) {
	names := CoreResponsePatternNames()
	if len(names) == 0 || !IsCoreResponsePatternName(names[0]) {
		t.Fatalf("CoreResponsePatternNames returned invalid registry: %v", names)
	}

	original := names[0]
	names[0] = "modified by caller"
	if fresh := CoreResponsePatternNames(); fresh[0] != original {
		t.Fatalf("CoreResponsePatternNames exposed mutable registry: got %q, want %q", fresh[0], original)
	}
}
