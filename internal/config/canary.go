// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"
	"strings"
)

// CanaryTokens configures synthetic secrets used to detect exfiltration.
//
// Free tier: global canary tokens are available without gating.
// Note: per-agent canary variants should follow the existing agents gate
// (FeatureAgents) rather than introducing a new license type.
type CanaryTokens struct {
	Enabled bool          `yaml:"enabled"`
	Tokens  []CanaryToken `yaml:"tokens"`
}

// CanaryToken is a synthetic secret value and optional env var binding.
type CanaryToken struct {
	Name   string `yaml:"name"`
	Value  string `yaml:"value"`
	EnvVar string `yaml:"env_var,omitempty"`
}

var canaryEnvVarPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateCanaryTokens validates and normalizes canary token config.
func validateCanaryTokens(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.CanaryTokens.Enabled && len(cfg.CanaryTokens.Tokens) == 0 {
		return fmt.Errorf("canary_tokens.enabled is true but canary_tokens.tokens is empty")
	}

	seenNames := make(map[string]struct{}, len(cfg.CanaryTokens.Tokens))
	seenValues := make(map[string]struct{}, len(cfg.CanaryTokens.Tokens))
	for i := range cfg.CanaryTokens.Tokens {
		tok := &cfg.CanaryTokens.Tokens[i]
		tok.Name = strings.TrimSpace(tok.Name)
		tok.Value = strings.TrimSpace(tok.Value)
		tok.EnvVar = strings.TrimSpace(tok.EnvVar)

		if tok.Name == "" {
			return fmt.Errorf("canary_tokens.tokens[%d].name is required", i)
		}
		if tok.Value == "" {
			return fmt.Errorf("canary_tokens.tokens[%d].value is required", i)
		}
		if len(tok.Value) < 8 {
			return fmt.Errorf("canary_tokens.tokens[%d].value must be at least 8 characters", i)
		}
		key := strings.ToLower(tok.Name)
		if _, exists := seenNames[key]; exists {
			return fmt.Errorf("canary_tokens.tokens[%d].name %q is duplicated", i, tok.Name)
		}
		seenNames[key] = struct{}{}
		if _, exists := seenValues[tok.Value]; exists {
			return fmt.Errorf("canary_tokens.tokens[%d].value is duplicated", i)
		}
		seenValues[tok.Value] = struct{}{}

		if tok.EnvVar != "" && !canaryEnvVarPattern.MatchString(tok.EnvVar) {
			return fmt.Errorf("canary_tokens.tokens[%d].env_var %q is invalid", i, tok.EnvVar)
		}
	}

	return nil
}
