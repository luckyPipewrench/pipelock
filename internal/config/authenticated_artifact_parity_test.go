// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestAuthenticatedArtifactBundleNameMatchesRulesContract(t *testing.T) {
	t.Parallel()

	names := []string{
		"", "a", "ab", "abc", "a-b", "-abc", "abc-", "Abc", "a_b",
		"a" + strings.Repeat("b", 62) + "c",
		"a" + strings.Repeat("b", 63) + "c",
	}
	for _, name := range names {
		cfg := config.Defaults()
		cfg.ResponseScanning.AuthenticatedArtifacts = []config.AuthenticatedArtifactEntry{{
			Host:       "rules.example",
			Path:       "/rules/example/bundle.yaml",
			BundleName: name,
		}}
		configAccepts := cfg.Validate() == nil
		rulesAccepts := rules.ValidateBundleName(name) == nil
		if configAccepts != rulesAccepts {
			t.Errorf("bundle name %q: config accepts=%t, rules accepts=%t", name, configAccepts, rulesAccepts)
		}
	}
}
