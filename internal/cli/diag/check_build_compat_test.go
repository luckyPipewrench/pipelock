// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCheckCmdRejectsNamedAgentsWithoutEnterpriseImplementation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	const cfgYAML = `mode: balanced
agents:
  worker: {}
`
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := CheckCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--config", path, "--require-build-compatibility"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "named agent profiles require an enterprise build") {
		t.Fatalf("Execute() error = %v, want enterprise build refusal; output:\n%s", err, buf.String())
	}
	if strings.Contains(buf.String(), "Config validation: OK") {
		t.Fatalf("incompatible config reported success:\n%s", buf.String())
	}
}

func TestCheckCmdAllowsNamedAgentsWithoutCompatibilityRequirement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte("mode: balanced\nagents:\n  worker: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := CheckCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--config", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, want nil; output:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "Config validation: OK") {
		t.Fatalf("ordinary config validation did not report success:\n%s", buf.String())
	}
}

func TestCheckBuildConfigCompatibilityAllowsDefaultProfileAndEnterprise(t *testing.T) {
	t.Run("default profile in core build", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Agents = map[string]config.AgentProfile{"_default": {}}
		if err := checkBuildConfigCompatibility(cfg); err != nil {
			t.Fatalf("checkBuildConfigCompatibility() error = %v, want nil", err)
		}
	})

	t.Run("named profile with enterprise implementation", func(t *testing.T) {
		original := config.ValidateAgentsFunc
		config.ValidateAgentsFunc = func(*config.Config) error { return nil }
		t.Cleanup(func() { config.ValidateAgentsFunc = original })

		cfg := config.Defaults()
		cfg.Agents = map[string]config.AgentProfile{"worker": {}}
		if err := checkBuildConfigCompatibility(cfg); err != nil {
			t.Fatalf("checkBuildConfigCompatibility() error = %v, want nil", err)
		}
	})
}
