// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

func TestPresetToolPoliciesCoverEquivalentProtectedPathOperations(t *testing.T) {
	presets := []string{
		"audit.yaml",
		"balanced.yaml",
		"claude-code.yaml",
		"cursor.yaml",
		"generic-agent.yaml",
		"hostile-model.yaml",
		"strict.yaml",
	}
	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
			path, err := filepath.Abs(filepath.Join("..", "..", "..", "configs", preset))
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("load preset: %v", err)
			}
			pc := New(cfg.MCPToolPolicy)
			if pc == nil {
				t.Fatal("preset tool policy is disabled")
			}

			credentialAction := effectiveRuleAction(t, cfg.MCPToolPolicy, "Credential File Access")
			for _, toolName := range strings.Split(fileReadToolPattern, "|") {
				assertPolicyCall(t, pc, toolName, map[string]any{
					"path": "/home/user/.ssh/id_rsa",
				}, "Credential File Access", credentialAction)
			}

			checks := []struct {
				path         string
				moveRule     string
				copyRule     string
				baselineRule string
			}{
				{path: "/etc/systemd/system/p.service", moveRule: "Persistence Path Write", copyRule: "Protected Path Copy", baselineRule: "Persistence Path Write"},
				{path: "/home/user/.bashrc", moveRule: "Shell Profile Modification", copyRule: "Protected Path Copy", baselineRule: "Shell Profile Modification"},
				{path: "/var/log/audit.log", moveRule: "Audit Log Move", copyRule: "Audit Log Copy", baselineRule: "Audit Log Tampering"},
			}
			for _, check := range checks {
				wantAction := effectiveRuleAction(t, cfg.MCPToolPolicy, check.baselineRule)
				for _, direction := range []string{"source", "destination"} {
					args := map[string]any{"source": "/tmp/staged", "destination": "/tmp/backup"}
					args[direction] = check.path
					assertPolicyCall(t, pc, "move_file", args, check.moveRule, wantAction)
				}
				assertPolicyCall(t, pc, "copy_file", map[string]any{
					"source": "/tmp/staged", "destination": check.path,
				}, check.copyRule, wantAction)
			}
		})
	}
}

func effectiveRuleAction(t *testing.T, cfg config.MCPToolPolicy, name string) string {
	t.Helper()
	for _, rule := range cfg.Rules {
		if rule.Name == name {
			if rule.Action != "" {
				return rule.Action
			}
			return cfg.Action
		}
	}
	t.Fatalf("rule %q not found", name)
	return ""
}

func assertPolicyCall(t *testing.T, pc *Config, toolName string, args map[string]any, wantRule, wantAction string) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	extracted := jsonrpc.ExtractStringsFromJSONResult(raw)
	v := pc.CheckToolCallWithArgs(toolName, extracted.Strings, raw)
	if !v.Matched || !slices.Contains(v.Rules, wantRule) {
		t.Fatalf("%s(%s) verdict = %+v, want rule %q", toolName, raw, v, wantRule)
	}
	if v.Action != wantAction {
		t.Fatalf("%s(%s) action = %q, want preserved action %q", toolName, raw, v.Action, wantAction)
	}
}
