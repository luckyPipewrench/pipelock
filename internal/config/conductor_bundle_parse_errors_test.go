// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestConductorBundleRejectsMalformedInputBeforeRuntimeMutation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "malformed first document", yaml: "mode: [", want: "config sections:"},
		{name: "malformed trailing document", yaml: "mode: balanced\n---\n[", want: "config sections:"},
		{name: "multiple documents", yaml: "mode: balanced\n---\nmode: strict", want: "multiple YAML documents"},
		{name: "unknown field", yaml: "unknown_control: true", want: "raw config:"},
		{name: "scalar document", yaml: "strict", want: "raw config:"},
		{name: "sequence document", yaml: "- mode: strict", want: "raw config:"},
		{name: "duplicate field", yaml: "mode: balanced\nmode: strict", want: "raw config:"},
		{name: "response missing name", yaml: "response_scanning:\n  patterns:\n    - regex: blocked", want: "response scanning pattern missing name"},
		{name: "response missing regex", yaml: "response_scanning:\n  patterns:\n    - name: remote", want: "response scanning pattern \"remote\" missing regex"},
		{name: "response invalid regex", yaml: "response_scanning:\n  patterns:\n    - name: remote\n      regex: '['", want: "response scanning pattern \"remote\" has invalid regex"},
		{name: "tool missing name", yaml: "mcp_tool_policy:\n  rules:\n    - tool_pattern: .*", want: "rule 0 missing name"},
		{name: "tool missing pattern", yaml: "mcp_tool_policy:\n  rules:\n    - name: remote", want: "rule \"remote\" missing tool_pattern"},
		{name: "tool invalid pattern", yaml: "mcp_tool_policy:\n  rules:\n    - name: remote\n      tool_pattern: '['", want: "invalid tool_pattern"},
		{name: "tool invalid argument pattern", yaml: "mcp_tool_policy:\n  rules:\n    - name: remote\n      tool_pattern: .*\n      arg_pattern: '['", want: "invalid arg_pattern"},
		{name: "tool argument key without pattern", yaml: "mcp_tool_policy:\n  rules:\n    - name: remote\n      tool_pattern: .*\n      arg_key: target", want: "arg_key without arg_pattern"},
		{name: "tool invalid argument key", yaml: "mcp_tool_policy:\n  rules:\n    - name: remote\n      tool_pattern: .*\n      arg_pattern: .*\n      arg_key: '['", want: "invalid arg_key"},
		{name: "tool invalid action", yaml: "mcp_tool_policy:\n  rules:\n    - name: remote\n      tool_pattern: .*\n      action: allow", want: "invalid action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldCfg := Defaults()
			oldCfg.FetchProxy.Listen = "localhost:8888"
			oldCfg.ResponseScanning.Enabled = true
			oldBefore := oldCfg.Clone()
			candidate := Defaults()
			candidate.Mode = ModeStrict
			before := candidate.Clone()
			err := PreserveConductorBundleLocalRuntimeState(candidate, oldCfg, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("PreserveConductorBundleLocalRuntimeState() = %v, want %q", err, tt.want)
			}
			if !reflect.DeepEqual(candidate, before) {
				t.Fatal("malformed bundle partially changed the candidate runtime configuration")
			}
			if !reflect.DeepEqual(oldCfg, oldBefore) {
				t.Fatal("malformed bundle changed the active runtime configuration")
			}
		})
	}
}

func TestConductorBundleEmptyInputPreservesLocalDetections(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"", "# no remote controls\n", "mode: strict\n"} {
		t.Run(input, func(t *testing.T) {
			oldCfg := Defaults()
			candidate := Defaults()
			candidate.DLP.Patterns = nil
			candidate.ResponseScanning.Patterns = nil
			if err := PreserveConductorBundleLocalRuntimeState(candidate, oldCfg, input); err != nil {
				t.Fatalf("valid bundle: %v", err)
			}
			if len(oldCfg.DLP.Patterns) == 0 || len(oldCfg.ResponseScanning.Patterns) == 0 {
				t.Fatal("positive control requires configured local detections")
			}
			if !reflect.DeepEqual(candidate.DLP, oldCfg.DLP) || !reflect.DeepEqual(candidate.ResponseScanning, oldCfg.ResponseScanning) {
				t.Fatal("bundle without detection sections removed local protections")
			}
		})
	}
}
