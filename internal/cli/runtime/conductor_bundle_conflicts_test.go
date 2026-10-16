//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReloadConductorBundleConflictsPreserveActiveState(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "dlp merge conflict",
			yaml: "dlp:\n  patterns:\n    - name: local-detection\n      regex: BUNDLE_DETECTION\n      severity: high\n",
			want: `cannot redefine local dlp.patterns item "local-detection"`,
		},
		{
			name: "canary merge conflict",
			yaml: "canary_tokens:\n  tokens:\n    - name: local-canary\n      value: bundle-canary\n",
			want: `cannot redefine local canary_tokens.tokens item "local-canary"`,
		},
		{
			name: "response merge conflict",
			yaml: "response_scanning:\n  patterns:\n    - name: local-response\n      regex: BUNDLE_RESPONSE\n",
			want: `cannot redefine local response_scanning.patterns item "local-response"`,
		},
		{
			name: "tool rule merge conflict",
			yaml: "mcp_tool_policy:\n  enabled: false\n  rules:\n    - name: local-tool\n      tool_pattern: ^bundle_\n      action: warn\n",
			want: `cannot redefine local mcp_tool_policy.rules item "local-tool"`,
		},
		{
			name: "inherited redirect requires profile",
			yaml: "mcp_tool_policy:\n  enabled: false\n  rules:\n    - name: bundle-tool\n      tool_pattern: ^bundle_\n",
			want: `mcp_tool_policy rule "bundle-tool" has action=redirect but no redirect_profile`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := newConductorApplyTestServer(t)
			active := s.proxy.CurrentConfig()
			active.DLP.Patterns = []config.DLPPattern{{Name: "local-detection", Regex: "LOCAL_DETECTION", Severity: config.SeverityHigh}}
			active.CanaryTokens.Tokens = []config.CanaryToken{{Name: "local-canary", Value: "local-canary-value"}}
			active.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "local-response", Regex: "LOCAL_RESPONSE"}}
			active.MCPToolPolicy = config.MCPToolPolicy{
				Action: config.ActionRedirect,
				RedirectProfiles: map[string]config.RedirectProfile{
					"safe-fetch": {Exec: []string{"/usr/bin/safe-fetch"}},
				},
				Rules: []config.ToolPolicyRule{{Name: "local-tool", ToolPattern: "^local_", Action: config.ActionBlock}},
			}
			before := active.Clone()
			scanner := s.proxy.ScannerPtr().Load()
			runtimeCfg := s.currentConfig()
			raw := "mode: strict\napi_allowlist:\n  - api.vendor.example\n" + tt.yaml
			candidate, err := config.LoadBytes([]byte(raw))
			if err != nil {
				t.Fatalf("valid candidate must reach the preservation helpers: %v", err)
			}
			if err := s.reloadConductorPolicyBundle(candidate, raw); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("reloadConductorPolicyBundle() = %v, want %q", err, tt.want)
			}
			if s.proxy.CurrentConfig() != active || !reflect.DeepEqual(active, before) {
				t.Fatal("rejected bundle changed the active proxy configuration")
			}
			if s.currentConfig() != runtimeCfg || !reflect.DeepEqual(runtimeCfg, before) {
				t.Fatal("rejected bundle changed the active runtime configuration")
			}
			if s.proxy.ScannerPtr().Load() != scanner {
				t.Fatal("rejected bundle replaced the active scanner")
			}
		})
	}
}
