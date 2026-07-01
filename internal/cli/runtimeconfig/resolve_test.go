// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtimeconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func loadConfigYAML(t *testing.T, yaml string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func TestResolveAndReportConfig_ResponseScanningBooleanStates(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantWarning bool
	}{
		{name: "omitted", yaml: "version: 1\n", wantWarning: false},
		{name: "null", yaml: "version: 1\nresponse_scanning:\n  enabled: null\n", wantWarning: false},
		{name: "false", yaml: "version: 1\nresponse_scanning:\n  enabled: false\n", wantWarning: true},
		{name: "true", yaml: "version: 1\nresponse_scanning:\n  enabled: true\n", wantWarning: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			ResolveAndReportConfig(loadConfigYAML(t, tc.yaml), config.RuntimeResolveOpts{Mode: config.RuntimeMCPScan}, &stderr, "scan")
			gotWarning := strings.Contains(stderr.String(), ResponseScanningMCPDisabledWarning)
			if gotWarning != tc.wantWarning {
				t.Fatalf("warning = %v, want %v; stderr:\n%s", gotWarning, tc.wantWarning, stderr.String())
			}
		})
	}
}

func TestResolveAndReportConfig_ResponseScanningReloadStates(t *testing.T) {
	trueCfg := loadConfigYAML(t, "version: 1\nresponse_scanning:\n  enabled: true\n")
	falseCfg := loadConfigYAML(t, "version: 1\nresponse_scanning:\n  enabled: false\n")

	var stderr bytes.Buffer
	ResolveAndReportConfig(trueCfg, config.RuntimeResolveOpts{Mode: config.RuntimeMCPScan}, &stderr, "reload")
	if strings.Contains(stderr.String(), ResponseScanningMCPDisabledWarning) {
		t.Fatalf("reload without disable should not warn:\n%s", stderr.String())
	}

	stderr.Reset()
	ResolveAndReportConfig(falseCfg, config.RuntimeResolveOpts{Mode: config.RuntimeMCPScan}, &stderr, "reload")
	if !strings.Contains(stderr.String(), ResponseScanningMCPDisabledWarning) {
		t.Fatalf("reload with disable should warn:\n%s", stderr.String())
	}

	stderr.Reset()
	ResolveAndReportConfig(falseCfg, config.RuntimeResolveOpts{Mode: config.RuntimeMCPScan}, &stderr, "reload")
	if !strings.Contains(stderr.String(), ResponseScanningMCPDisabledWarning) {
		t.Fatalf("reload without config change should still warn when fallback fires:\n%s", stderr.String())
	}
}

func TestEmitResolveInfoLogs_AllBranches(t *testing.T) {
	EmitResolveInfoLogs(nil, config.ResolveRuntimeInfo{
		ResponseScanningFallback:    true,
		MCPInputScanningAutoEnabled: true,
		MCPToolScanningAutoEnabled:  true,
		MCPToolPolicyAutoEnabled:    true,
	}, "proxy")

	var stderr bytes.Buffer
	EmitResolveInfoLogs(&stderr, config.ResolveRuntimeInfo{
		ResponseScanningFallback:    true,
		MCPInputScanningAutoEnabled: true,
		MCPToolScanningAutoEnabled:  true,
		MCPToolPolicyAutoEnabled:    true,
	}, "proxy")

	out := stderr.String()
	for _, want := range []string{
		ResponseScanningMCPDisabledWarning,
		"auto-enabling MCP input scanning for proxy mode",
		"auto-enabling MCP tool scanning for proxy mode",
		"auto-enabling MCP tool call policy for proxy mode",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in stderr:\n%s", want, out)
		}
	}
}
