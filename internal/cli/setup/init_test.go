// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func TestInitCmd_DryRun(t *testing.T) {
	home := t.TempDir()

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--dry-run", "--scan-home", home, "--skip-canary", "--skip-validate"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("Would write config to")) {
		t.Errorf("expected 'Would write config to' in output, got:\n%s", output)
	}
}

func TestInitCmd_WritesConfig(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "test-config.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("config file was not written")
	}

	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	if !bytes.Contains(data, []byte("mode: balanced")) {
		t.Errorf("expected 'mode: balanced' in config, got:\n%s", string(data))
	}
}

func TestInitCmd_StrictPreset(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "strict.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--preset", "strict",
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	if !bytes.Contains(data, []byte("mode: strict")) {
		t.Errorf("expected 'mode: strict' in config, got:\n%s", string(data))
	}
}

func TestInitCmd_AuditPreset(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "audit.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--preset", "audit",
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	if !bytes.Contains(data, []byte("mode: audit")) {
		t.Errorf("expected 'mode: audit' in config, got:\n%s", string(data))
	}
}

func TestInitCmd_BadPreset(t *testing.T) {
	home := t.TempDir()

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--scan-home", home, "--preset", "bogus"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for bad preset")
	}
}

func TestInitCmd_JSONOutput(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "init.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--json",
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result initResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}

	if result.Setup.Preset != "balanced" {
		t.Errorf("preset = %q, want balanced", result.Setup.Preset)
	}
	if !result.Setup.Written {
		t.Error("expected Written=true")
	}
}

func TestInitCmd_DryRunDoesNotWrite(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "should-not-exist.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--dry-run",
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Error("dry run should not have written the config file")
	}
}

func TestInitCmd_DefaultConfigPath(t *testing.T) {
	home := t.TempDir()

	// Use --output to a known location since the default path uses
	// os.UserConfigDir() which varies by platform and test environment.
	configPath := filepath.Join(home, "default-test.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("expected config at %s", configPath)
	}
}

func TestInitCmd_DiscoverWithClaudeConfig(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "init.yaml")

	content := `{"mcpServers":{
		"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]},
		"raw":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--json",
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result initResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if result.Discover.ClientsFound != 1 {
		t.Errorf("clients_found = %d, want 1", result.Discover.ClientsFound)
	}
	if result.Discover.ServersFound != 2 {
		t.Errorf("servers_found = %d, want 2", result.Discover.ServersFound)
	}
}

func TestInitCmd_RefusesOverwrite(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "existing.yaml")

	// Create an existing config.
	if err := os.WriteFile(configPath, []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Original file should be preserved.
	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "mode: strict\n" {
		t.Error("existing config was overwritten without --force")
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("already exists")) {
		t.Errorf("expected 'already exists' warning, got:\n%s", output)
	}
}

func TestInitCmd_ForceOverwrite(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "existing.yaml")

	if err := os.WriteFile(configPath, []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--force",
		"--skip-canary",
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("mode: balanced")) {
		t.Error("--force should have overwritten with new config")
	}
}

func TestInitCmd_UnwritablePath(t *testing.T) {
	home := t.TempDir()

	// Create a regular file, then try to use it as a directory.
	blocker := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", filepath.Join(blocker, "config.yaml"),
		"--skip-canary",
		"--skip-validate",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestInitCmd_WithVerify(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "init.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--skip-canary",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("Passed:")) {
		t.Errorf("expected verify results in output, got:\n%s", output)
	}
}

func TestInitCmd_WithCanary(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "init.yaml")

	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--skip-validate",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("Canary")) {
		t.Errorf("expected canary results in output, got:\n%s", output)
	}
}

func TestBuildConfig_MCPEnablement(t *testing.T) {
	tests := []struct {
		name          string
		servers       int
		wantMCPInput  bool
		wantToolChain bool
	}{
		{
			name:          "no servers",
			servers:       0,
			wantMCPInput:  false,
			wantToolChain: false,
		},
		{
			name:          "few servers enables MCP scanning",
			servers:       2,
			wantMCPInput:  true,
			wantToolChain: false,
		},
		{
			name:          "many servers enables tool chain detection",
			servers:       5,
			wantMCPInput:  true,
			wantToolChain: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := &discover.Report{
				Summary: discover.Summary{
					TotalServers: tc.servers,
				},
			}

			cfg := buildConfig(config.ModeBalanced, report)

			if cfg.MCPInputScanning.Enabled != tc.wantMCPInput {
				t.Errorf("MCPInputScanning.Enabled = %v, want %v",
					cfg.MCPInputScanning.Enabled, tc.wantMCPInput)
			}
			if cfg.ToolChainDetection.Enabled != tc.wantToolChain {
				t.Errorf("ToolChainDetection.Enabled = %v, want %v",
					cfg.ToolChainDetection.Enabled, tc.wantToolChain)
			}
		})
	}
}

func TestScanCanaryURL(t *testing.T) {
	tests := []struct {
		name   string
		preset string
		url    string
		want   bool
	}{
		{
			name:   "balanced mode detects canary",
			preset: config.ModeBalanced,
			url:    "https://github.com/test?key=" + canaryToken(),
			want:   true,
		},
		{
			name:   "strict mode detects canary on allowlisted host",
			preset: config.ModeStrict,
			url:    "https://github.com/test?key=" + canaryToken(),
			want:   true,
		},
		{
			name:   "clean URL not detected",
			preset: config.ModeBalanced,
			url:    "https://github.com/test",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Mode = tc.preset
			got := scanCanaryURL(cfg, tc.url)
			if got != tc.want {
				t.Errorf("scanCanaryURL(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestWriteConfig_Permissions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "subdir", "pipelock.yaml")

	cfg := config.Defaults()
	if err := writeConfig(cfg, configPath, "balanced"); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permission = %o, want 600", perm)
	}
}

func TestInitResult_JSONRoundTrip(t *testing.T) {
	result := &initResult{
		Discover: &initDiscoverResult{
			ClientsFound: 2,
			ServersFound: 5,
			Protected:    3,
			Unprotected:  2,
		},
		Setup: &initSetupResult{
			ConfigPath: "/home/user/.config/pipelock/pipelock.yaml",
			Preset:     "balanced",
			Written:    true,
		},
		Verify: &initVerifyResult{
			Passed: 4,
			Failed: 0,
		},
		Canary: &initCanaryResult{
			Detected: true,
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded initResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Discover.ClientsFound != 2 {
		t.Errorf("ClientsFound = %d, want 2", decoded.Discover.ClientsFound)
	}
	if decoded.Setup.Preset != "balanced" {
		t.Errorf("Preset = %q, want balanced", decoded.Setup.Preset)
	}
}
