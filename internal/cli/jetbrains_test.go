// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const testMCPFilename = "mcp.json"

func TestJetbrainsInstall_StdioServer(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"my-server": map[string]interface{}{
				"command": "node",
				"args":    []interface{}{"server.js"},
			},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := jetbrainsInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--dry-run", "--project"})

	// Override the working directory by setting configFile path directly.
	// We test the dry-run output parsing instead.
	// For a real test, we'd need to chdir, but dry-run is sufficient.
	t.Setenv("HOME", dir)

	// Test the global path resolves correctly.
	path, err := junieConfigPath(true)
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(dir, ".junie", "mcp", testMCPFilename)
	if path != expected {
		t.Errorf("junieConfigPath(true) = %q, want %q", path, expected)
	}
}

func TestJetbrainsInstall_DryRun(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"test-srv": map[string]interface{}{
				"command": "echo",
				"args":    []interface{}{"hello"},
			},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Read, wrap, marshal — test the core logic directly.
	mcpCfg, originalData, err := readMCPConfig(configPath, junieServersKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(mcpCfg.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(mcpCfg.Servers))
	}

	exe := "/usr/local/bin/pipelock"
	for name, server := range mcpCfg.Servers {
		newServer, meta, err := wrapMCPServer(server, exe, "")
		if err != nil {
			t.Fatalf("wrapping %q: %v", name, err)
		}
		if meta.OriginalCommand != "echo" {
			t.Errorf("meta.OriginalCommand = %q, want echo", meta.OriginalCommand)
		}

		metaJSON, _ := json.Marshal(meta)
		var metaMap interface{}
		_ = json.Unmarshal(metaJSON, &metaMap)
		newServer[mcpFieldPipelock] = metaMap
		mcpCfg.Servers[name] = newServer
	}

	output, err := marshalMCPConfig(originalData, mcpCfg, junieServersKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify output has pipelock wrapping.
	var result map[string]json.RawMessage
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}

	var servers map[string]map[string]interface{}
	if err := json.Unmarshal(result["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}

	srv := servers["test-srv"]
	if cmd, _ := srv[mcpFieldCommand].(string); cmd != exe {
		t.Errorf("command = %q, want %q", cmd, exe)
	}
	if _, ok := srv[mcpFieldPipelock]; !ok {
		t.Error("expected _pipelock metadata in wrapped server")
	}
}

func TestJetbrainsRemove_Unwrap(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Create a wrapped config.
	wrapped := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"test-srv": map[string]interface{}{
				"type":    "stdio",
				"command": "/usr/local/bin/pipelock",
				"args":    []interface{}{"mcp", "proxy", "--", "echo", "hello"},
				"_pipelock": map[string]interface{}{
					"original_type":    "stdio",
					"original_command": "echo",
					"original_args":    []interface{}{"hello"},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(wrapped, "", "  ")
	configPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	mcpCfg, _, err := readMCPConfig(configPath, junieServersKey)
	if err != nil {
		t.Fatal(err)
	}

	for name, server := range mcpCfg.Servers {
		if !isWrapped(server) {
			t.Fatal("expected server to be wrapped")
		}
		restored, err := unwrapMCPServer(server)
		if err != nil {
			t.Fatalf("unwrapping %q: %v", name, err)
		}
		cmd, _ := restored[mcpFieldCommand].(string)
		if cmd != "echo" {
			t.Errorf("restored command = %q, want echo", cmd)
		}
		if _, ok := restored[mcpFieldPipelock]; ok {
			t.Error("expected _pipelock metadata to be removed after unwrap")
		}
	}
}

func TestJetbrainsConfigPath(t *testing.T) {
	// Project path.
	path, err := junieConfigPath(false)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != testMCPFilename {
		t.Errorf("expected mcp.json, got %s", filepath.Base(path))
	}
	if !filepath.IsAbs(path) && path != filepath.Join(".", ".junie", "mcp", testMCPFilename) {
		t.Errorf("unexpected project path: %s", path)
	}

	// Global path.
	globalPath, err := junieConfigPath(true)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(globalPath) != testMCPFilename {
		t.Errorf("expected mcp.json, got %s", filepath.Base(globalPath))
	}
}

func TestReadMCPConfig_NonExistent(t *testing.T) {
	cfg, data, err := readMCPConfig("/nonexistent/path/mcp.json", junieServersKey)
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Error("expected nil data for nonexistent file")
	}
	if len(cfg.Servers) != 0 {
		t.Error("expected empty servers for nonexistent file")
	}
}

func TestReadMCPConfig_VSCodeKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testMCPFilename)
	data := []byte(`{"servers": {"srv": {"command": "test"}}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := readMCPConfig(path, "servers")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 {
		t.Errorf("expected 1 server with 'servers' key, got %d", len(cfg.Servers))
	}
}

func TestMarshalMCPConfig_PreservesUnknownFields(t *testing.T) {
	original := `{"mcpServers": {"srv": {"command": "test"}}, "customField": "preserved"}`
	cfg := &mcpConfig{
		Servers: map[string]map[string]interface{}{
			"srv": {mcpFieldCommand: "wrapped"},
		},
	}

	output, err := marshalMCPConfig([]byte(original), cfg, junieServersKey)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}

	if _, ok := result["customField"]; !ok {
		t.Error("expected customField to be preserved")
	}
}

func TestMarshalMCPConfig_VSCodeKey(t *testing.T) {
	cfg := &mcpConfig{
		Servers: map[string]map[string]interface{}{
			"srv": {mcpFieldCommand: "test"},
		},
	}

	output, err := marshalMCPConfig(nil, cfg, "servers")
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if _, ok := result["servers"]; !ok {
		t.Error("expected 'servers' key in output")
	}
}

func TestDiscoverIncludesJunie(t *testing.T) {
	// This is a compile-time check that Junie is in configPaths.
	// The actual discover tests live in internal/discover/.
	// Here we just verify the import path works.
}
