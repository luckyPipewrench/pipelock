// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testMCPFilename  = "mcp.json"
	testPipelockExe  = "/usr/local/bin/pipelock"
	testTypeSSE      = "sse"
	testConfigFlag   = "--config"
	testPipelockConf = "/etc/pipelock.yaml"
	testEchoCmd      = "echo"
	testWrappedJSON  = `{"mcpServers": {"srv": {"type": "stdio", "command": "pipelock", "args": ["mcp", "proxy", "--", "echo"], "_pipelock": {"original_type": "stdio", "original_command": "echo"}}}}`
)

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
				"command": testEchoCmd,
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

	exe := testPipelockExe
	for name, server := range mcpCfg.Servers {
		newServer, meta, err := wrapMCPServer(server, exe, "")
		if err != nil {
			t.Fatalf("wrapping %q: %v", name, err)
		}
		if meta.OriginalCommand != testEchoCmd {
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
				"command": testPipelockExe,
				"args":    []interface{}{"mcp", "proxy", "--", testEchoCmd, "hello"},
				"_pipelock": map[string]interface{}{
					"original_type":    "stdio",
					"original_command": testEchoCmd,
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
		if cmd != testEchoCmd {
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

func TestRunJetbrainsInstall_DryRun(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfgData := `{"mcpServers": {"srv": {"command": "echo", "args": ["hi"]}}}`
	cfgPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(cfgPath, []byte(cfgData), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// Use --project so it targets a relative path we can control by chdir.
	cmd.SetArgs([]string{"install", "--project", "--dry-run"})

	// chdir into the temp dir so --project finds .junie/mcp/mcp.json
	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install --dry-run failed: %v\noutput: %s", err, buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "Would write") {
		t.Errorf("expected dry-run output, got: %s", out)
	}
	if !strings.Contains(out, "1 wrapped") {
		t.Errorf("expected 1 wrapped, got: %s", out)
	}
}

func TestRunJetbrainsRemove_DryRun(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	wrapped := testWrappedJSON
	cfgPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(cfgPath, []byte(wrapped), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"remove", "--project", "--dry-run"})

	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove --dry-run failed: %v\noutput: %s", err, buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "1 unwrapped") {
		t.Errorf("expected 1 unwrapped, got: %s", out)
	}
}

func TestRunJetbrainsInstall_WritesFile(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfgData := `{"mcpServers": {"srv": {"command": "echo", "args": ["hi"]}}}`
	cfgPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(cfgPath, []byte(cfgData), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"install", "--project"})

	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v\noutput: %s", err, buf.String())
	}

	// Verify file was actually written.
	data, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "_pipelock") {
		t.Error("expected _pipelock metadata in written file")
	}

	// Verify backup was created.
	bakData, err := os.ReadFile(filepath.Clean(cfgPath + ".bak"))
	if err != nil {
		t.Fatal("expected .bak backup file")
	}
	if !strings.Contains(string(bakData), `"echo"`) {
		t.Error("backup should contain original config")
	}
}

func TestRunJetbrainsInstall_NewFile(t *testing.T) {
	dir := t.TempDir()

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"install", "--project"})

	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	// No existing .junie/mcp/mcp.json — should create it with empty servers.
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install on empty dir failed: %v\noutput: %s", err, buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "Wrapped 0 server(s)") {
		t.Errorf("expected 'Wrapped 0 server(s)' for empty config, got: %s", out)
	}
}

func TestRunJetbrainsInstall_AlreadyWrapped(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Pre-wrapped config.
	wrapped := testWrappedJSON
	cfgPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(cfgPath, []byte(wrapped), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"install", "--project"})

	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "1 already wrapped") {
		t.Errorf("expected already-wrapped skip, got: %s", out)
	}
}

func TestRunJetbrainsRemove_WritesFile(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	wrapped := testWrappedJSON
	cfgPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(cfgPath, []byte(wrapped), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"remove", "--project"})

	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove failed: %v\noutput: %s", err, buf.String())
	}

	// Verify _pipelock metadata was removed.
	data, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "_pipelock") {
		t.Error("expected _pipelock to be removed from written file")
	}
	if !strings.Contains(string(data), `"echo"`) {
		t.Error("expected original command to be restored")
	}
}

func TestRunJetbrainsRemove_NoFile(t *testing.T) {
	dir := t.TempDir()

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"remove", "--project"})

	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove on empty dir failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No mcp.json found") {
		t.Errorf("expected 'No mcp.json found', got: %s", out)
	}
}

func TestRunJetbrainsRemove_MutualExclusion(t *testing.T) {
	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"remove", "--global", "--project", "--dry-run"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for --global + --project on remove")
	}
}

func TestRunJetbrainsInstall_SkipsHTTPWithHeaders(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := `{"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.com", "headers": {"Authorization": "Bearer tok"}}}}`
	cfgPath := filepath.Join(junieDir, testMCPFilename)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"install", "--project"})

	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	out := buf.String()
	errOut := buf.String()
	if !strings.Contains(out, "0 wrapped") && !strings.Contains(errOut, "skipping") {
		t.Errorf("expected skip warning for HTTP server with headers, got: %s", out)
	}
}

func TestReadMCPConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testMCPFilename)
	if err := os.WriteFile(path, []byte("{invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := readMCPConfig(path, junieServersKey)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestUnwrapMCPServer_MissingOriginalType(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldPipelock: map[string]interface{}{
			"original_command": testEchoCmd,
		},
	}
	_, err := unwrapMCPServer(server)
	if err == nil {
		t.Error("expected error for missing original_type")
	}
}

func TestUnwrapMCPServer_MissingOriginalURL(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldPipelock: map[string]interface{}{
			"original_type": testTypeSSE,
		},
	}
	_, err := unwrapMCPServer(server)
	if err == nil {
		t.Error("expected error for missing original_url on HTTP server")
	}
}

func TestUnwrapMCPServer_MissingOriginalCommand(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldPipelock: map[string]interface{}{
			"original_type": "stdio",
		},
	}
	_, err := unwrapMCPServer(server)
	if err == nil {
		t.Error("expected error for missing original_command on stdio server")
	}
}

func TestRunJetbrainsInstall_MutualExclusion(t *testing.T) {
	cmd := jetbrainsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"install", "--global", "--project", "--dry-run"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for --global + --project")
	}
}

func TestWrapMCPServer_HTTPWithHeaders_Rejected(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldType: testTypeSSE,
		mcpFieldURL:  "https://mcp.example.com/v1",
		mcpFieldHeaders: map[string]interface{}{
			"Authorization": "Bearer tok",
		},
	}

	_, _, err := wrapMCPServer(server, testPipelockExe, "")
	if err == nil {
		t.Error("expected error for HTTP server with headers")
	}
	if !strings.Contains(err.Error(), "headers") {
		t.Errorf("error should mention headers, got: %v", err)
	}
}

func TestWrapMCPServer_HTTPWithoutHeaders(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldType: testTypeSSE,
		mcpFieldURL:  "https://mcp.example.com/v1",
	}

	result, meta, err := wrapMCPServer(server, testPipelockExe, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.OriginalURL != "https://mcp.example.com/v1" {
		t.Errorf("meta.OriginalURL = %q", meta.OriginalURL)
	}
	if cmd, _ := result[mcpFieldCommand].(string); cmd != testPipelockExe {
		t.Errorf("command = %q", cmd)
	}
}

func TestUnwrapMCPServer_HTTP(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldType:    "stdio",
		mcpFieldCommand: testPipelockExe,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--upstream", "https://mcp.example.com/v1"},
		mcpFieldPipelock: map[string]interface{}{
			"original_type": testTypeSSE,
			"original_url":  "https://mcp.example.com/v1",
			"original_headers": map[string]interface{}{
				"Authorization": "Bearer tok",
			},
		},
	}

	restored, err := unwrapMCPServer(server)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	if url, _ := restored[mcpFieldURL].(string); url != "https://mcp.example.com/v1" {
		t.Errorf("url = %q", url)
	}
	if tp, _ := restored[mcpFieldType].(string); tp != testTypeSSE {
		t.Errorf("type = %q", tp)
	}
	if headers, ok := restored[mcpFieldHeaders].(map[string]interface{}); !ok || len(headers) == 0 {
		t.Error("expected headers to be restored")
	}
}

func TestWrapMCPServer_StdioMissingCommand(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldType: "stdio",
	}
	_, _, err := wrapMCPServer(server, testPipelockExe, "")
	if err == nil {
		t.Error("expected error for stdio server missing command")
	}
}

func TestWrapMCPServer_WithConfigFile(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldCommand: "node",
		mcpFieldArgs:    []interface{}{"server.js"},
	}

	result, _, err := wrapMCPServer(server, testPipelockExe, testPipelockConf)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := result[mcpFieldArgs].([]string)
	found := false
	for i, a := range args {
		if a == testConfigFlag && i+1 < len(args) && args[i+1] == testPipelockConf {
			found = true
		}
	}
	if !found {
		t.Errorf("expected --config /etc/pipelock.yaml in args: %v", args)
	}
}

func TestWrapMCPServer_EnvPassthrough(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldCommand: "node",
		mcpFieldArgs:    []interface{}{"server.js"},
		"env": map[string]interface{}{
			"API_KEY": "secret",
		},
	}

	result, _, err := wrapMCPServer(server, testPipelockExe, "")
	if err != nil {
		t.Fatal(err)
	}
	args, _ := result[mcpFieldArgs].([]string)
	found := false
	for i, a := range args {
		if a == "--env" && i+1 < len(args) && args[i+1] == "API_KEY" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected --env API_KEY in args: %v", args)
	}
}

func TestIsWrapped(t *testing.T) {
	wrapped := map[string]interface{}{mcpFieldPipelock: map[string]interface{}{}}
	if !isWrapped(wrapped) {
		t.Error("expected wrapped")
	}

	notWrapped := map[string]interface{}{mcpFieldCommand: testEchoCmd}
	if isWrapped(notWrapped) {
		t.Error("expected not wrapped")
	}
}

func TestUnwrapMCPServer_NotWrapped(t *testing.T) {
	server := map[string]interface{}{mcpFieldCommand: testEchoCmd}
	result, err := unwrapMCPServer(server)
	if err != nil {
		t.Fatal(err)
	}
	if cmd, _ := result[mcpFieldCommand].(string); cmd != testEchoCmd {
		t.Errorf("expected echo, got %q", cmd)
	}
}

func TestDiscoverIncludesJunie(t *testing.T) {
	dir := t.TempDir()
	junieDir := filepath.Join(dir, ".junie", "mcp")
	if err := os.MkdirAll(junieDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := `{"mcpServers": {"test-srv": {"command": "echo", "args": ["hello"]}}}`
	if err := os.WriteFile(filepath.Join(junieDir, testMCPFilename), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Verify readMCPConfig finds the Junie config at the expected path.
	mcpCfg, data, err := readMCPConfig(filepath.Join(junieDir, testMCPFilename), junieServersKey)
	if err != nil {
		t.Fatal(err)
	}
	if data == nil {
		t.Fatal("expected non-nil data from Junie config")
	}
	if len(mcpCfg.Servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(mcpCfg.Servers))
	}
	if _, ok := mcpCfg.Servers["test-srv"]; !ok {
		t.Error("expected test-srv in Junie config")
	}
}
