// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const (
	testOriginalCmd = "npx"
	testTypeHTTP    = "http" // VS Code MCP server type for HTTP upstream
	testTypeStdio   = "stdio"
	testExampleURL  = "https://api.example.com/mcp"
	testNodeCmd     = "node"
	testBearerTok   = "Bearer " + "vs-tok"

	testStdioConfig = `{
  "servers": {
    "my-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@example/mcp-server"],
      "env": { "MY_VAR": "test" }
    }
  }
}`

	testHTTPConfig = `{
  "servers": {
    "remote": {
      "type": "http",
      "url": "https://api.example.com/mcp",
      "headers": { "Authorization": "Bearer vs-tok" }
    }
  }
}`

	testMixedConfig = `{
  "inputs": [{"type": "promptString", "id": "key", "description": "API Key"}],
  "servers": {
    "stdio-srv": {
      "type": "stdio",
      "command": "node",
      "args": ["server.js"]
    },
    "http-srv": {
      "type": "http",
      "url": "https://example.com/mcp"
    }
  }
}`

	testEmptyConfig  = `{"servers": {}}`
	testNoTypeConfig = `{
  "servers": {
    "implicit": {
      "command": "npx",
      "args": ["-y", "@example/server"]
    }
  }
}`
)

func TestVscodeInstall_DryRun(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project", "--dry-run"})
	// Run from the temp dir so --project finds .vscode/mcp.json.
	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	// File should not have changed.
	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != testStdioConfig {
		t.Error("dry-run modified the file")
	}
}

func TestVscodeInstall_StdioServer(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project"})
	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}

	var cfg vscodeMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing result: %v", err)
	}

	server, ok := cfg.Servers["my-server"]
	if !ok {
		t.Fatal("server 'my-server' not found in result")
	}

	// Should have _pipelock metadata.
	if _, ok := server["_pipelock"]; !ok {
		t.Error("missing _pipelock metadata")
	}

	// Should have "mcp" and "proxy" in args.
	args := interfaceSliceToStrings(server["args"])
	if len(args) < 4 {
		t.Fatalf("expected at least 4 args, got %d: %v", len(args), args)
	}
	if args[0] != "mcp" || args[1] != "proxy" {
		t.Errorf("expected args to start with 'mcp proxy', got %v", args[:2])
	}

	// Original command should appear after "--".
	dashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashIdx = i
			break
		}
	}
	if dashIdx < 0 {
		t.Fatal("no '--' separator in args")
	}
	if args[dashIdx+1] != testOriginalCmd {
		t.Errorf("expected original command 'npx' after '--', got %q", args[dashIdx+1])
	}

	// --env flags should be present before "--" for passthrough.
	foundEnvFlag := false
	for i, a := range args {
		if a == "--env" && i+1 < len(args) && args[i+1] == "MY_VAR" {
			foundEnvFlag = true
			break
		}
	}
	if !foundEnvFlag {
		t.Errorf("expected --env MY_VAR flag in args for env passthrough: %v", args)
	}

	// Env block should be preserved in JSON.
	env, ok := server["env"].(map[string]interface{})
	if !ok {
		t.Fatal("env not preserved")
	}
	if env["MY_VAR"] != "test" {
		t.Errorf("expected env key preserved, got %v", env["MY_VAR"])
	}
}

func TestVscodeInstall_HTTPServer(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testHTTPConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project"})
	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}

	var cfg vscodeMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing result: %v", err)
	}

	server := cfg.Servers["remote"]

	// HTTP servers should be converted to stdio with --upstream.
	serverType, _ := server["type"].(string)
	if serverType != "stdio" {
		t.Errorf("expected type stdio after wrapping, got %q", serverType)
	}

	args := interfaceSliceToStrings(server["args"])
	foundUpstream := false
	for i, a := range args {
		if a == "--upstream" && i+1 < len(args) {
			if args[i+1] != testExampleURL {
				t.Errorf("expected upstream URL, got %q", args[i+1])
			}
			foundUpstream = true
			break
		}
	}
	if !foundUpstream {
		t.Error("--upstream not found in args")
	}

	// Metadata should store original type and URL.
	metaRaw, ok := server["_pipelock"]
	if !ok {
		t.Fatal("missing _pipelock metadata")
	}
	metaJSON, _ := json.Marshal(metaRaw)
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.OriginalType != testTypeHTTP {
		t.Errorf("expected original_type=http, got %q", meta.OriginalType)
	}
	if meta.OriginalURL != testExampleURL {
		t.Errorf("expected original URL, got %q", meta.OriginalURL)
	}
	if meta.OriginalHeaders["Authorization"] != testBearerTok {
		t.Errorf("expected original headers preserved, got %v", meta.OriginalHeaders)
	}
}

func TestVscodeInstall_Idempotent(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	// First install.
	cmd1 := rootCmd()
	cmd1.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	first, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))

	// Second install.
	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second install failed: %v", err)
	}
	second, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))

	if string(first) != string(second) {
		t.Error("second install changed the file (not idempotent)")
	}
}

func TestVscodeInstall_PreservesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testMixedConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	// "inputs" should be preserved.
	if _, ok := raw["inputs"]; !ok {
		t.Error("inputs field was not preserved")
	}
}

func TestVscodeInstall_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	// No .vscode dir exists yet.

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project"})
	// Should succeed with empty config (no servers to wrap, but creates the file).
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".vscode", "mcp.json")); err != nil {
		t.Error("mcp.json was not created")
	}
}

func TestVscodeInstall_ImplicitStdioType(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testNoTypeConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	var cfg vscodeMCPConfig
	_ = json.Unmarshal(data, &cfg)

	server := cfg.Servers["implicit"]
	if _, ok := server["_pipelock"]; !ok {
		t.Error("server without explicit type should still be wrapped as stdio")
	}
}

func TestVscodeInstall_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	original := []byte(testStdioConfig)
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), original, 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	backup, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json.bak")))
	if err != nil {
		t.Fatal("backup file not created")
	}
	if string(backup) != string(original) {
		t.Error("backup content doesn't match original")
	}
}

func TestVscodeRemove_UnwrapsServers(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testMixedConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	// Install first.
	cmd1 := rootCmd()
	cmd1.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	// Remove.
	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"vscode", "remove", "--project"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	data, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	var cfg vscodeMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

	// stdio-srv should be restored.
	stdioSrv := cfg.Servers["stdio-srv"]
	if _, ok := stdioSrv["_pipelock"]; ok {
		t.Error("_pipelock metadata should be removed after unwrap")
	}
	cmd, _ := stdioSrv["command"].(string)
	if cmd != testNodeCmd {
		t.Errorf("expected original command 'node', got %q", cmd)
	}

	// http-srv should be restored.
	httpSrv := cfg.Servers["http-srv"]
	if _, ok := httpSrv["_pipelock"]; ok {
		t.Error("_pipelock metadata should be removed after unwrap")
	}
	srvType, _ := httpSrv["type"].(string)
	if srvType != testTypeHTTP {
		t.Errorf("expected type restored to 'http', got %q", srvType)
	}
	url, _ := httpSrv["url"].(string)
	if url != "https://example.com/mcp" {
		t.Errorf("expected original URL restored, got %q", url)
	}
}

func TestVscodeRemove_Idempotent(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// File with no pipelock wrapping.
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "remove", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	// File should be unchanged (0 unwrapped).
	data, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	var cfg vscodeMCPConfig
	_ = json.Unmarshal(data, &cfg)
	server := cfg.Servers["my-server"]
	cmd2, _ := server["command"].(string)
	if cmd2 != testOriginalCmd {
		t.Error("remove modified an unwrapped server")
	}
}

func TestVscodeRemove_NoFile(t *testing.T) {
	dir := t.TempDir()

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "remove", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove with no file should not error: %v", err)
	}
}

func TestVscodeInstall_MutuallyExclusiveFlags(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--global", "--project"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error with both --global and --project")
	}
}

func TestVscodeInstall_WithConfig(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--project", "--config", "/etc/pipelock.yaml"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install with --config failed: %v", err)
	}

	data, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	var cfg vscodeMCPConfig
	_ = json.Unmarshal(data, &cfg)

	args := interfaceSliceToStrings(cfg.Servers["my-server"]["args"])
	foundConfig := false
	for i, a := range args {
		if a == "--config" && i+1 < len(args) && args[i+1] == "/etc/pipelock.yaml" {
			foundConfig = true
			break
		}
	}
	if !foundConfig {
		t.Errorf("--config flag not passed through to wrapper args: %v", args)
	}
}

func TestVscodeInstall_SpacedExecutablePath(t *testing.T) {
	// Verify that command field contains the raw path, not shell-quoted.
	server := map[string]interface{}{
		"type":    "stdio",
		"command": "npx",
		"args":    []interface{}{"-y", "@example/server"},
	}

	exePath := "/path with spaces/to/pipelock"
	wrapped, _, err := wrapVscodeServer(server, exePath, "")
	if err != nil {
		t.Fatal(err)
	}

	cmd, _ := wrapped["command"].(string)
	if cmd != exePath {
		t.Errorf("expected raw path %q, got %q (should not be shell-quoted)", exePath, cmd)
	}
}

func TestVscodeInstall_ImplicitTypeRoundTrip(t *testing.T) {
	// A server without "type" should not have "type" after install+remove.
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testNoTypeConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	// Install.
	cmd1 := rootCmd()
	cmd1.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	// Remove.
	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"vscode", "remove", "--project"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}

	var cfg vscodeMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

	server := cfg.Servers["implicit"]

	// Should not have "type" field since the original omitted it.
	if _, hasType := server["type"]; hasType {
		t.Error("type field should not be present after round-trip (original omitted it)")
	}

	// Should still have the original command.
	cmd, _ := server["command"].(string)
	if cmd != testOriginalCmd {
		t.Errorf("expected command 'npx', got %q", cmd)
	}
}

func TestVscodeUserConfigPath(t *testing.T) {
	// Just verify it returns a non-empty path without error.
	path, err := vscodeUserConfigPath()
	if err != nil {
		t.Fatalf("vscodeUserConfigPath failed: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
	if filepath.Base(path) != "mcp.json" {
		t.Errorf("expected path ending in mcp.json, got %q", path)
	}
}

func TestVscodeRemove_DryRun(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	oldWD, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWD) }()

	// Install first.
	cmd1 := rootCmd()
	cmd1.SetArgs([]string{"vscode", "install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	installed, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))

	// Remove with dry-run.
	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"vscode", "remove", "--project", "--dry-run"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("remove --dry-run failed: %v", err)
	}

	// File should not have changed.
	after, _ := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if string(after) != string(installed) {
		t.Error("dry-run modified the file")
	}
}

func TestVscodeRemove_MutuallyExclusiveFlags(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "remove", "--global", "--project"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error with both --global and --project")
	}
}

func TestWrapVscodeServer_MissingCommand(t *testing.T) {
	server := map[string]interface{}{
		"type": testTypeStdio,
		// No command field.
	}
	_, _, err := wrapVscodeServer(server, "/usr/bin/pipelock", "")
	if err == nil {
		t.Error("expected error for stdio server missing command")
	}
}

func TestWrapVscodeServer_MissingURL(t *testing.T) {
	server := map[string]interface{}{
		"type": testTypeHTTP,
		// No url field.
	}
	_, _, err := wrapVscodeServer(server, "/usr/bin/pipelock", "")
	if err == nil {
		t.Error("expected error for http server missing url")
	}
}

func TestWrapVscodeServer_SSEType(t *testing.T) {
	server := map[string]interface{}{
		"type": "sse",
		"url":  "https://example.com/sse",
	}
	wrapped, meta, err := wrapVscodeServer(server, "/usr/bin/pipelock", "")
	if err != nil {
		t.Fatalf("wrap sse failed: %v", err)
	}
	if meta.OriginalType != "sse" {
		t.Errorf("expected original_type=sse, got %q", meta.OriginalType)
	}
	// Should be converted to stdio.
	if wrapped["type"] != vsTypeStdio {
		t.Errorf("expected wrapped type=stdio, got %v", wrapped["type"])
	}
}

func TestUnwrapVscodeServer_NoMeta(t *testing.T) {
	server := map[string]interface{}{
		"type":    testTypeStdio,
		"command": testNodeCmd,
	}
	result, err := unwrapVscodeServer(server)
	if err != nil {
		t.Fatal(err)
	}
	// Should return server unchanged.
	if result["command"] != testNodeCmd {
		t.Error("unwrap without metadata should return server as-is")
	}
}

func TestUnwrapVscodeServer_HTTPWithHeaders(t *testing.T) {
	server := map[string]interface{}{
		"type":    vsTypeStdio,
		"command": "/usr/bin/pipelock",
		"args":    []interface{}{"mcp", "proxy", "--upstream", testExampleURL},
		"_pipelock": map[string]interface{}{
			"original_type": testTypeHTTP,
			"original_url":  testExampleURL,
			"original_headers": map[string]interface{}{
				"Authorization": testBearerTok,
			},
		},
	}

	result, err := unwrapVscodeServer(server)
	if err != nil {
		t.Fatal(err)
	}

	if result["type"] != testTypeHTTP {
		t.Errorf("expected type=%s, got %v", testTypeHTTP, result["type"])
	}
	if result["url"] != testExampleURL {
		t.Errorf("expected url restored, got %v", result["url"])
	}
	headers, ok := result["headers"].(map[string]interface{})
	if !ok {
		t.Fatal("headers not restored")
	}
	if headers["Authorization"] != testBearerTok {
		t.Errorf("expected Authorization header restored, got %v", headers["Authorization"])
	}
	if _, ok := result["_pipelock"]; ok {
		t.Error("_pipelock metadata should be removed")
	}
}

func TestUnwrapVscodeServer_StdioNoArgs(t *testing.T) {
	// Stdio server with no original args should not have args after unwrap.
	server := map[string]interface{}{
		"type":    vsTypeStdio,
		"command": "/usr/bin/pipelock",
		"args":    []interface{}{"mcp", "proxy", "--", "node"},
		"_pipelock": map[string]interface{}{
			"original_type":    testTypeStdio,
			"original_command": testNodeCmd,
		},
	}

	result, err := unwrapVscodeServer(server)
	if err != nil {
		t.Fatal(err)
	}
	if result["command"] != testNodeCmd {
		t.Errorf("expected command=node, got %v", result["command"])
	}
	if _, ok := result["args"]; ok {
		t.Error("args should not be present when original had none")
	}
}

func TestInterfaceSliceToStrings_NonSlice(t *testing.T) {
	result := interfaceSliceToStrings("not a slice")
	if result != nil {
		t.Errorf("expected nil for non-slice input, got %v", result)
	}
}

func TestInterfaceSliceToStrings_MixedTypes(t *testing.T) {
	input := []interface{}{"hello", 42, "world", true}
	result := interfaceSliceToStrings(input)
	if len(result) != 2 || result[0] != "hello" || result[1] != "world" {
		t.Errorf("expected [hello world], got %v", result)
	}
}

func TestMarshalVscodeConfig_NoOriginalData(t *testing.T) {
	cfg := &vscodeMCPConfig{
		Servers: map[string]map[string]interface{}{
			"test": {"type": testTypeStdio, "command": testNodeCmd},
		},
	}
	data, err := marshalVscodeConfig(nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestVscodeInstall_Global(t *testing.T) {
	// Test --global path resolution (exercises vscodeConfigPath + vscodeUserConfigPath).
	cmd := rootCmd()
	cmd.SetArgs([]string{"vscode", "install", "--global", "--dry-run"})
	// Dry-run won't write, but exercises the path resolution.
	if err := cmd.Execute(); err != nil {
		t.Fatalf("global dry-run failed: %v", err)
	}
}

func TestVscodeAtomicWrite_HappyPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.json")
	data := []byte(`{"test": true}`)

	if err := vscodeAtomicWrite(target, data, dir); err != nil {
		t.Fatalf("atomic write failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}

	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestVscodeAtomicWrite_BadDir(t *testing.T) {
	// Writing to a non-existent temp dir should fail.
	err := vscodeAtomicWrite("/tmp/does-not-exist/test.json", []byte("{}"), "/tmp/does-not-exist")
	if err == nil {
		t.Error("expected error writing to non-existent dir")
	}
}

func TestMarshalVscodeConfig_PreservesUnknownTopLevel(t *testing.T) {
	original := []byte(`{"servers":{},"custom_field":"preserved","inputs":[]}`)
	cfg := &vscodeMCPConfig{
		Servers: map[string]map[string]interface{}{
			"test": {"type": testTypeStdio, "command": testNodeCmd},
		},
	}
	data, err := marshalVscodeConfig(original, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["custom_field"]; !ok {
		t.Error("custom_field was not preserved")
	}
}

func TestIsVscodeHTTPType(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{vsTypeStdio, false},
		{"", false},
		{testTypeHTTP, true},
		{"sse", true},
		{"grpc", true}, // unknown type treated as HTTP-style
	}
	for _, tt := range tests {
		if got := isVscodeHTTPType(tt.input); got != tt.want {
			t.Errorf("isVscodeHTTPType(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
