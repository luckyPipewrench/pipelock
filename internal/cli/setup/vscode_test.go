// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testOriginalCmd    = "npx"
	testTypeHTTP       = "http" // VS Code MCP server type for HTTP upstream
	testTypeStdio      = "stdio"
	testExampleURL     = "https://api.example.com/mcp"
	testNodeCmd        = "node"
	testBearerTok      = "Bearer " + "vs-tok" // retained for the secret-rejection test below
	testWorkspaceHdr   = "X-Workspace-Id"
	testWorkspaceValue = "ws-vs-tok"

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
      "headers": { "X-Workspace-Id": "ws-vs-tok" }
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

	// Server with missing command -- should trigger wrap warning and skip.
	testBadStdioConfig = `{
  "servers": {
    "broken": {
      "type": "stdio"
    }
  }
}`

	// Null servers field -- exercises nil server map init path.
	testNullServersConfig = `{"servers": null}`

	// Invalid JSON -- exercises parse error path.
	testInvalidJSON  = `{not json`
	testNoTypeConfig = `{
  "servers": {
    "implicit": {
      "command": "npx",
      "args": ["-y", "@example/server"]
    }
  }
}`
)

// testHTTPConfigSecretHeader is built at init to keep gosec G101 from
// flagging the fixture as a hardcoded credential. The token value is split.
var testHTTPConfigSecretHeader = `{
  "servers": {
    "remote": {
      "type": "http",
      "url": "https://api.example.com/mcp",
      "headers": { "Authorization": "` + testBearerTok + `" }
    }
  }
}`

func TestVscodeInstall_DryRun(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project", "--dry-run"})
	// Run from the temp dir so --project finds .vscode/mcp.json.
	chdirTemp(t, dir)

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

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	chdirTemp(t, dir)

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
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testHTTPConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	chdirTemp(t, dir)

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
	// Header values now travel via a 0o600 sidecar referenced through
	// --header-file, never in argv. The wrapped argv must not contain the
	// header value; the sidecar file must contain the "Key: Value" line.
	sidecarPath := ""
	for i, a := range args {
		if a == mcpFlagHeaderFile && i+1 < len(args) {
			sidecarPath = args[i+1]
			break
		}
	}
	if sidecarPath == "" {
		t.Fatalf("wrapped argv missing --header-file flag: %v", args)
	}
	if hasAdjacentArg(args, mcpFlagHeader, testWorkspaceHdr+": "+testWorkspaceValue) {
		t.Errorf("header value leaked into argv via --header; sidecar must be the only carrier")
	}
	body, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if !strings.Contains(string(body), testWorkspaceHdr+": "+testWorkspaceValue) {
		t.Errorf("sidecar missing %q line: %q", testWorkspaceHdr, body)
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
	if meta.OriginalHeaders[testWorkspaceHdr] != testWorkspaceValue {
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

	chdirTemp(t, dir)

	// First install.
	cmd1 := VscodeCmd()
	cmd1.SetArgs([]string{"install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	first, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}

	// Second install.
	cmd2 := VscodeCmd()
	cmd2.SetArgs([]string{"install", "--project"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second install failed: %v", err)
	}
	second, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}

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

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}
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

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
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

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
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

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
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

	chdirTemp(t, dir)

	// Install first.
	cmd1 := VscodeCmd()
	cmd1.SetArgs([]string{"install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	// Remove.
	cmd2 := VscodeCmd()
	cmd2.SetArgs([]string{"remove", "--project"})
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

	// stdio-srv should be restored.
	stdioSrv := cfg.Servers["stdio-srv"]
	if _, ok := stdioSrv["_pipelock"]; ok {
		t.Error("_pipelock metadata should be removed after unwrap")
	}
	srvCmd, _ := stdioSrv["command"].(string)
	if srvCmd != testNodeCmd {
		t.Errorf("expected original command 'node', got %q", srvCmd)
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

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	// File should be unchanged (0 unwrapped).
	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}
	var cfg vscodeMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	server := cfg.Servers["my-server"]
	srvCmd, _ := server["command"].(string)
	if srvCmd != testOriginalCmd {
		t.Error("remove modified an unwrapped server")
	}
}

func TestVscodeRemove_NoFile(t *testing.T) {
	dir := t.TempDir()

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove with no file should not error: %v", err)
	}
}

func TestVscodeInstall_MutuallyExclusiveFlags(t *testing.T) {
	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--global", "--project"})
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

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project", "--config", "/etc/pipelock.yaml"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install with --config failed: %v", err)
	}

	data, readErr := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	var cfg vscodeMCPConfig
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

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

func TestVscodeInstall_WithRelativeConfigPersistsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "relative.yaml"), []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project", "--config", "relative.yaml"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install with relative --config failed: %v", err)
	}

	data, readErr := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	var cfg vscodeMCPConfig
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

	args := interfaceSliceToStrings(cfg.Servers["my-server"]["args"])
	if !hasAdjacentArg(args, "--config", filepath.Join(dir, "relative.yaml")) {
		t.Errorf("relative --config was not persisted as absolute path: %v", args)
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
	wrapped, _, _, err := wrapVscodeServer(server, exePath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	srvCmd, _ := wrapped["command"].(string)
	if srvCmd != exePath {
		t.Errorf("expected raw path %q, got %q (should not be shell-quoted)", exePath, srvCmd)
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

	chdirTemp(t, dir)

	// Install.
	cmd1 := VscodeCmd()
	cmd1.SetArgs([]string{"install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	// Remove.
	cmd2 := VscodeCmd()
	cmd2.SetArgs([]string{"remove", "--project"})
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
	srvCmd, _ := server["command"].(string)
	if srvCmd != testOriginalCmd {
		t.Errorf("expected command 'npx', got %q", srvCmd)
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

	chdirTemp(t, dir)

	// Install first.
	cmd1 := VscodeCmd()
	cmd1.SetArgs([]string{"install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	installed, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}

	// Remove with dry-run.
	cmd2 := VscodeCmd()
	cmd2.SetArgs([]string{"remove", "--project", "--dry-run"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("remove --dry-run failed: %v", err)
	}

	// File should not have changed.
	after, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(installed) {
		t.Error("dry-run modified the file")
	}
}

func TestVscodeRemove_MutuallyExclusiveFlags(t *testing.T) {
	cmd := VscodeCmd()
	cmd.SetArgs([]string{"remove", "--global", "--project"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error with both --global and --project")
	}
}

func TestWrapVscodeServer_MissingCommand(t *testing.T) {
	server := map[string]interface{}{
		"type": testTypeStdio,
		// No command field.
	}
	_, _, _, err := wrapVscodeServer(server, "/usr/bin/pipelock", "", "", "")
	if err == nil {
		t.Error("expected error for stdio server missing command")
	}
}

func TestWrapVscodeServer_MissingURL(t *testing.T) {
	server := map[string]interface{}{
		"type": testTypeHTTP,
		// No url field.
	}
	_, _, _, err := wrapVscodeServer(server, "/usr/bin/pipelock", "", "", "")
	if err == nil {
		t.Error("expected error for http server missing url")
	}
}

// TestVscodeInstall_SecretHeaderRoutesThroughSidecar locks in that install
// accepts credential-bearing headers because the values land in a 0o600
// sidecar file referenced via --header-file, not in the wrapped argv. The
// wrapped argv carries the sidecar path; the sidecar contents carry the
// `Authorization: Bearer ...` line.
func TestVscodeInstall_SecretHeaderRoutesThroughSidecar(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testHTTPConfigSecretHeader), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sidecar dir lives under HOME; point it at a tempdir so the assertion
	// can read the sidecar back without touching the operator's real config.
	t.Setenv("HOME", dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	chdirTemp(t, dir)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install with credential header should succeed via sidecar, got: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}
	var cfg vscodeMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	entry := cfg.Servers["remote"]
	if _, wrapped := entry["_pipelock"]; !wrapped {
		t.Fatal("entry must be wrapped via the sidecar path")
	}
	args := interfaceSliceToStrings(entry["args"])

	// Wrapped argv must NOT contain the credential value anywhere.
	for _, a := range args {
		if strings.Contains(a, testBearerTok) {
			t.Fatalf("credential value leaked into wrapped argv: %v", args)
		}
		if strings.EqualFold(a, "Authorization") {
			t.Fatalf("Authorization header name leaked into wrapped argv as a flag value: %v", args)
		}
	}

	// Wrapped argv must reference the sidecar file via --header-file.
	sidecarPath := ""
	for i, a := range args {
		if a == mcpFlagHeaderFile && i+1 < len(args) {
			sidecarPath = args[i+1]
			break
		}
	}
	if sidecarPath == "" {
		t.Fatalf("wrapped argv missing --header-file flag: %v", args)
	}

	// Sidecar must be 0o600 and contain the credential line.
	info, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatalf("sidecar not written at %s: %v", sidecarPath, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar mode = %04o, want 0o600", info.Mode().Perm())
	}
	body, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Authorization: "+testBearerTok) {
		t.Errorf("sidecar content missing the Authorization line: %q", body)
	}

	// Sidecar dir must be 0o700 so other local users cannot enumerate.
	dirInfo, err := os.Stat(filepath.Dir(sidecarPath))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("sidecar dir mode = %04o, want 0o700", dirInfo.Mode().Perm())
	}
}

func TestWrapVscodeServer_SSEType(t *testing.T) {
	server := map[string]interface{}{
		"type": "sse",
		"url":  "https://example.com/sse",
	}
	wrapped, meta, _, err := wrapVscodeServer(server, "/usr/bin/pipelock", "", "", "")
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
	result, _, err := unwrapVscodeServer(server)
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

	result, _, err := unwrapVscodeServer(server)
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

func TestUnwrapVscodeServer_HeaderSidecarDeletePathValidated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sidecarPath, err := headerSidecarPath(filepath.Join(home, ".vscode", "mcp.json"), "remote")
	if err != nil {
		t.Fatal(err)
	}

	server := map[string]interface{}{
		"type":    vsTypeStdio,
		"command": "/usr/bin/pipelock",
		"args":    []interface{}{"mcp", "proxy", "--header-file", sidecarPath, "--upstream", testExampleURL},
		"_pipelock": map[string]interface{}{
			"original_type":       testTypeHTTP,
			"original_url":        testExampleURL,
			"header_sidecar_path": sidecarPath,
		},
	}

	_, plan, err := unwrapVscodeServer(server)
	if err != nil {
		t.Fatalf("unwrapVscodeServer: %v", err)
	}
	if plan == nil {
		t.Fatal("expected sidecar delete plan")
	}
	if plan.kind != "delete" {
		t.Errorf("plan.kind = %q, want delete", plan.kind)
	}
	if plan.path != sidecarPath {
		t.Errorf("plan.path = %q, want %q", plan.path, sidecarPath)
	}
}

func TestUnwrapVscodeServer_RejectsEscapingHeaderSidecarPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	outside := filepath.Join(home, "victim.headers")

	server := map[string]interface{}{
		"_pipelock": map[string]interface{}{
			"original_type":       testTypeHTTP,
			"original_url":        testExampleURL,
			"header_sidecar_path": outside,
		},
	}

	_, _, err := unwrapVscodeServer(server)
	if err == nil {
		t.Fatal("expected escaping header sidecar path to be rejected")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("unwrap error = %q, want escape rejection", err.Error())
	}
}

func TestUnwrapVscodeServer_RejectsSymlinkEscapingHeaderSidecarPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir, err := headerSidecarDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	escapedPath := filepath.Join(link, "victim.headers")
	if err := os.WriteFile(escapedPath, []byte("X-Test: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := map[string]interface{}{
		"_pipelock": map[string]interface{}{
			"original_type":       testTypeHTTP,
			"original_url":        testExampleURL,
			"header_sidecar_path": escapedPath,
		},
	}

	_, _, err = unwrapVscodeServer(server)
	if err == nil {
		t.Fatal("expected symlink-escaping header sidecar path to be rejected")
	}
	if !strings.Contains(err.Error(), "resolves outside") {
		t.Fatalf("unwrap error = %q, want symlink escape rejection", err.Error())
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

	result, _, err := unwrapVscodeServer(server)
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
	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--global", "--dry-run"})
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

	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("stat failed: %v", statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestVscodeAtomicWrite_BadDir(t *testing.T) {
	// Writing to a non-existent temp dir should fail.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	err := vscodeAtomicWrite(filepath.Join(missing, "test.json"), []byte("{}"), missing)
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

func TestVscodeInstall_SkipsBadServer(t *testing.T) {
	// Server missing command should be skipped with a warning, not fail install.
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testBadStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install should not fail for bad server: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(vsDir, "mcp.json")))
	if err != nil {
		t.Fatal(err)
	}
	var cfg vscodeMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

	// Server should not be wrapped (no _pipelock metadata).
	if _, ok := cfg.Servers["broken"]["_pipelock"]; ok {
		t.Error("broken server should not have been wrapped")
	}
}

func TestVscodeInstall_NullServers(t *testing.T) {
	// "servers": null should be treated as empty.
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testNullServersConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install with null servers failed: %v", err)
	}
}

func TestVscodeInstall_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testInvalidJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestVscodeRemove_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testInvalidJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuildEnvFlags(t *testing.T) {
	// Server with env vars should produce --env flags.
	server := map[string]interface{}{
		"env": map[string]interface{}{
			"FOO": "bar",
			"BAZ": "qux",
		},
	}
	flags := buildEnvFlags(server)
	if len(flags) != 4 { // 2 keys * 2 (--env KEY)
		t.Errorf("expected 4 flag elements, got %d: %v", len(flags), flags)
	}

	// Server with no env should return nil.
	noEnv := map[string]interface{}{}
	if flags := buildEnvFlags(noEnv); flags != nil {
		t.Errorf("expected nil for no env, got %v", flags)
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

func TestUnwrapVscodeServer_InvalidMeta_MissingCommand(t *testing.T) {
	server := map[string]interface{}{
		"_pipelock": map[string]interface{}{
			"original_type": testTypeStdio,
			// Missing original_command.
		},
	}
	_, _, err := unwrapVscodeServer(server)
	if err == nil {
		t.Error("expected error for missing original_command")
	}
}

func TestUnwrapVscodeServer_InvalidMeta_MissingURL(t *testing.T) {
	server := map[string]interface{}{
		"_pipelock": map[string]interface{}{
			"original_type": testTypeHTTP,
			// Missing original_url.
		},
	}
	_, _, err := unwrapVscodeServer(server)
	if err == nil {
		t.Error("expected error for missing original_url")
	}
}

func TestUnwrapVscodeServer_InvalidMeta_MissingType(t *testing.T) {
	server := map[string]interface{}{
		"_pipelock": map[string]interface{}{
			// Missing original_type entirely.
		},
	}
	_, _, err := unwrapVscodeServer(server)
	if err == nil {
		t.Error("expected error for missing original_type")
	}
}

func TestMarshalVscodeConfig_WithInputs(t *testing.T) {
	// Exercise the cfg.Inputs != nil path.
	inputs := json.RawMessage(`[{"type":"promptString","id":"key"}]`)
	cfg := &vscodeMCPConfig{
		Inputs:  inputs,
		Servers: map[string]map[string]interface{}{},
	}
	original := []byte(`{"servers":{},"inputs":[]}`)
	data, err := marshalVscodeConfig(original, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["inputs"]; !ok {
		t.Error("inputs should be present in output")
	}
}

func TestMarshalVscodeConfig_BadOriginalJSON(t *testing.T) {
	// Invalid original data should fall through to marshal-from-scratch.
	cfg := &vscodeMCPConfig{
		Servers: map[string]map[string]interface{}{
			"test": {"type": testTypeStdio, "command": testNodeCmd},
		},
	}
	data, err := marshalVscodeConfig([]byte(`{broken`), cfg)
	if err != nil {
		t.Fatalf("should fall through to scratch marshal: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestVscodeAtomicWrite_ReadOnlyDir(t *testing.T) {
	// Write to a read-only directory should fail on chmod or rename.
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(roDir, 0o750); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(roDir, "test.json")
	// Write initial file so rename target exists.
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Make dir read-only so CreateTemp fails.
	if err := os.Chmod(roDir, 0o500); err != nil { //nolint:gosec // test: need read-only dir
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) }) //nolint:gosec // test: restore dir

	err := vscodeAtomicWrite(target, []byte(`{"new":true}`), roDir)
	if err == nil {
		t.Error("expected error writing to read-only dir")
	}
}

func TestVscodeInstall_ReadErrorOnExistingFile(t *testing.T) {
	// A file that exists but can't be read (permissions) should error.
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	mcpPath := filepath.Join(vsDir, "mcp.json")
	if err := os.WriteFile(mcpPath, []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	// Make unreadable.
	if err := os.Chmod(mcpPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mcpPath, 0o600) })

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for unreadable file")
	}
}

func TestVscodeRemove_ReadErrorOnExistingFile(t *testing.T) {
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	mcpPath := filepath.Join(vsDir, "mcp.json")
	if err := os.WriteFile(mcpPath, []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mcpPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mcpPath, 0o600) })

	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for unreadable file")
	}
}

func TestVscodeInstall_BackupWriteError(t *testing.T) {
	// Existing file + read-only dir should fail on backup write.
	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vsDir, "mcp.json"), []byte(testStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	// First install works (creates backup).
	cmd1 := VscodeCmd()
	cmd1.SetArgs([]string{"install", "--project"})
	if err := cmd1.Execute(); err != nil {
		t.Fatal(err)
	}

	// Make .bak read-only and dir read-only so backup write fails on next install.
	bakPath := filepath.Join(vsDir, "mcp.json.bak")
	if err := os.Chmod(bakPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vsDir, 0o500); err != nil { //nolint:gosec // test: need read-only dir
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(vsDir, 0o700) //nolint:gosec // test: restore dir
		_ = os.Chmod(bakPath, 0o600)
	})

	// Remove should try to backup and fail.
	cmd2 := VscodeCmd()
	cmd2.SetArgs([]string{"remove", "--project"})
	// May or may not error depending on OS behavior, but exercises the path.
	_ = cmd2.Execute()
}

func TestWrapVscodeServer_PreservesExtraFields(t *testing.T) {
	// Unknown fields like sandbox, envFile should pass through.
	server := map[string]interface{}{
		"type":           testTypeStdio,
		"command":        testOriginalCmd,
		"args":           []interface{}{"-y", "@example/server"},
		"sandboxEnabled": true,
		"envFile":        "${workspaceFolder}/.env",
	}
	wrapped, _, _, err := wrapVscodeServer(server, "/usr/bin/pipelock", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if wrapped["sandboxEnabled"] != true {
		t.Error("sandboxEnabled not preserved")
	}
	if wrapped["envFile"] != "${workspaceFolder}/.env" {
		t.Error("envFile not preserved")
	}
}

// ---------------------------------------------------------------------------
// vscodeAtomicWrite — overwrite existing file test
// ---------------------------------------------------------------------------

func TestVscodeAtomicWrite_OverwriteExisting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	targetPath := filepath.Join(dir, "mcp.json")

	// Write initial content to be overwritten.
	if err := os.WriteFile(targetPath, []byte(`{"old":"data"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	newData := []byte(`{"servers":{"new":"data"}}` + "\n")
	if err := vscodeAtomicWrite(targetPath, newData, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(targetPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newData) {
		t.Errorf("overwrite failed: got %q, want %q", string(got), string(newData))
	}
}

// listVscodeSidecarFiles returns entries in the sidecar dir under home, or
// nil if the dir is absent. Tests use this to assert dry-run never lands a
// sidecar on disk.
func listVscodeSidecarFiles(t *testing.T, home string) []string {
	t.Helper()
	dir := filepath.Join(home, ".config", "pipelock", "wrap-headers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading sidecar dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestVscodeInstall_DryRunWithHeadersCreatesNoSidecar locks in that --dry-run
// is read-only across both the canonical config AND the operator-private
// header sidecar dir. A dry-run that wrote a sidecar would leak the
// operator's Authorization value to disk without their consent.
func TestVscodeInstall_DryRunWithHeadersCreatesNoSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(vsDir, "mcp.json")
	if err := os.WriteFile(cfgPath, []byte(testHTTPConfigSecretHeader), 0o600); err != nil {
		t.Fatal(err)
	}
	chdirTemp(t, dir)

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"install", "--project", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testHTTPConfigSecretHeader {
		t.Error("dry-run modified the canonical config file")
	}

	if files := listVscodeSidecarFiles(t, home); len(files) > 0 {
		t.Errorf("dry-run wrote sidecar(s) to disk: %v", files)
	}
}

// TestVscodeRemove_DryRunPreservesSidecar locks in that --dry-run on remove
// does NOT delete a wrapped server's header sidecar. A dry-run that deleted
// the sidecar would put the agent into a broken state since the still-wrapped
// argv references a --header-file path that no longer exists.
func TestVscodeRemove_DryRunPreservesSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := t.TempDir()
	vsDir := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(vsDir, "mcp.json")
	if err := os.WriteFile(cfgPath, []byte(testHTTPConfigSecretHeader), 0o600); err != nil {
		t.Fatal(err)
	}
	chdirTemp(t, dir)

	// Install first so a real sidecar lands on disk.
	installCmd := VscodeCmd()
	installCmd.SetArgs([]string{"install", "--project"})
	if err := installCmd.Execute(); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	files := listVscodeSidecarFiles(t, home)
	if len(files) != 1 {
		t.Fatalf("expected one sidecar after install, got %d (%v)", len(files), files)
	}
	sidecarPath := filepath.Join(home, ".config", "pipelock", "wrap-headers", files[0])
	sidecarBefore, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("read sidecar before remove: %v", err)
	}
	cfgBefore, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}

	// remove --dry-run must touch neither the canonical config nor the sidecar.
	removeCmd := VscodeCmd()
	removeCmd.SetArgs([]string{"remove", "--project", "--dry-run"})
	if err := removeCmd.Execute(); err != nil {
		t.Fatalf("remove --dry-run failed: %v", err)
	}

	cfgAfter, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cfgAfter, cfgBefore) {
		t.Error("remove --dry-run modified the canonical config")
	}

	sidecarAfter, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("remove --dry-run deleted the sidecar: %v", err)
	}
	if !bytes.Equal(sidecarAfter, sidecarBefore) {
		t.Error("remove --dry-run mutated the sidecar contents")
	}
}

// TestHeaderSidecarPath_DistinguishesSanitizedNameCollisions locks in that
// attacker-controlled server names cannot collide after path-component
// sanitization. Without the raw-name hash, "prod/api" and "prod_api" would
// share one sidecar path and whichever install wrote last would determine the
// headers used by both wrapped servers.
func TestHeaderSidecarPath_DistinguishesSanitizedNameCollisions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configPath := filepath.Join(home, ".cline", "mcp.json")

	slashed, err := headerSidecarPath(configPath, "prod/api")
	if err != nil {
		t.Fatal(err)
	}
	underscored, err := headerSidecarPath(configPath, "prod_api")
	if err != nil {
		t.Fatal(err)
	}
	if slashed == underscored {
		t.Fatalf("sanitized server-name collision produced one sidecar path: %s", slashed)
	}
	if strings.Contains(filepath.Base(slashed), "/") || strings.Contains(filepath.Base(underscored), "/") {
		t.Fatalf("sidecar filename contains a path separator: %q / %q", filepath.Base(slashed), filepath.Base(underscored))
	}

	longName := strings.Repeat("a", 512)
	longPath, err := headerSidecarPath(configPath, longName)
	if err != nil {
		t.Fatal(err)
	}
	if len(filepath.Base(longPath)) > 128 {
		t.Fatalf("sidecar filename too long: %d bytes (%q)", len(filepath.Base(longPath)), filepath.Base(longPath))
	}
}

func TestValidatedHeaderSidecarDeletePath_FailClosedBranches(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir, err := headerSidecarDir()
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "valid.headers")

	got, err := validatedHeaderSidecarDeletePath("")
	if err != nil {
		t.Fatalf("empty path returned error: %v", err)
	}
	if got != "" {
		t.Fatalf("empty path = %q, want empty", got)
	}

	for _, tt := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "relative rejected",
			path: filepath.Join("relative", "valid.headers"),
			want: "must be absolute",
		},
		{
			name: "wrong suffix rejected",
			path: filepath.Join(dir, "valid.txt"),
			want: "must end in .headers",
		},
		{
			name: "sidecar dir itself rejected",
			path: dir,
			want: "must end in .headers",
		},
		{
			name: "parent escape rejected",
			path: filepath.Join(dir, "..", "victim.headers"),
			want: "escapes",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := validatedHeaderSidecarDeletePath(tt.path); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validatedHeaderSidecarDeletePath(%q) err = %v, want containing %q", tt.path, err, tt.want)
			}
		})
	}

	got, err = validatedHeaderSidecarDeletePath(inside)
	if err != nil {
		t.Fatalf("inside missing path returned error: %v", err)
	}
	if got != inside {
		t.Fatalf("inside missing path = %q, want %q", got, inside)
	}

	if pathWithinDir(dir, dir) {
		t.Fatal("pathWithinDir accepted the directory itself")
	}
}

func TestExtractHeaderLines_ValueValidationMatchesRuntime(t *testing.T) {
	server := map[string]interface{}{
		"headers": map[string]interface{}{
			"X-Display-Name": "Cafe\u00e9",
		},
	}
	lines, err := extractHeaderLines(server)
	if err != nil {
		t.Fatalf("extractHeaderLines accepted runtime-valid non-ASCII value: %v", err)
	}
	if len(lines) != 1 || lines[0] != "X-Display-Name: Cafe\u00e9" {
		t.Fatalf("extractHeaderLines = %v, want non-ASCII header line", lines)
	}

	server = map[string]interface{}{
		"headers": map[string]interface{}{
			"X-Display-Name": "Cafe\u2003hidden",
		},
	}
	if _, err := extractHeaderLines(server); err == nil {
		t.Fatal("expected unicode whitespace in header value to be rejected")
	}
}

// TestApplySidecarOps_RollsBackOnPartialWriteFailure locks in that a sidecar
// write plan is atomic from the caller's perspective: if any write in the
// plan fails, every previously-written sidecar from the same plan is
// removed before the error returns. Without this guarantee, a multi-server
// install could leave operator credentials on disk for servers whose wrap
// completed before a later server's wrap failed.
func TestApplySidecarOps_RollsBackOnPartialWriteFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	first, err := headerSidecarPath(filepath.Join(home, "a", "mcp.json"), "first")
	if err != nil {
		t.Fatal(err)
	}

	// Second op writes through /dev/null/, which is not a directory. The
	// write will fail when commitHeaderSidecar tries os.MkdirAll on the
	// parent. /dev/null/ is platform-stable enough for the test's purposes
	// (every supported pipelock dev OS treats /dev/null as a character
	// device, not a directory).
	impossible := "/dev/null/wrap-headers/second.headers"

	ops := []sidecarOp{
		{kind: "write", path: first, body: []byte("X-One: a\n")},
		{kind: "write", path: impossible, body: []byte("X-Two: b\n")},
	}

	if err := applySidecarOps(ops); err == nil {
		_ = os.Remove(first)
		t.Fatal("expected applySidecarOps to fail on the second (impossible) write")
	}

	if _, statErr := os.Stat(first); !os.IsNotExist(statErr) {
		t.Errorf("first sidecar was not rolled back after later failure: stat err=%v", statErr)
	}
}

// TestApplySidecarOps_DeletesNeverRollBackWrites covers the asymmetric path
// in applySidecarOps: delete ops are best-effort and a missing file is not
// an error, so they can never trigger the rollback path. A "delete" before a
// successful "write" must leave the written sidecar in place.
func TestApplySidecarOps_DeletesNeverRollBackWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	deletePath, err := headerSidecarPath(filepath.Join(home, "a", "mcp.json"), "delete-target")
	if err != nil {
		t.Fatal(err)
	}
	writePath, err := headerSidecarPath(filepath.Join(home, "b", "mcp.json"), "write-target")
	if err != nil {
		t.Fatal(err)
	}

	ops := []sidecarOp{
		{kind: "delete", path: deletePath},
		{kind: "write", path: writePath, body: []byte("X: 1\n")},
	}

	if err := applySidecarOps(ops); err != nil {
		t.Fatalf("applySidecarOps: %v", err)
	}

	body, err := os.ReadFile(filepath.Clean(writePath))
	if err != nil {
		t.Fatalf("expected the write to survive a preceding noop delete: %v", err)
	}
	if string(body) != "X: 1\n" {
		t.Errorf("write payload mismatch: got %q", body)
	}
}

// TestRollbackSidecarWrites_DeletesAllWrites locks in that the rollback
// helper invoked when the canonical config write fails removes every
// sidecar from the plan, leaving no orphaned credential files behind.
func TestRollbackSidecarWrites_DeletesAllWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	one, err := headerSidecarPath(filepath.Join(home, "a", "mcp.json"), "one")
	if err != nil {
		t.Fatal(err)
	}
	two, err := headerSidecarPath(filepath.Join(home, "b", "mcp.json"), "two")
	if err != nil {
		t.Fatal(err)
	}

	ops := []sidecarOp{
		{kind: "write", path: one, body: []byte("X-One: a\n")},
		{kind: "write", path: two, body: []byte("X-Two: b\n")},
	}
	if err := applySidecarOps(ops); err != nil {
		t.Fatalf("seed applySidecarOps: %v", err)
	}
	for _, p := range []string{one, two} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("seed sidecar missing: %v", err)
		}
	}

	rollbackSidecarWrites(ops)

	for _, p := range []string{one, two} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("sidecar %q survived rollback (err=%v)", p, err)
		}
	}
}
