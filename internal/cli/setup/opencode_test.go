// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testOpenCodeLocalConfig = `{
  "mcp": {
    "my-server": {
      "type": "local",
      "command": ["npx", "-y", "@example/mcp-server"],
      "environment": { "MY_VAR": "test" }
    }
  }
}`

	testOpenCodeRemoteConfig = `{
  "mcp": {
    "remote": {
      "type": "remote",
      "url": "https://api.example.com/mcp",
      "headers": { "X-Workspace-Id": "ws-cli-tok" }
    }
  }
}`

	testOpenCodeWithUnknownField = `{
  "$schema": "https://opencode.ai/config.json",
  "theme": "system",
  "mcp": {
    "stdio-srv": {
      "type": "local",
      "command": ["node", "server.js"]
    }
  }
}`

	testOpenCodeNoMCP      = `{"theme":"system"}`
	testOpenCodeNullMCP    = `{"mcp": null}`
	testOpenCodeNoCmdNoURL = `{
  "mcp": {
    "broken": {
      "type": "local",
      "environment": { "FOO": "bar" }
    }
  }
}`

	testOpenCodeCommandAndURL = `{
  "mcp": {
    "ambiguous": {
      "type": "local",
      "command": ["node"],
      "url": "https://api.example.com/mcp"
    }
  }
}`
)

var testOpenCodeRemoteConfigSecretHeader = `{
  "mcp": {
    "remote": {
      "type": "remote",
      "url": "https://api.example.com/mcp",
      "headers": { "Authorization": "Bearer ` + "opencode-token" + `" }
    }
  }
}`

func writeOpenCodeFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, opencodeConfigFilename)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return p
}

func runOpenCodeCmd(t *testing.T, args ...string) error {
	t.Helper()
	_, _, err := runOpenCodeCmdOutput(t, args...)
	return err
}

func runOpenCodeCmdOutput(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := OpenCodeCmd()
	cmd.SetArgs(args)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func openCodeCommand(t *testing.T, server map[string]interface{}) []string {
	t.Helper()
	cmd, err := openCodeCommandToStrings(server[mcpFieldCommand])
	if err != nil {
		t.Fatalf("reading command array: %v", err)
	}
	return cmd
}

func TestOpenCodeInstall_DryRun(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeLocalConfig)

	if err := runOpenCodeCmd(t, "install", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("re-read after dry-run: %v", err)
	}
	if string(got) != testOpenCodeLocalConfig {
		t.Error("dry-run modified the file")
	}
}

func TestOpenCodeInstall_LocalServer(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeLocalConfig)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse result: %v", err)
	}

	server := cfg.Servers["my-server"]
	if _, ok := server[mcpFieldPipelock]; !ok {
		t.Error("missing _pipelock metadata after wrap")
	}
	if server[mcpFieldType] != opencodeTypeLocal {
		t.Errorf("wrapped server type = %v, want local", server[mcpFieldType])
	}
	cmd := openCodeCommand(t, server)
	if len(cmd) < 5 {
		t.Fatalf("expected wrapped command array, got %v", cmd)
	}
	if !filepath.IsAbs(cmd[0]) {
		t.Errorf("first command element should be an absolute pipelock binary path, got %q", cmd[0])
	}
	if cmd[1] != codexMCP || cmd[2] != codexMCPProxy {
		t.Errorf("expected mcp proxy prefix, got %v", cmd[:3])
	}
	if !hasAdjacentArg(cmd, codexFlagEnv, "MY_VAR") {
		t.Errorf("expected --env MY_VAR passthrough in command: %v", cmd)
	}
	dashIdx := -1
	for i, a := range cmd {
		if a == codexArgSeparator {
			dashIdx = i
			break
		}
	}
	if dashIdx < 0 {
		t.Fatal("no -- separator in wrapped command")
	}
	if got := cmd[dashIdx+1]; got != testOriginalCmd {
		t.Errorf("original command after -- = %q, want %q", got, testOriginalCmd)
	}

	env, ok := server[opencodeFieldEnvironment].(map[string]interface{})
	if !ok || env["MY_VAR"] != "test" {
		t.Errorf("environment block not preserved: %v", server[opencodeFieldEnvironment])
	}
}

func TestOpenCodeInstall_RemoteServerWithHeaderSidecar(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfig)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse result: %v", err)
	}

	server := cfg.Servers["remote"]
	cmd := openCodeCommand(t, server)
	if server[mcpFieldType] != opencodeTypeLocal {
		t.Errorf("remote wrapper type = %v, want local", server[mcpFieldType])
	}
	if !hasAdjacentArg(cmd, codexFlagUpstream, testExampleURL) {
		t.Errorf("wrapped command missing --upstream %q: %v", testExampleURL, cmd)
	}
	sidecarPath := ""
	for i, a := range cmd {
		if a == mcpFlagHeaderFile && i+1 < len(cmd) {
			sidecarPath = cmd[i+1]
			break
		}
	}
	if sidecarPath == "" {
		t.Fatalf("wrapped command missing --header-file flag: %v", cmd)
	}
	if hasAdjacentArg(cmd, mcpFlagHeader, "X-Workspace-Id: ws-cli-tok") {
		t.Fatalf("header value leaked into argv via --header: %v", cmd)
	}
	body, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if !strings.Contains(string(body), "X-Workspace-Id: ws-cli-tok") {
		t.Errorf("sidecar missing header line: %q", body)
	}
	info, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar mode = %04o, want 0o600", info.Mode().Perm())
	}

	metaJSON, _ := json.Marshal(server[mcpFieldPipelock])
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.OriginalType != opencodeTypeRemote {
		t.Errorf("OriginalType = %q, want remote", meta.OriginalType)
	}
	if meta.OriginalURL != testExampleURL {
		t.Errorf("OriginalURL = %q, want %q", meta.OriginalURL, testExampleURL)
	}
	if meta.OriginalHeaders["X-Workspace-Id"] != "ws-cli-tok" {
		t.Errorf("headers not preserved in metadata: %v", meta.OriginalHeaders)
	}
	if meta.HeaderSidecarPath != sidecarPath {
		t.Errorf("HeaderSidecarPath = %q, want %q", meta.HeaderSidecarPath, sidecarPath)
	}
}

func TestOpenCodeInstall_ConfigDiscoveryUsesAbsolutePath(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeLocalConfig)
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("pipelock.yaml", []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runOpenCodeCmd(t, "install", "--path", path, "--config", "pipelock.yaml"); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cmd := openCodeCommand(t, cfg.Servers["my-server"])
	want := filepath.Join(dir, "pipelock.yaml")
	if !hasAdjacentArg(cmd, codexFlagConfig, want) {
		t.Errorf("wrapped command missing absolute --config %q: %v", want, cmd)
	}
}

func TestOpenCodeInstall_Idempotent(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeLocalConfig)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("first install: %v", err)
	}
	firstRun, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("second install: %v", err)
	}
	secondRun, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if string(firstRun) != string(secondRun) {
		t.Errorf("install is not idempotent:\nfirst:\n%s\nsecond:\n%s", firstRun, secondRun)
	}
}

func TestOpenCodeInstall_PreservesUnknownTopLevelFields(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeWithUnknownField)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"theme"`) {
		t.Error("unknown top-level field 'theme' was dropped on install")
	}
	if !strings.Contains(string(data), opencodeSchemaURL) {
		t.Error("schema field was dropped on install")
	}
}

func TestOpenCodeInstall_CreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, opencodeConfigFilename)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install on missing file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected file to be created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected mode 0o600 on new file, got %o", info.Mode().Perm())
	}
}

func TestOpenCodeRemove_UnwrapsLocal(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeLocalConfig)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runOpenCodeCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	server := cfg.Servers["my-server"]
	if _, hasMeta := server[mcpFieldPipelock]; hasMeta {
		t.Error("_pipelock metadata not stripped after remove")
	}
	cmd := openCodeCommand(t, server)
	want := []string{testOriginalCmd, "-y", "@example/mcp-server"}
	if strings.Join(cmd, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("original command not restored: got %v, want %v", cmd, want)
	}
	if server[mcpFieldType] != opencodeTypeLocal {
		t.Errorf("type not restored: %v", server[mcpFieldType])
	}
}

func TestOpenCodeRemove_UnwrapsRemote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfig)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runOpenCodeCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	server := cfg.Servers["remote"]
	if server[mcpFieldType] != opencodeTypeRemote {
		t.Errorf("type = %v, want remote", server[mcpFieldType])
	}
	if server[mcpFieldURL] != testExampleURL {
		t.Errorf("url = %v, want %q", server[mcpFieldURL], testExampleURL)
	}
	headers, ok := server[mcpFieldHeaders].(map[string]interface{})
	if !ok || headers["X-Workspace-Id"] != "ws-cli-tok" {
		t.Errorf("headers not restored: %v", server[mcpFieldHeaders])
	}
}

func TestOpenCodeInstall_SecretHeaderRoutesThroughSidecar(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfigSecretHeader)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install with credential header should succeed via sidecar: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cmd := openCodeCommand(t, cfg.Servers["remote"])
	for _, a := range cmd {
		if strings.Contains(a, "opencode-token") {
			t.Fatalf("credential value leaked into wrapped command argv: %v", cmd)
		}
	}
	sidecarPath := ""
	for i, a := range cmd {
		if a == mcpFlagHeaderFile && i+1 < len(cmd) {
			sidecarPath = cmd[i+1]
			break
		}
	}
	if sidecarPath == "" {
		t.Fatalf("wrapped command missing --header-file: %v", cmd)
	}
	info, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar mode = %04o, want 0o600", info.Mode().Perm())
	}
}

func TestOpenCodeRemove_NoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")

	if err := runOpenCodeCmd(t, "remove", "--path", path); err != nil {
		t.Errorf("remove on missing file should be no-op, got: %v", err)
	}
}

func TestOpenCodeRemove_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, opencodeConfigFilename)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runOpenCodeCmd(t, "remove", "--path", path); err == nil {
		t.Error("expected remove to fail on invalid JSON")
	}
}

func TestOpenCodeRemove_BackupError(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeLocalConfig)
	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := os.Remove(path + ".bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".bak", 0o750); err != nil {
		t.Fatal(err)
	}

	if err := runOpenCodeCmd(t, "remove", "--path", path); err == nil {
		t.Error("expected remove to fail when backup path is a directory")
	}
}

func TestOpenCodeRemove_ReadError(t *testing.T) {
	dirPath := t.TempDir()

	if err := runOpenCodeCmd(t, "remove", "--path", dirPath); err == nil {
		t.Error("expected remove to fail when --path points at a directory")
	}
}

func TestOpenCodeRemove_WarnsAndSkipsInvalidWrappedEntry(t *testing.T) {
	path := writeOpenCodeFile(t, `{
  "mcp": {
    "bad": {
      "type": "local",
      "command": ["/usr/bin/pipelock", "mcp", "proxy"],
      "_pipelock": { "original_type": "local" }
    }
  }
}`)

	stdout, stderr, err := runOpenCodeCmdOutput(t, "remove", "--path", path)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(stdout, "No OpenCode servers were unwrapped") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "could not unwrap") {
		t.Errorf("stderr missing warning: %q", stderr)
	}
}

func TestOpenCodeRemove_SkipsNonWrappedEntry(t *testing.T) {
	original := `{
  // keep this comment on no-op remove
  "mcp": {
    "my-server": {
      "type": "local",
      "command": ["npx", "-y", "@example/mcp-server"]
    }
  }
}`
	path := writeOpenCodeFile(t, original)

	stdout, _, err := runOpenCodeCmdOutput(t, "remove", "--path", path)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(stdout, "No OpenCode servers were unwrapped") {
		t.Errorf("stdout = %q", stdout)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Error("no-op remove rewrote the config")
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-op remove created backup: %v", err)
	}
}

func TestOpenCodeRemove_AtomicWriteError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, opencodeConfigFilename)
	if err := os.WriteFile(path, []byte(testOpenCodeLocalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // directory needs execute bit; this test removes write permission
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // restore private test directory permissions
			t.Fatalf("restore dir mode: %v", err)
		}
	})

	if err := runOpenCodeCmd(t, "remove", "--path", path); err == nil {
		t.Error("expected remove to fail when atomic write cannot create a temp file")
	}
}

func TestOpenCodeInstall_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, opencodeConfigFilename)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runOpenCodeCmd(t, "install", "--path", path); err == nil {
		t.Error("expected install to fail on invalid JSON")
	}
}

func TestOpenCodeInstall_ReadError(t *testing.T) {
	dirPath := t.TempDir()

	if err := runOpenCodeCmd(t, "install", "--path", dirPath); err == nil {
		t.Error("expected install to fail when --path points at a directory")
	}
}

func TestOpenCodeInstall_BackupError(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeLocalConfig)
	if err := os.Mkdir(path+".bak", 0o750); err != nil {
		t.Fatal(err)
	}

	if err := runOpenCodeCmd(t, "install", "--path", path); err == nil {
		t.Error("expected install to fail when backup path is a directory")
	}
}

func TestOpenCodeInstall_HeaderSidecarWriteErrorLeavesConfigUntouched(t *testing.T) {
	homeFile := filepath.Join(t.TempDir(), "home-file")
	if err := os.WriteFile(homeFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", homeFile)
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfigSecretHeader)

	if err := runOpenCodeCmd(t, "install", "--path", path); err == nil {
		t.Fatal("expected install to fail when sidecar directory cannot be created")
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testOpenCodeRemoteConfigSecretHeader {
		t.Error("config changed even though sidecar write failed")
	}
}

func TestOpenCodeInstall_TargetDirCreateError(t *testing.T) {
	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parentFile, opencodeConfigFilename)

	if err := runOpenCodeCmd(t, "install", "--path", path); err == nil {
		t.Error("expected install to fail when target parent cannot be created")
	}
}

func TestOpenCodeInstall_AtomicWriteError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, opencodeConfigFilename)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // directory needs execute bit; this test removes write permission
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // restore private test directory permissions
			t.Fatalf("restore dir mode: %v", err)
		}
	})

	if err := runOpenCodeCmd(t, "install", "--path", path); err == nil {
		t.Error("expected install to fail when atomic write cannot create a temp file")
	}
}

func TestRunOpenCodeInstall_ConfigPathError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(opencodeConfigEnv, "")
	cmd := OpenCodeCmd()

	if err := runOpenCodeInstall(cmd, "", false, ""); err == nil {
		t.Error("expected install to fail when default config path cannot be resolved")
	}
}

func TestRunOpenCodeRemove_ConfigPathError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(opencodeConfigEnv, "")
	cmd := OpenCodeCmd()

	if err := runOpenCodeRemove(cmd, "", false); err == nil {
		t.Error("expected remove to fail when default config path cannot be resolved")
	}
}

func TestOpenCodeInstall_JSONC(t *testing.T) {
	path := writeOpenCodeFile(t, `{
  // opencode supports comments in config
  "mcp": {
    "fixture": {
      "type": "local",
      "command": ["node", "server.js"] /* trailing block */
    }
  }
}`)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install JSONC: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("output should be valid JSON: %v", err)
	}
	if _, wrapped := cfg.Servers["fixture"][mcpFieldPipelock]; !wrapped {
		t.Error("JSONC input server was not wrapped")
	}
}

func TestOpenCodeInstall_JSONCWithTrailingCommas(t *testing.T) {
	path := writeOpenCodeFile(t, `{
  "mcp": {
    "fixture": {
      "type": "local",
      "command": ["node", "server.js",],
    },
  },
}`)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install JSONC with trailing commas: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("output should be valid JSON: %v", err)
	}
	cmd := openCodeCommand(t, cfg.Servers["fixture"])
	if !hasAdjacentArg(cmd, codexArgSeparator, testNodeCmd) {
		t.Errorf("wrapped command missing original node command: %v", cmd)
	}
}

func TestOpenCodeInstall_NullMCP(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeNullMCP)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install with null mcp: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"mcp"`) {
		t.Error("mcp key missing after handling null input")
	}
}

func TestOpenCodeInstall_NoMCP(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeNoMCP)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install without mcp: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"mcp"`) {
		t.Error("mcp key missing after install")
	}
	if !strings.Contains(string(data), `"theme"`) {
		t.Error("unknown top-level field dropped")
	}
}

func TestOpenCodeInstall_SkipServersMissingCmdAndURL(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeNoCmdNoURL)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"_pipelock"`) {
		t.Error("entries without a usable command/url must not be wrapped")
	}
}

func TestOpenCodeInstall_SkipAmbiguousCommandAndURL(t *testing.T) {
	path := writeOpenCodeFile(t, testOpenCodeCommandAndURL)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	server := cfg.Servers["ambiguous"]
	if _, wrapped := server[mcpFieldPipelock]; wrapped {
		t.Fatal("ambiguous command+url entry must not be wrapped")
	}
	if server[mcpFieldURL] != testExampleURL {
		t.Errorf("ambiguous entry was not preserved: %v", server)
	}
}

func TestOpenCodeInstall_SkipRemoteOAuth(t *testing.T) {
	path := writeOpenCodeFile(t, `{
  "mcp": {
    "oauth": {
      "type": "remote",
      "url": "https://api.example.com/mcp",
      "oauth": { "authorization": "https://api.example.com/oauth" }
    }
  }
}`)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"_pipelock"`) {
		t.Error("remote oauth entry must be skipped because OpenCode's oauth flow cannot be preserved")
	}
}

func TestWrapOpenCodeServer_LocalWithoutExplicitType(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldCommand: []interface{}{testNodeCmd, "server.js"},
	}

	result, meta, _, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "", "", "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if meta.OriginalType != opencodeTypeLocal {
		t.Errorf("OriginalType = %q, want local", meta.OriginalType)
	}
	if result[mcpFieldType] != opencodeTypeLocal {
		t.Errorf("result type = %v, want local", result[mcpFieldType])
	}
}

func TestWrapOpenCodeServer_NeitherCommandNorURL(t *testing.T) {
	server := map[string]interface{}{
		opencodeFieldEnvironment: map[string]interface{}{"FOO": "bar"},
	}

	if _, _, _, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
		t.Error("wrap should fail when entry has neither command nor url")
	}
}

func TestWrapOpenCodeServer_UnsupportedType(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldType: "stdio",
	}

	if _, _, _, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
		t.Error("wrap should fail on unsupported OpenCode MCP type")
	}
}

func TestWrapOpenCodeServer_LocalCommandValidation(t *testing.T) {
	tests := []struct {
		name    string
		command interface{}
	}{
		{name: "not array", command: testNodeCmd},
		{name: "non string", command: []interface{}{testNodeCmd, 42}},
		{name: "empty array", command: []interface{}{}},
		{name: "empty executable", command: []interface{}{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := map[string]interface{}{
				mcpFieldType:    opencodeTypeLocal,
				mcpFieldCommand: tt.command,
			}
			if _, _, _, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
				t.Error("wrap should reject invalid local command")
			}
		})
	}
}

func TestWrapOpenCodeServer_RemoteValidation(t *testing.T) {
	tests := []struct {
		name   string
		server map[string]interface{}
	}{
		{
			name: "missing url",
			server: map[string]interface{}{
				mcpFieldType: opencodeTypeRemote,
			},
		},
		{
			name: "non string header",
			server: map[string]interface{}{
				mcpFieldType:    opencodeTypeRemote,
				mcpFieldURL:     testExampleURL,
				mcpFieldHeaders: map[string]interface{}{"X-Test": 42},
			},
		},
		{
			name: "invalid header key",
			server: map[string]interface{}{
				mcpFieldType:    opencodeTypeRemote,
				mcpFieldURL:     testExampleURL,
				mcpFieldHeaders: map[string]interface{}{"Bad Header": "value"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := wrapOpenCodeServer(tt.server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
				t.Error("wrap should reject invalid remote server")
			}
		})
	}
}

func TestWrapOpenCodeServer_RemoteWithoutExplicitType(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldURL: testExampleURL,
	}

	result, meta, plan, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "/tmp/pipelock.yaml", "", "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if plan != nil {
		t.Fatalf("remote without headers should not produce sidecar plan: %#v", plan)
	}
	if meta.OriginalType != opencodeTypeRemote {
		t.Errorf("OriginalType = %q, want remote", meta.OriginalType)
	}
	cmd := result[mcpFieldCommand].([]string)
	if !hasAdjacentArg(cmd, codexFlagConfig, "/tmp/pipelock.yaml") {
		t.Errorf("wrapped remote command missing --config: %v", cmd)
	}
	if !hasAdjacentArg(cmd, codexFlagUpstream, testExampleURL) {
		t.Errorf("wrapped remote command missing --upstream: %v", cmd)
	}
}

func TestWrapOpenCodeServer_EnvironmentError(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldType:             opencodeTypeLocal,
		mcpFieldCommand:          []interface{}{testNodeCmd},
		opencodeFieldEnvironment: map[string]interface{}{"--bad": "value"},
	}

	if _, _, _, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
		t.Error("wrap should reject unsafe environment keys")
	}
}

func TestWrapOpenCodeServer_HeaderSidecarPathError(t *testing.T) {
	t.Setenv("HOME", "")
	server := map[string]interface{}{
		mcpFieldType:    opencodeTypeRemote,
		mcpFieldURL:     testExampleURL,
		mcpFieldHeaders: map[string]interface{}{"X-Test": "value"},
	}

	if _, _, _, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "", "/tmp/opencode.json", "remote"); err == nil {
		t.Error("wrap should fail when header sidecar path cannot be resolved")
	}
}

func TestWrapOpenCodeServer_BothCommandAndURL(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldCommand: []interface{}{testNodeCmd},
		mcpFieldURL:     testExampleURL,
	}

	if _, _, _, err := wrapOpenCodeServer(server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
		t.Error("wrap should fail rather than silently dropping command or url")
	}
}

func TestOpenCodeConfigPath_DefaultUsesHome(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv(opencodeConfigEnv, "")

	got, err := opencodeConfigPath("")
	if err != nil {
		t.Fatalf("opencodeConfigPath: %v", err)
	}
	want := filepath.Join(tmpHome, ".config", opencodeConfigDirname, opencodeConfigFilename)
	if got != want {
		t.Errorf("default path mismatch: got %q, want %q", got, want)
	}
}

func TestOpenCodeConfigPath_HomeError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(opencodeConfigEnv, "")

	if _, err := opencodeConfigPath(""); err == nil {
		t.Error("expected missing HOME to fail default config discovery")
	}
}

func TestOpenCodeConfigPath_ExistingJSON(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv(opencodeConfigEnv, "")
	dir := filepath.Join(tmpHome, ".config", opencodeConfigDirname)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(dir, opencodeConfigFilename)
	if err := os.WriteFile(jsonPath, []byte(testOpenCodeNoMCP), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := opencodeConfigPath("")
	if err != nil {
		t.Fatalf("opencodeConfigPath: %v", err)
	}
	if got != jsonPath {
		t.Errorf("existing json path not used: got %q, want %q", got, jsonPath)
	}
}

func TestOpenCodeConfigPath_EnvOverride(t *testing.T) {
	t.Setenv(opencodeConfigEnv, "/tmp/custom-opencode.json")

	got, err := opencodeConfigPath("")
	if err != nil {
		t.Fatalf("opencodeConfigPath: %v", err)
	}
	if got != "/tmp/custom-opencode.json" {
		t.Errorf("env override not used: got %q", got)
	}
}

func TestOpenCodeConfigPath_OverrideRespected(t *testing.T) {
	got, err := opencodeConfigPath("/etc/opencode/custom.json")
	if err != nil {
		t.Fatalf("opencodeConfigPath: %v", err)
	}
	if got != "/etc/opencode/custom.json" {
		t.Errorf("override path not used: got %q", got)
	}
}

func TestOpenCodeConfigPath_ExistingJSONC(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv(opencodeConfigEnv, "")
	dir := filepath.Join(tmpHome, ".config", opencodeConfigDirname)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	jsoncPath := filepath.Join(dir, opencodeConfigJSONCFilename)
	if err := os.WriteFile(jsoncPath, []byte(testOpenCodeNoMCP), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := opencodeConfigPath("")
	if err != nil {
		t.Fatalf("opencodeConfigPath: %v", err)
	}
	if got != jsoncPath {
		t.Errorf("existing jsonc path not used: got %q, want %q", got, jsoncPath)
	}
}

func TestUnwrapOpenCodeServer_InvalidMetadata(t *testing.T) {
	tests := []struct {
		name string
		meta map[string]interface{}
	}{
		{name: "missing type", meta: map[string]interface{}{}},
		{name: "missing command", meta: map[string]interface{}{"original_type": opencodeTypeLocal}},
		{name: "missing url", meta: map[string]interface{}{"original_type": opencodeTypeRemote}},
		{name: "unsupported type", meta: map[string]interface{}{"original_type": "unknown"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := map[string]interface{}{mcpFieldPipelock: tt.meta}
			if _, _, err := unwrapOpenCodeServer(server); err == nil {
				t.Error("unwrap should reject invalid metadata")
			}
		})
	}
}

func TestUnwrapOpenCodeServer_NoMeta(t *testing.T) {
	server := map[string]interface{}{"name": "plain"}

	result, plan, err := unwrapOpenCodeServer(server)
	if err != nil {
		t.Fatalf("unwrap no meta: %v", err)
	}
	if plan != nil {
		t.Fatalf("no-meta unwrap returned sidecar plan: %#v", plan)
	}
	if result["name"] != "plain" {
		t.Errorf("server changed: %v", result)
	}
}

func TestUnwrapOpenCodeServer_MetadataDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		meta interface{}
	}{
		{name: "marshal", meta: map[string]interface{}{"bad": func() {}}},
		{name: "unmarshal", meta: "not an object"},
		{name: "bad sidecar path", meta: map[string]interface{}{
			"original_type":       opencodeTypeRemote,
			"original_url":        testExampleURL,
			"original_headers":    map[string]string{"X-Test": "value"},
			"header_sidecar_path": "relative.headers",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := map[string]interface{}{mcpFieldPipelock: tt.meta}
			if _, _, err := unwrapOpenCodeServer(server); err == nil {
				t.Error("expected unwrap to fail")
			}
		})
	}
}

func TestCleanupOpenCodeSidecars_IgnoresNonDeleteAndMissing(t *testing.T) {
	cmd := OpenCodeCmd()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	cleanupOpenCodeSidecars(cmd, "/tmp/opencode.json", []sidecarOp{
		{kind: sidecarOpWrite, path: "/tmp/not-a-delete.headers"},
		{kind: sidecarOpDelete},
		{kind: sidecarOpDelete, path: filepath.Join(t.TempDir(), "missing.headers")},
	})

	if stderr.Len() != 0 {
		t.Errorf("expected no cleanup warnings, got %q", stderr.String())
	}
}

func TestBuildOpenCodeEnvFlags_UnsafeKey(t *testing.T) {
	server := map[string]interface{}{
		opencodeFieldEnvironment: map[string]interface{}{"--bad": "value"},
	}

	if _, err := buildOpenCodeEnvFlags(server); err == nil {
		t.Error("expected unsafe environment key to fail")
	}
}

func TestUnsupportedOpenCodeRemoteAuth(t *testing.T) {
	tests := []struct {
		name string
		raw  interface{}
		want bool
	}{
		{name: "absent", raw: nil, want: false},
		{name: "false", raw: false, want: false},
		{name: "true", raw: true, want: true},
		{name: "empty object", raw: map[string]interface{}{}, want: false},
		{name: "object", raw: map[string]interface{}{"authorization": testExampleURL}, want: true},
		{name: "string", raw: "yes", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := map[string]interface{}{}
			if tt.raw != nil {
				server[opencodeFieldOAuth] = tt.raw
			}
			if got := unsupportedOpenCodeRemoteAuth(server); got != tt.want {
				t.Errorf("unsupportedOpenCodeRemoteAuth = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenCodeInstall_DryRunWithHeadersCreatesNoSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfigSecretHeader)

	if err := runOpenCodeCmd(t, "install", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("re-read after dry-run: %v", err)
	}
	if string(got) != testOpenCodeRemoteConfigSecretHeader {
		t.Error("dry-run modified the canonical config file")
	}
	if files := listSidecarFiles(t, home); len(files) > 0 {
		t.Errorf("dry-run wrote sidecar(s) to disk: %v", files)
	}
}

func TestOpenCodeRemove_DryRunPreservesSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfigSecretHeader)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	files := listSidecarFiles(t, home)
	if len(files) != 1 {
		t.Fatalf("expected one sidecar after install, got %v", files)
	}
	sidecarPath := filepath.Join(home, ".config", "pipelock", "wrap-headers", files[0])

	if err := runOpenCodeCmd(t, "remove", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("remove --dry-run: %v", err)
	}

	if _, err := os.Stat(sidecarPath); err != nil {
		t.Fatalf("dry-run remove deleted or changed sidecar: %v", err)
	}
}

func TestOpenCodeRemove_DeletesSidecarAfterConfigRestore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfigSecretHeader)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	files := listSidecarFiles(t, home)
	if len(files) != 1 {
		t.Fatalf("expected one sidecar after install, got %v", files)
	}
	sidecarPath := filepath.Join(home, ".config", "pipelock", "wrap-headers", files[0])

	if err := runOpenCodeCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := os.Stat(sidecarPath); !os.IsNotExist(err) {
		t.Fatalf("sidecar still exists after remove or stat failed: %v", err)
	}
}

func TestOpenCodeRemove_WarnsOnSidecarCleanupFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeOpenCodeFile(t, testOpenCodeRemoteConfigSecretHeader)

	if err := runOpenCodeCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	files := listSidecarFiles(t, home)
	if len(files) != 1 {
		t.Fatalf("expected one sidecar after install, got %v", files)
	}
	sidecarDir := filepath.Join(home, ".config", "pipelock", "wrap-headers")
	sidecarPath := filepath.Join(sidecarDir, files[0])
	if err := os.Chmod(sidecarDir, 0o500); err != nil { //nolint:gosec // directory needs execute bit; this test removes write permission
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(sidecarDir, 0o700); err != nil { //nolint:gosec // restore private sidecar directory permissions
			t.Fatalf("restore sidecar dir mode: %v", err)
		}
	})

	_, stderr, err := runOpenCodeCmdOutput(t, "remove", "--path", path)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(stderr, "could not clean up header sidecar") {
		t.Errorf("stderr missing sidecar cleanup warning: %q", stderr)
	}
	if _, err := os.Stat(sidecarPath); err != nil {
		t.Fatalf("sidecar should remain after failed cleanup: %v", err)
	}
}

func TestStripJSONC_PreservesURLInsideString(t *testing.T) {
	data := []byte(`{"url":"https://api.example.com/mcp","path":"/* literal */"}`)

	stripped, err := stripJSONC(data)
	if err != nil {
		t.Fatalf("stripJSONC: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(stripped, &got); err != nil {
		t.Fatalf("unmarshal stripped: %v", err)
	}
	if got["url"] != testExampleURL || got["path"] != "/* literal */" {
		t.Errorf("string contents changed: %v", got)
	}
}

func TestStripJSONC_TrailingCommas(t *testing.T) {
	data := []byte(`{
  "arr": [1, 2,],
  "obj": {
    "nested": true,
  },
  "commented": [
    "value", // keep newline
  ],
  "blockCommented": {
    "value": 1, /* keep object comma removable */
  },
}`)

	stripped, err := stripJSONC(data)
	if err != nil {
		t.Fatalf("stripJSONC: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(stripped, &got); err != nil {
		t.Fatalf("unmarshal stripped trailing-comma JSONC: %v\n%s", err, stripped)
	}
}

func TestJSONCNextSignificant(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "brace", input: "  }", want: true},
		{name: "line comment then bracket", input: " // c\n]", want: true},
		{name: "block comment then brace", input: " /* c */ }", want: true},
		{name: "slash not comment", input: " /not-comment }", want: false},
		{name: "only whitespace", input: " \n\t", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jsonCNextSignificant([]byte(tt.input), 0); got != tt.want {
				t.Errorf("jsonCNextSignificant(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMarshalOpenCodeConfig_FallbackForInvalidOriginal(t *testing.T) {
	cfg := &opencodeConfig{Servers: map[string]map[string]interface{}{}}

	out, err := marshalOpenCodeConfig([]byte("{not json"), cfg)
	if err != nil {
		t.Fatalf("marshal fallback: %v", err)
	}
	if !strings.Contains(string(out), opencodeSchemaURL) {
		t.Errorf("fallback output missing schema: %s", out)
	}
}

func TestMarshalOpenCodeConfig_ServerMarshalError(t *testing.T) {
	cfg := &opencodeConfig{
		Servers: map[string]map[string]interface{}{
			"bad": {"value": func() {}},
		},
	}

	if _, err := marshalOpenCodeConfig([]byte(testOpenCodeNoMCP), cfg); err == nil {
		t.Error("expected marshal to fail on non-JSON server value")
	}
}

func TestMarshalOpenCodeConfig_FallbackMarshalError(t *testing.T) {
	cfg := &opencodeConfig{
		Servers: map[string]map[string]interface{}{
			"bad": {"value": func() {}},
		},
	}

	if _, err := marshalOpenCodeConfig(nil, cfg); err == nil {
		t.Error("expected fallback marshal to fail on non-JSON server value")
	}
}

func TestUnmarshalOpenCodeConfig_StripError(t *testing.T) {
	var cfg opencodeConfig
	if err := unmarshalOpenCodeConfig([]byte(`{"x":1 /* no close`), &cfg); err == nil {
		t.Error("expected unmarshal to fail on invalid JSONC")
	}
}

func TestStripJSONC_EscapedQuote(t *testing.T) {
	data := []byte(`{"value":"quote: \" // not comment"}`)

	stripped, err := stripJSONC(data)
	if err != nil {
		t.Fatalf("stripJSONC: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(stripped, &got); err != nil {
		t.Fatalf("unmarshal stripped: %v", err)
	}
	if got["value"] != `quote: " // not comment` {
		t.Errorf("escaped quote handling changed value: %q", got["value"])
	}
}

func TestStripJSONC_BlockCommentPreservesNewline(t *testing.T) {
	data := []byte("{\n/* comment\ncontinued */\n\"x\": 1\n}")

	stripped, err := stripJSONC(data)
	if err != nil {
		t.Fatalf("stripJSONC: %v", err)
	}
	var got map[string]int
	if err := json.Unmarshal(stripped, &got); err != nil {
		t.Fatalf("unmarshal stripped: %v\n%s", err, stripped)
	}
	if got["x"] != 1 {
		t.Errorf("decoded value = %v", got)
	}
}

func TestStripJSONC_Errors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "unterminated string", body: `{"x":"unterminated}`},
		{name: "unterminated block", body: `{"x":1 /* no close`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := stripJSONC([]byte(tt.body)); err == nil {
				t.Error("expected stripJSONC to fail")
			}
		})
	}
}
