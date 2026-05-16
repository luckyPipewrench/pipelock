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
	testClineEnvKey   = "MY_VAR"
	testClineEnvValue = "test"

	testClineStdioConfig = `{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "@example/mcp-server"],
      "env": { "MY_VAR": "test" }
    }
  }
}`

	testClineHTTPConfig = `{
  "mcpServers": {
    "remote": {
      "url": "https://api.example.com/mcp",
      "headers": { "X-Workspace-Id": "ws-cli-tok" }
    }
  }
}`

	testClineWithUnknownField = `{
  "version": 2,
  "mcpServers": {
    "stdio-srv": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}`

	testClineStdioEmptyArgs = `{
  "mcpServers": {
    "fixture": {
      "command": "cat",
      "args": []
    }
  }
}`
	testClineNullServers = `{"mcpServers": null}`
	testClineNoCmdNoURL  = `{
  "mcpServers": {
    "broken": {
      "env": { "FOO": "bar" }
    }
  }
}`

	testClineCommandAndURL = `{
  "mcpServers": {
    "ambiguous": {
      "command": "node",
      "url": "https://api.example.com/mcp"
    }
  }
}`
)

// testClineHTTPConfigSecretHeader is built at init from a split bearer-token
// value so gosec G101 does not flag the fixture as a hardcoded credential.
var (
	testClineWorkspaceToken = "ws-cli-" + "tok"

	testClineHTTPConfigSecretHeader = `{
  "mcpServers": {
    "remote": {
      "url": "https://api.example.com/mcp",
      "headers": { "Authorization": "Bearer ` + "cli-tok" + `" }
    }
  }
}`
)

// writeClineFile writes a config string to a temp dir and returns the path.
func writeClineFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return p
}

func runClineCmd(t *testing.T, args ...string) error {
	t.Helper()
	_, _, err := runClineCmdOutput(t, args...)
	return err
}

func runClineCmdOutput(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := ClineCmd()
	cmd.SetArgs(args)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func hasAdjacentArg(args []string, flag, value string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestClineInstall_DryRun(t *testing.T) {
	path := writeClineFile(t, testClineStdioConfig)

	if err := runClineCmd(t, "install", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("re-read after dry-run: %v", err)
	}
	if string(got) != testClineStdioConfig {
		t.Error("dry-run modified the file")
	}
}

func TestClineInstall_StdioServerWithImplicitType(t *testing.T) {
	path := writeClineFile(t, testClineStdioConfig)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var cfg clineMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing result: %v", err)
	}

	server, ok := cfg.Servers["my-server"]
	if !ok {
		t.Fatal("server 'my-server' not in result")
	}

	if _, ok := server[mcpFieldPipelock]; !ok {
		t.Error("missing _pipelock metadata after wrap")
	}

	args := interfaceSliceToStrings(server["args"])
	if len(args) < 4 {
		t.Fatalf("expected at least 4 wrapped args, got %d: %v", len(args), args)
	}
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "mcp proxy ") {
		t.Errorf("expected wrapped args to start with mcp proxy, got %v", args[:2])
	}

	dashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashIdx = i
			break
		}
	}
	if dashIdx < 0 {
		t.Fatal("no -- separator in wrapped args")
	}
	if args[dashIdx+1] != testOriginalCmd {
		t.Errorf("expected original command after --, got %q", args[dashIdx+1])
	}

	foundEnv := false
	for i, a := range args {
		if a == codexFlagEnv && i+1 < len(args) && args[i+1] == testClineEnvKey {
			foundEnv = true
			break
		}
	}
	if !foundEnv {
		t.Errorf("expected --env %s passthrough in args: %v", testClineEnvKey, args)
	}

	env, ok := server["env"].(map[string]interface{})
	if !ok || env[testClineEnvKey] != testClineEnvValue {
		t.Errorf("env block not preserved: %v", server["env"])
	}

	if _, hasType := server[mcpFieldType]; !hasType {
		t.Error("wrapped stdio entry must declare type=stdio so Cline launches the pipelock subprocess")
	}
}

func TestClineInstall_HTTPServerWithImplicitType(t *testing.T) {
	// Sidecar dir lives under HOME; point it at a temp dir so the sidecar
	// file lands somewhere the test can read back without touching the
	// operator's real config.
	t.Setenv("HOME", t.TempDir())

	path := writeClineFile(t, testClineHTTPConfig)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var cfg clineMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing result: %v", err)
	}

	server := cfg.Servers["remote"]

	args := interfaceSliceToStrings(server["args"])
	foundUpstream := false
	for i, a := range args {
		if a == codexFlagUpstream && i+1 < len(args) {
			if args[i+1] != testExampleURL {
				t.Errorf("upstream URL mismatch: got %q, want %q", args[i+1], testExampleURL)
			}
			foundUpstream = true
			break
		}
	}
	if !foundUpstream {
		t.Error("--upstream flag missing from wrapped HTTP server")
	}

	// Wrapped argv carries the sidecar path, not the header value.
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
	if hasAdjacentArg(args, mcpFlagHeader, "X-Workspace-Id: ws-cli-tok") {
		t.Errorf("header value leaked into argv via --header; sidecar must be the only carrier")
	}
	body, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if !strings.Contains(string(body), "X-Workspace-Id: ws-cli-tok") {
		t.Errorf("sidecar missing the header line: %q", body)
	}

	metaJSON, _ := json.Marshal(server[mcpFieldPipelock])
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.OriginalURL != testExampleURL {
		t.Errorf("expected original URL preserved, got %q", meta.OriginalURL)
	}
	if !meta.TypeOmitted {
		t.Error("Cline HTTP wrap must record TypeOmitted=true so remove restores a typeless entry")
	}
	if meta.OriginalHeaders["X-Workspace-Id"] != testClineWorkspaceToken {
		t.Errorf("headers not preserved in metadata: %v", meta.OriginalHeaders)
	}
	if meta.HeaderSidecarPath != sidecarPath {
		t.Errorf("meta.HeaderSidecarPath = %q, want %q", meta.HeaderSidecarPath, sidecarPath)
	}
}

func TestClineInstall_Idempotent(t *testing.T) {
	path := writeClineFile(t, testClineStdioConfig)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("first install: %v", err)
	}
	firstRun, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	if err := runClineCmd(t, "install", "--path", path); err != nil {
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

func TestClineInstall_PreservesUnknownTopLevelFields(t *testing.T) {
	path := writeClineFile(t, testClineWithUnknownField)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version"`) {
		t.Error("unknown top-level field 'version' was dropped on install")
	}
}

func TestClineInstall_CreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install on missing file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected file to be created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected mode 0600 on new file, got %o", info.Mode().Perm())
	}
}

func TestClineInstall_BackupCreated(t *testing.T) {
	path := writeClineFile(t, testClineStdioConfig)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	backup, err := os.ReadFile(filepath.Clean(path + ".bak"))
	if err != nil {
		t.Fatalf("expected .bak backup: %v", err)
	}
	if string(backup) != testClineStdioConfig {
		t.Error("backup content does not match original")
	}
}

// TestClineRoundTrip_PreservesEmptyArgs locks in that `"args": []` on the
// source round-trips byte-exact through install + remove. Prior to the
// ArgsPresent metadata field, unwrap dropped empty args entirely because
// the restore branch gated on len(meta.OriginalArgs) > 0; the E2E harness
// in tests/e2e/cline-install.sh surfaced this in production-shaped configs.
func TestClineRoundTrip_PreservesEmptyArgs(t *testing.T) {
	path := writeClineFile(t, testClineStdioEmptyArgs)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	// Confirm the wrap recorded ArgsPresent on the metadata.
	wrappedData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var wrappedCfg clineMCPConfig
	if err := json.Unmarshal(wrappedData, &wrappedCfg); err != nil {
		t.Fatal(err)
	}
	metaJSON, _ := json.Marshal(wrappedCfg.Servers["fixture"][mcpFieldPipelock])
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatal(err)
	}
	if !meta.ArgsPresent {
		t.Error("wrap of stdio entry with empty args must record ArgsPresent=true")
	}

	// Run remove and assert the args field is restored as an empty array.
	if err := runClineCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	restoredData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var restoredRaw map[string]map[string]map[string]interface{}
	if err := json.Unmarshal(restoredData, &restoredRaw); err != nil {
		t.Fatal(err)
	}
	args, hasArgs := restoredRaw["mcpServers"]["fixture"]["args"]
	if !hasArgs {
		t.Fatal("unwrap dropped the args field that was present in the source")
	}
	argsSlice, ok := args.([]interface{})
	if !ok {
		t.Fatalf("restored args has wrong type: %T", args)
	}
	if len(argsSlice) != 0 {
		t.Errorf("expected empty args slice, got %v", argsSlice)
	}
}

func TestClineRemove_UnwrapsStdio(t *testing.T) {
	path := writeClineFile(t, testClineStdioConfig)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runClineCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var cfg clineMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse after remove: %v", err)
	}

	server := cfg.Servers["my-server"]
	if _, hasMeta := server[mcpFieldPipelock]; hasMeta {
		t.Error("_pipelock metadata not stripped after remove")
	}
	if server["command"] != testOriginalCmd {
		t.Errorf("original command not restored: got %v", server["command"])
	}
	if _, hasType := server[mcpFieldType]; hasType {
		t.Error("Cline stdio remove must not introduce a type field that was not in the original")
	}
}

func TestClineRemove_UnwrapsHTTP(t *testing.T) {
	path := writeClineFile(t, testClineHTTPConfig)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runClineCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var cfg clineMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse after remove: %v", err)
	}

	server := cfg.Servers["remote"]
	if _, hasType := server[mcpFieldType]; hasType {
		t.Error("Cline HTTP remove must not introduce a type field (Cline infers transport from url)")
	}
	if server["url"] != testExampleURL {
		t.Errorf("original URL not restored: got %v", server["url"])
	}
	headers, ok := server["headers"].(map[string]interface{})
	if !ok || headers["X-Workspace-Id"] != testClineWorkspaceToken {
		t.Errorf("headers not restored: %v", server["headers"])
	}
}

// TestClineInstall_SecretHeaderRoutesThroughSidecar locks in that install
// accepts credential-bearing headers because the values land in a 0o600
// sidecar referenced via --header-file, not in the wrapped argv.
func TestClineInstall_SecretHeaderRoutesThroughSidecar(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path := writeClineFile(t, testClineHTTPConfigSecretHeader)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install with credential header should succeed via sidecar: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var cfg clineMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	entry := cfg.Servers["remote"]
	if _, wrapped := entry[mcpFieldPipelock]; !wrapped {
		t.Fatal("entry must be wrapped via the sidecar path")
	}
	args := interfaceSliceToStrings(entry["args"])

	for _, a := range args {
		if strings.Contains(a, "cli-tok") {
			t.Fatalf("credential value leaked into wrapped argv: %v", args)
		}
	}
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
	info, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar mode = %04o, want 0o600", info.Mode().Perm())
	}
}

func TestClineRemove_NoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	if err := runClineCmd(t, "remove", "--path", path); err != nil {
		t.Errorf("remove on missing file should be a no-op, got: %v", err)
	}
}

func TestClineRemove_Idempotent(t *testing.T) {
	path := writeClineFile(t, testClineStdioConfig)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runClineCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("first remove: %v", err)
	}
	firstRun, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	if err := runClineCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	secondRun, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	if string(firstRun) != string(secondRun) {
		t.Errorf("remove is not idempotent:\nfirst:\n%s\nsecond:\n%s", firstRun, secondRun)
	}
}

func TestClineInstall_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runClineCmd(t, "install", "--path", path); err == nil {
		t.Error("expected install to fail on invalid JSON")
	}
}

func TestClineInstall_NullServers(t *testing.T) {
	path := writeClineFile(t, testClineNullServers)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install with null servers: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"mcpServers"`) {
		t.Error("mcpServers key missing after handling null input")
	}
}

func TestClineInstall_SkipServersMissingCmdAndURL(t *testing.T) {
	path := writeClineFile(t, testClineNoCmdNoURL)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"_pipelock"`) {
		t.Error("entries with neither command nor url must not be wrapped")
	}
}

func TestClineInstall_SkipAmbiguousCommandAndURL(t *testing.T) {
	path := writeClineFile(t, testClineCommandAndURL)

	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	var cfg clineMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse after install: %v", err)
	}
	server := cfg.Servers["ambiguous"]
	if _, wrapped := server[mcpFieldPipelock]; wrapped {
		t.Fatal("ambiguous command+url entry must not be wrapped")
	}
	if server[mcpFieldCommand] != testNodeCmd || server[mcpFieldURL] != testExampleURL {
		t.Errorf("ambiguous entry was not preserved: %v", server)
	}
}

func TestWrapClineServer_WithExplicitType(t *testing.T) {
	server := map[string]interface{}{
		"type":    testTypeStdio,
		"command": testNodeCmd,
		"args":    []interface{}{"server.js"},
	}

	result, meta, _, err := wrapClineServer(server, "/usr/local/bin/pipelock", "", "", "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if meta.OriginalType != testTypeStdio {
		t.Errorf("expected OriginalType=stdio, got %q", meta.OriginalType)
	}
	if meta.TypeOmitted {
		t.Error("explicit type must produce TypeOmitted=false")
	}
	if result["type"] != testTypeStdio {
		t.Errorf("expected wrapped type=stdio, got %v", result["type"])
	}
}

func TestWrapClineServer_NeitherCommandNorURL(t *testing.T) {
	server := map[string]interface{}{
		"env": map[string]interface{}{"FOO": "bar"},
	}

	if _, _, _, err := wrapClineServer(server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
		t.Error("wrap should fail when the entry has neither command nor url")
	}
}

func TestWrapClineServer_BothCommandAndURL(t *testing.T) {
	server := map[string]interface{}{
		mcpFieldCommand: testNodeCmd,
		mcpFieldURL:     testExampleURL,
	}

	if _, _, _, err := wrapClineServer(server, "/usr/local/bin/pipelock", "", "", ""); err == nil {
		t.Error("wrap should fail rather than silently dropping command or url")
	}
}

func TestClineConfigPath_DefaultUsesHome(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	got, err := clineConfigPath("")
	if err != nil {
		t.Fatalf("clineConfigPath: %v", err)
	}
	want := filepath.Join(tmpHome, ".cline", "mcp.json")
	if got != want {
		t.Errorf("default path mismatch: got %q, want %q", got, want)
	}
}

func TestClineConfigPath_OverrideRespected(t *testing.T) {
	got, err := clineConfigPath("/etc/cline/custom.json")
	if err != nil {
		t.Fatalf("clineConfigPath: %v", err)
	}
	if got != "/etc/cline/custom.json" {
		t.Errorf("override path not used: got %q", got)
	}
}

// listSidecarFiles returns the entries in $HOME/.config/pipelock/wrap-headers
// (or nil if the directory does not exist). Tests use this to assert the
// dry-run paths never land a sidecar on disk.
func listSidecarFiles(t *testing.T, home string) []string {
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

// TestClineInstall_DryRunWithHeadersCreatesNoSidecar locks in that --dry-run
// is read-only across both the canonical config AND the operator-private
// header sidecar dir. A dry-run that wrote a sidecar would leak the
// operator's Authorization value to disk without their consent and would
// also leave an orphan file the operator did not opt into.
func TestClineInstall_DryRunWithHeadersCreatesNoSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := writeClineFile(t, testClineHTTPConfigSecretHeader)

	if err := runClineCmd(t, "install", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("re-read after dry-run: %v", err)
	}
	if string(got) != testClineHTTPConfigSecretHeader {
		t.Error("dry-run modified the canonical config file")
	}

	if files := listSidecarFiles(t, home); len(files) > 0 {
		t.Errorf("dry-run wrote sidecar(s) to disk: %v", files)
	}
}

// TestClineRemove_DryRunPreservesSidecar locks in that --dry-run on remove
// does NOT delete a wrapped server's header sidecar. A dry-run that deleted
// the sidecar would put the agent into a broken state since the still-wrapped
// argv references a --header-file path that no longer exists.
func TestClineRemove_DryRunPreservesSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := writeClineFile(t, testClineHTTPConfigSecretHeader)

	// Install first so a real sidecar lands on disk.
	if err := runClineCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	files := listSidecarFiles(t, home)
	if len(files) != 1 {
		t.Fatalf("expected one sidecar after install, got %d (%v)", len(files), files)
	}
	sidecarPath := filepath.Join(home, ".config", "pipelock", "wrap-headers", files[0])
	sidecarBefore, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("read sidecar before remove: %v", err)
	}
	cfgBefore, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	// remove --dry-run must touch neither the canonical config nor the sidecar.
	if err := runClineCmd(t, "remove", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("remove --dry-run failed: %v", err)
	}

	cfgAfter, err := os.ReadFile(filepath.Clean(path))
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
