// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	testZedEnvValue = "test"

	testZedStdioConfig = `{
  "context_servers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "@example/mcp-server"],
      "env": { "MY_VAR": "test" }
    }
  }
}`

	testZedHTTPConfig = `{
  "context_servers": {
    "remote": {
      "url": "https://api.example.com/mcp",
      "headers": { "X-Workspace-Id": "ws-zed-tok" }
    }
  }
}`

	testZedWithUnknownField = `{
  "theme": "One Dark",
  "ui_font_size": 16,
  "context_servers": {
    "stdio-srv": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}`

	testZedStdioEmptyArgs = `{
  "context_servers": {
    "fixture": {
      "command": "cat",
      "args": []
    }
  }
}`

	testZedNullServers  = `{"context_servers": null}`
	testZedEmptyServers = `{"context_servers": {}}`

	testZedNoCmdNoURL = `{
  "context_servers": {
    "broken": {
      "env": { "FOO": "bar" }
    }
  }
}`

	testZedCommandAndURL = `{
  "context_servers": {
    "ambiguous": {
      "command": "node",
      "url": "https://api.example.com/mcp"
    }
  }
}`

	testZedMultipleServers = `{
  "context_servers": {
    "stdio-a": {
      "command": "node",
      "args": ["a.js"]
    },
    "stdio-b": {
      "command": "python",
      "args": ["-m", "server"]
    }
  }
}`
)

// testZedHTTPConfigSecretHeader carries a credential-bearing Authorization
// header. Split-string construction keeps gosec G101 from flagging the
// fixture as a hardcoded token.
var (
	testZedWorkspaceToken = "ws-zed-" + "tok"

	testZedHTTPConfigSecretHeader = `{
  "context_servers": {
    "remote": {
      "url": "https://api.example.com/mcp",
      "headers": { "Authorization": "Bearer ` + "zed-tok" + `" }
    }
  }
}`
)

// writeZedFile writes a settings.json body to a temp dir and returns the path.
func writeZedFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return p
}

func runZedCmd(t *testing.T, args ...string) error {
	t.Helper()
	_, _, err := runZedCmdOutput(t, args...)
	return err
}

func runZedCmdOutput(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := ZedCmd()
	cmd.SetArgs(args)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

// isolateHome returns a private $HOME for the test that also overrides
// XDG_CONFIG_HOME so the sidecar dir lookups land under it. Returns the home
// directory the test can write into.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

// chdirIsolated chdirs into a temp dir for the duration of the test, returning
// the dir. zedProjectConfigPath uses os.Getwd, so this prevents tests from
// stumbling onto the developer's real .zed/settings.json.
func chdirIsolated(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

// requirePOSIXPermissions skips the test on Windows (no POSIX mode bits) and
// when running as uid 0 (root bypasses chmod-based access checks, so a test
// that depends on EACCES from a chmod 0 dir gets a false-pass under root).
// Permission-manipulating tests should call this first.
func requirePOSIXPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission test skipped on Windows: no POSIX mode bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("permission test skipped under root: uid 0 bypasses chmod-based access checks")
	}
}

func TestZedInstall_DryRun(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)

	if err := runZedCmd(t, "install", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("re-read after dry-run: %v", err)
	}
	if string(got) != testZedStdioConfig {
		t.Error("dry-run modified the file")
	}
}

func TestZedInstall_StdioServerWithImplicitType(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	_ = data

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
	if !strings.HasPrefix(strings.Join(args, " "), "mcp proxy ") {
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
	if dashIdx+1 >= len(args) {
		t.Fatalf("-- separator at end of args with no original command following: %v", args)
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
	if !ok || env[testClineEnvKey] != testZedEnvValue {
		t.Errorf("env block not preserved: %v", server["env"])
	}

	if _, hasType := server[mcpFieldType]; !hasType {
		t.Error("wrapped stdio entry must declare type=stdio so Zed launches the pipelock subprocess")
	}
}

func TestZedInstall_HTTPServerWithImplicitType(t *testing.T) {
	isolateHome(t)
	path := writeZedFile(t, testZedHTTPConfig)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
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
	body, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if !strings.Contains(string(body), "X-Workspace-Id: ws-zed-tok") {
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
		t.Error("Zed HTTP wrap must record TypeOmitted=true so remove restores a typeless entry")
	}
	if meta.OriginalHeaders["X-Workspace-Id"] != testZedWorkspaceToken {
		t.Errorf("headers not preserved in metadata: %v", meta.OriginalHeaders)
	}
	if meta.HeaderSidecarPath != sidecarPath {
		t.Errorf("meta.HeaderSidecarPath = %q, want %q", meta.HeaderSidecarPath, sidecarPath)
	}
}

func TestZedInstall_Idempotent(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("first install: %v", err)
	}
	firstRun, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install", "--path", path); err != nil {
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

func TestZedInstall_PreservesUnknownTopLevelFields(t *testing.T) {
	path := writeZedFile(t, testZedWithUnknownField)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"theme"`) {
		t.Error("unknown top-level field 'theme' was dropped on install")
	}
	if !strings.Contains(string(data), `"ui_font_size"`) {
		t.Error("unknown top-level field 'ui_font_size' was dropped on install")
	}
}

func TestZedInstall_CreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "settings.json")

	if err := runZedCmd(t, "install", "--path", path); err != nil {
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

func TestZedInstall_BackupCreated(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	backup, err := os.ReadFile(filepath.Clean(path + ".bak"))
	if err != nil {
		t.Fatalf("expected .bak backup: %v", err)
	}
	if string(backup) != testZedStdioConfig {
		t.Error("backup content does not match original")
	}
}

// TestZedRoundTrip_PreservesEmptyArgs locks in that `"args": []` round-trips
// byte-exact through install + remove, mirroring the cline regression.
func TestZedRoundTrip_PreservesEmptyArgs(t *testing.T) {
	path := writeZedFile(t, testZedStdioEmptyArgs)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, _ := json.Marshal(cfg.Servers["fixture"][mcpFieldPipelock])
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatal(err)
	}
	if !meta.ArgsPresent {
		t.Error("wrap of stdio entry with empty args must record ArgsPresent=true")
	}

	if err := runZedCmd(t, "remove", "--path", path); err != nil {
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
	args, hasArgs := restoredRaw["context_servers"]["fixture"]["args"]
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

func TestZedRemove_UnwrapsStdio(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runZedCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
		t.Fatalf("parse after remove: %v", err)
	}

	server := cfg.Servers["my-server"]
	if _, hasMeta := server[mcpFieldPipelock]; hasMeta {
		t.Error("_pipelock metadata not stripped after remove")
	}
	if server[mcpFieldCommand] != testOriginalCmd {
		t.Errorf("original command not restored: got %v", server[mcpFieldCommand])
	}
	if _, hasType := server[mcpFieldType]; hasType {
		t.Error("Zed stdio remove must not introduce a type field that was not in the original")
	}
}

func TestZedRemove_UnwrapsHTTP(t *testing.T) {
	isolateHome(t)
	path := writeZedFile(t, testZedHTTPConfig)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runZedCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
		t.Fatalf("parse after remove: %v", err)
	}

	server := cfg.Servers["remote"]
	if _, hasType := server[mcpFieldType]; hasType {
		t.Error("Zed HTTP remove must not introduce a type field (Zed infers transport from url)")
	}
	if server[mcpFieldURL] != testExampleURL {
		t.Errorf("original URL not restored: got %v", server[mcpFieldURL])
	}
	headers, ok := server["headers"].(map[string]interface{})
	if !ok || headers["X-Workspace-Id"] != testZedWorkspaceToken {
		t.Errorf("headers not restored: %v", server["headers"])
	}
}

// TestZedInstall_SecretHeaderRoutesThroughSidecar locks in that install accepts
// credential-bearing headers because the values land in a 0o600 sidecar
// referenced via --header-file, not in the wrapped argv.
func TestZedInstall_SecretHeaderRoutesThroughSidecar(t *testing.T) {
	isolateHome(t)
	path := writeZedFile(t, testZedHTTPConfigSecretHeader)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install with credential header should succeed via sidecar: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	entry := cfg.Servers["remote"]
	if _, wrapped := entry[mcpFieldPipelock]; !wrapped {
		t.Fatal("entry must be wrapped via the sidecar path")
	}
	args := interfaceSliceToStrings(entry["args"])

	for _, a := range args {
		if strings.Contains(a, "zed-tok") {
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

func TestZedRemove_NoFileWithPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	if err := runZedCmd(t, "remove", "--path", path); err != nil {
		t.Errorf("remove on missing file should be a no-op, got: %v", err)
	}
}

func TestZedRemove_Idempotent(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runZedCmd(t, "remove", "--path", path); err != nil {
		t.Fatalf("first remove: %v", err)
	}
	firstRun, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "remove", "--path", path); err != nil {
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

func TestZedInstall_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install", "--path", path); err == nil {
		t.Error("expected install to fail on invalid JSON")
	}
}

func TestZedInstall_NullServers(t *testing.T) {
	path := writeZedFile(t, testZedNullServers)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install with null servers: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"context_servers"`) {
		t.Error("context_servers key missing after handling null input")
	}
}

func TestZedInstall_EmptyServers(t *testing.T) {
	path := writeZedFile(t, testZedEmptyServers)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install with empty servers: %v", err)
	}
}

func TestZedInstall_SkipServersMissingCmdAndURL(t *testing.T) {
	path := writeZedFile(t, testZedNoCmdNoURL)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
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

func TestZedInstall_SkipAmbiguousCommandAndURL(t *testing.T) {
	path := writeZedFile(t, testZedCommandAndURL)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
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

func TestZedInstall_WrapsMultipleServers(t *testing.T) {
	path := writeZedFile(t, testZedMultipleServers)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stdio-a", "stdio-b"} {
		if _, ok := cfg.Servers[name][mcpFieldPipelock]; !ok {
			t.Errorf("server %q not wrapped", name)
		}
	}
}

// TestZedInstall_DryRunWithHeadersCreatesNoSidecar locks in that --dry-run is
// read-only across both the canonical config AND the operator-private header
// sidecar dir.
func TestZedInstall_DryRunWithHeadersCreatesNoSidecar(t *testing.T) {
	home := isolateHome(t)
	path := writeZedFile(t, testZedHTTPConfigSecretHeader)

	if err := runZedCmd(t, "install", "--path", path, "--dry-run"); err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("re-read after dry-run: %v", err)
	}
	if string(got) != testZedHTTPConfigSecretHeader {
		t.Error("dry-run modified the canonical config file")
	}
	if files := listSidecarFiles(t, home); len(files) > 0 {
		t.Errorf("dry-run wrote sidecar(s) to disk: %v", files)
	}
}

// TestZedRemove_DryRunPreservesSidecar locks in that remove --dry-run does NOT
// delete a wrapped server's header sidecar.
func TestZedRemove_DryRunPreservesSidecar(t *testing.T) {
	home := isolateHome(t)
	path := writeZedFile(t, testZedHTTPConfigSecretHeader)

	if err := runZedCmd(t, "install", "--path", path); err != nil {
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

	if err := runZedCmd(t, "remove", "--path", path, "--dry-run"); err != nil {
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

// --- Zed-specific multi-path discovery ---

func TestZedUserConfigPath_HonorsXDGConfigHome(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())

	got, err := zedUserConfigPath()
	if err != nil {
		t.Fatalf("zedUserConfigPath: %v", err)
	}
	want := filepath.Join(xdg, zedUserConfigSubdir, zedConfigFilename)
	if got != want {
		t.Errorf("XDG-rooted user path mismatch: got %q, want %q", got, want)
	}
}

func TestZedUserConfigPath_FallsBackToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	got, err := zedUserConfigPath()
	if err != nil {
		t.Fatalf("zedUserConfigPath: %v", err)
	}
	want := filepath.Join(home, ".config", zedUserConfigSubdir, zedConfigFilename)
	if got != want {
		t.Errorf("HOME-rooted user path mismatch: got %q, want %q", got, want)
	}
}

func TestZedProjectConfigPath_IsCwdRelative(t *testing.T) {
	dir := chdirIsolated(t)

	got, err := zedProjectConfigPath()
	if err != nil {
		t.Fatalf("zedProjectConfigPath: %v", err)
	}
	want := filepath.Join(dir, zedProjectConfigDir, zedConfigFilename)
	if got != want {
		t.Errorf("project path mismatch: got %q, want %q", got, want)
	}
}

func TestResolveZedTargets_OverrideShortCircuits(t *testing.T) {
	got, err := resolveZedTargets("/tmp/explicit/settings.json")
	if err != nil {
		t.Fatalf("resolveZedTargets: %v", err)
	}
	if len(got.candidatePaths) != 1 || got.candidatePaths[0] != "/tmp/explicit/settings.json" {
		t.Errorf("override should yield exactly that path, got %v", got.candidatePaths)
	}
	if len(got.existingPaths) != 1 || got.existingPaths[0] != "/tmp/explicit/settings.json" {
		t.Errorf("override existingPaths mismatch: %v", got.existingPaths)
	}
}

func TestResolveZedTargets_DefaultProbesBoth(t *testing.T) {
	home := isolateHome(t)
	cwd := chdirIsolated(t)

	// Seed only the user-level file.
	userPath := filepath.Join(home, ".config", zedUserConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(userPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveZedTargets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.candidatePaths) != 5 {
		t.Errorf("expected 5 candidates (project + native stable + native preview + flatpak stable + flatpak preview), got %d: %v", len(got.candidatePaths), got.candidatePaths)
	}
	if len(got.existingPaths) != 1 {
		t.Fatalf("expected only user path to be present, got %d", len(got.existingPaths))
	}
	if got.existingPaths[0] != userPath {
		t.Errorf("existingPaths should hold user path %q, got %q", userPath, got.existingPaths[0])
	}
	_ = cwd
}

func TestResolveZedTargets_DefaultStatError(t *testing.T) {
	requirePOSIXPermissions(t)
	home := t.TempDir()
	xdg := filepath.Join(home, ".config")
	zedDir := filepath.Join(xdg, zedUserConfigSubdir)
	if err := os.MkdirAll(zedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	chdirIsolated(t)

	if err := os.Chmod(zedDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreDirPerms(zedDir) })

	_, err := resolveZedTargets("")
	if err == nil {
		t.Fatal("expected inaccessible default path to fail target discovery")
	}
	if !strings.Contains(err.Error(), "checking Zed settings path") {
		t.Fatalf("error should name failed stat probe, got: %v", err)
	}
}

func TestZedInstall_DefaultScansBothPathsWhenBothExist(t *testing.T) {
	home := isolateHome(t)
	cwd := chdirIsolated(t)

	userPath := filepath.Join(home, ".config", zedUserConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(userPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	projectPath := filepath.Join(cwd, zedProjectConfigDir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(projectPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectPath, []byte(testZedMultipleServers), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runZedCmdOutput(t, "install")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	// Both files should be summarized in stdout so the operator can see what
	// was wrapped at each scope.
	if !strings.Contains(stdout, userPath) {
		t.Errorf("install output missing user path %q: %s", userPath, stdout)
	}
	if !strings.Contains(stdout, projectPath) {
		t.Errorf("install output missing project path %q: %s", projectPath, stdout)
	}

	for _, p := range []string{userPath, projectPath} {
		cfg, _, parseErr := readMCPConfig(p, zedServersKey)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", p, parseErr)
		}
		wrapCount := 0
		for _, server := range cfg.Servers {
			if isWrapped(server) {
				wrapCount++
			}
		}
		if wrapCount == 0 {
			t.Errorf("expected at least one wrapped server in %s", p)
		}
	}
}

// TestZedInstall_DualSidecarNoCollision proves the invariant that two
// settings.json files (user + project) sharing a context_server name still
// produce two distinct header-sidecar files. headerSidecarPath hashes the
// absolute settings.json path into the sidecar name, so a same-named server
// at different scopes cannot clobber the credential carrier of the other.
func TestZedInstall_DualSidecarNoCollision(t *testing.T) {
	home := isolateHome(t)
	cwd := chdirIsolated(t)

	httpServerCfg := `{
  "context_servers": {
    "remote": {
      "url": "https://api.example.com/mcp",
      "headers": { "X-Workspace-Id": "ws-zed-tok" }
    }
  }
}`

	userPath := filepath.Join(home, ".config", zedUserConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(userPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(httpServerCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	projectPath := filepath.Join(cwd, zedProjectConfigDir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(projectPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectPath, []byte(httpServerCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	files := listSidecarFiles(t, home)
	if len(files) != 2 {
		t.Fatalf("expected 2 sidecar files (one per scope), got %d: %v", len(files), files)
	}

	sidecarPaths := map[string]string{}
	for _, scope := range []struct{ label, path string }{
		{"user", userPath},
		{"project", projectPath},
	} {
		cfg, _, err := readMCPConfig(scope.path, zedServersKey)
		if err != nil {
			t.Fatalf("parse %s: %v", scope.path, err)
		}
		args := interfaceSliceToStrings(cfg.Servers["remote"]["args"])
		var sidecar string
		for i, a := range args {
			if a == mcpFlagHeaderFile && i+1 < len(args) {
				sidecar = args[i+1]
				break
			}
		}
		if sidecar == "" {
			t.Fatalf("%s scope missing --header-file flag in wrapped args: %v", scope.label, args)
		}
		body, err := os.ReadFile(filepath.Clean(sidecar))
		if err != nil {
			t.Fatalf("read %s sidecar: %v", scope.label, err)
		}
		if !strings.Contains(string(body), "X-Workspace-Id: ws-zed-tok") {
			t.Errorf("%s sidecar missing expected header line: %q", scope.label, body)
		}
		sidecarPaths[scope.label] = sidecar
	}

	if sidecarPaths["user"] == sidecarPaths["project"] {
		t.Fatalf("user and project sidecars must not share a path, got %q for both", sidecarPaths["user"])
	}
}

func TestZedInstall_DefaultNoFilesPrintsHint(t *testing.T) {
	home := isolateHome(t)
	chdirIsolated(t)

	stdout, _, err := runZedCmdOutput(t, "install")
	if err != nil {
		t.Fatalf("install with no files should succeed: %v", err)
	}
	if !strings.Contains(stdout, "No Zed settings.json found") {
		t.Errorf("expected friendly hint when no settings.json exists, got: %s", stdout)
	}
	if !strings.Contains(stdout, ".config/zed/settings.json") {
		t.Errorf("hint should name the user-level path it looked for: %s", stdout)
	}
	if !strings.Contains(stdout, ".zed/settings.json") {
		t.Errorf("hint should name the project-level path it looked for: %s", stdout)
	}
	_ = home
}

func TestZedRemove_DefaultNoFilesPrintsHint(t *testing.T) {
	isolateHome(t)
	chdirIsolated(t)

	stdout, _, err := runZedCmdOutput(t, "remove")
	if err != nil {
		t.Fatalf("remove with no files should succeed: %v", err)
	}
	if !strings.Contains(stdout, "No Zed settings.json found") {
		t.Errorf("expected friendly hint when no settings.json exists, got: %s", stdout)
	}
}

// TestZedInstall_DefaultWrapsZedPreviewChannel covers users who run Zed
// Preview alongside the stable channel: the installer must wrap both
// channels' settings.json files when both exist.
func TestZedInstall_DefaultWrapsZedPreviewChannel(t *testing.T) {
	home := isolateHome(t)
	chdirIsolated(t)

	previewPath := filepath.Join(home, ".config", zedPreviewConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(previewPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previewPath, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(previewPath, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	if !isWrapped(cfg.Servers["my-server"]) {
		t.Error("Zed Preview channel settings.json should have been wrapped")
	}
}

// TestZedInstall_DefaultWrapsFlatpakStable proves the Flatpak-sandboxed
// settings.json (~/.var/app/dev.zed.Zed/config/zed/settings.json) is in the
// default-discovery list. Operators who install Zed from Flathub keep their
// MCP config there; the installer must reach it without --path.
func TestZedInstall_DefaultWrapsFlatpakStable(t *testing.T) {
	home := isolateHome(t)
	chdirIsolated(t)

	flatpakPath := filepath.Join(home, ".var", "app", zedFlatpakAppStableDir, "config", zedUserConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(flatpakPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flatpakPath, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(flatpakPath, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	if !isWrapped(cfg.Servers["my-server"]) {
		t.Error("Flatpak Zed stable settings.json should have been wrapped")
	}
}

// TestZedInstall_DefaultWrapsFlatpakPreview covers Zed Preview installed via
// Flatpak. Different app id (dev.zed.Zed.Preview) and channel subdir
// (zed-preview) than the stable Flatpak.
func TestZedInstall_DefaultWrapsFlatpakPreview(t *testing.T) {
	home := isolateHome(t)
	chdirIsolated(t)

	flatpakPath := filepath.Join(home, ".var", "app", zedFlatpakAppPreviewDir, "config", zedPreviewConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(flatpakPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flatpakPath, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(flatpakPath, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	if !isWrapped(cfg.Servers["my-server"]) {
		t.Error("Flatpak Zed Preview settings.json should have been wrapped")
	}
}

// TestZedInstall_DefaultEnumeratesAllPathsInHint locks in that the
// "no Zed settings.json found" message lists every default candidate (not
// just the first two), so operators on Flatpak or Preview can see why the
// installer didn't find their config.
func TestZedInstall_DefaultEnumeratesAllPathsInHint(t *testing.T) {
	isolateHome(t)
	chdirIsolated(t)

	stdout, _, err := runZedCmdOutput(t, "install")
	if err != nil {
		t.Fatalf("install with no files: %v", err)
	}

	wantSubstrings := []string{
		"/.zed/settings.json",                                            // project
		"/.config/zed/settings.json",                                     // native stable
		"/.config/zed-preview/settings.json",                             // native preview
		"/.var/app/dev.zed.Zed/config/zed/settings.json",                 // flatpak stable
		"/.var/app/dev.zed.Zed.Preview/config/zed-preview/settings.json", // flatpak preview
	}
	// Normalize the captured stdout for cross-platform path comparison. The
	// installer renders paths with the platform's filepath separator, so on
	// Windows the hint contains backslashes; assertions written against
	// '/'-separated fragments would false-fail there. Other tests in the
	// codebase use filepath.ToSlash for the same reason.
	stdoutSlash := filepath.ToSlash(stdout)
	for _, s := range wantSubstrings {
		if !strings.Contains(stdoutSlash, s) {
			t.Errorf("friendly hint missing expected path fragment %q\nfull stdout:\n%s", s, stdout)
		}
	}
}

func TestZedDefaultCandidates_OrderingIsStable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Chdir(home)

	got, err := zedDefaultCandidates()
	if err != nil {
		t.Fatalf("zedDefaultCandidates: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("expected 5 candidates, got %d: %v", len(got), got)
	}
	wantSuffixes := []string{
		"/.zed/settings.json",                                            // project (first)
		"/.config/zed/settings.json",                                     // native stable
		"/.config/zed-preview/settings.json",                             // native preview
		"/.var/app/dev.zed.Zed/config/zed/settings.json",                 // flatpak stable
		"/.var/app/dev.zed.Zed.Preview/config/zed-preview/settings.json", // flatpak preview (last)
	}
	for i, suf := range wantSuffixes {
		if !strings.HasSuffix(filepath.ToSlash(got[i]), suf) {
			t.Errorf("candidate[%d] = %q, want suffix %q", i, got[i], suf)
		}
	}
}

func TestZedFlatpakConfigPath_HonorsAppID(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stable, err := zedFlatpakConfigPath(zedFlatpakAppStableDir, zedUserConfigSubdir)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := zedFlatpakConfigPath(zedFlatpakAppPreviewDir, zedPreviewConfigSubdir)
	if err != nil {
		t.Fatal(err)
	}
	if stable == preview {
		t.Errorf("stable and preview flatpak paths must differ, both = %q", stable)
	}
	if !strings.Contains(filepath.ToSlash(stable), "dev.zed.Zed/config/zed/") {
		t.Errorf("stable flatpak path missing expected app id, got %q", stable)
	}
	if !strings.Contains(filepath.ToSlash(preview), "dev.zed.Zed.Preview/config/zed-preview/") {
		t.Errorf("preview flatpak path missing expected app id, got %q", preview)
	}
}

func TestZedInstall_DefaultUserOnly(t *testing.T) {
	home := isolateHome(t)
	chdirIsolated(t)

	userPath := filepath.Join(home, ".config", zedUserConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(userPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(userPath, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	if !isWrapped(cfg.Servers["my-server"]) {
		t.Error("user-level server should be wrapped")
	}
}

func TestZedInstall_DefaultProjectOnly(t *testing.T) {
	isolateHome(t)
	cwd := chdirIsolated(t)

	projectPath := filepath.Join(cwd, zedProjectConfigDir, zedConfigFilename)
	if err := os.MkdirAll(filepath.Dir(projectPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectPath, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(projectPath, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	if !isWrapped(cfg.Servers["my-server"]) {
		t.Error("project-level server should be wrapped")
	}
}

// TestZedInstall_DefaultIgnoresDirectoryNamedSettings locks in that a
// directory named settings.json at a default location is treated as absent.
// This protects against a misconfiguration where ~/.config/zed/settings.json
// is itself a directory (e.g. user mistakenly mkdir'd it) — the installer
// should not error out, it should ignore that candidate.
func TestZedInstall_DefaultIgnoresDirectoryNamedSettings(t *testing.T) {
	home := isolateHome(t)
	chdirIsolated(t)

	userDir := filepath.Join(home, ".config", zedUserConfigSubdir, zedConfigFilename)
	if err := os.MkdirAll(userDir, 0o750); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runZedCmdOutput(t, "install")
	if err != nil {
		t.Fatalf("install with directory at user path should succeed: %v", err)
	}
	if !strings.Contains(stdout, "No Zed settings.json found") {
		t.Errorf("expected friendly hint when settings.json is a directory, got: %s", stdout)
	}
}

// TestZedInstall_MkdirAllError ensures the parent-directory creation error
// surfaces. We bait it by making the grandparent dir read-only AND pointing
// --path at a missing file inside a not-yet-created subdir, so readZedConfig
// short-circuits on IsNotExist and the MkdirAll call is the first thing that
// actually touches the filesystem under the unwritable root.
func TestZedInstall_MkdirAllError(t *testing.T) {
	requirePOSIXPermissions(t)
	root := t.TempDir()
	if err := os.Chmod(root, os.ModeDir|0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreDirPerms(root) })

	target := filepath.Join(root, "subdir", "settings.json")
	if err := runZedCmd(t, "install", "--path", target); err == nil {
		t.Error("expected install to fail when parent dir is read-only")
	}
}

// TestZedInstall_AtomicWriteErrorOnNewFile covers the vscodeAtomicWrite
// error branch on the "no existing data" path: target is a fresh file in
// a read-only dir, so backup is skipped (nothing to back up) and the temp
// rename inside vscodeAtomicWrite is the first write that fails.
func TestZedInstall_AtomicWriteErrorOnNewFile(t *testing.T) {
	requirePOSIXPermissions(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, os.ModeDir|0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreDirPerms(dir) })

	target := filepath.Join(dir, "settings.json")
	if err := runZedCmd(t, "install", "--path", target); err == nil {
		t.Error("expected install to fail when target dir is not writable")
	}
}

// TestZedInstall_AtomicWriteError makes the destination directory read-only
// after seeding settings.json so the temp-file rename inside vscodeAtomicWrite
// cannot land. The wrap loop should surface the I/O error.
func TestZedInstall_AtomicWriteError(t *testing.T) {
	requirePOSIXPermissions(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, os.ModeDir|0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreDirPerms(dir) })

	if err := runZedCmd(t, "install", "--path", path); err == nil {
		t.Error("expected install to fail when target directory is not writable")
	}
}

// TestZedRemove_AtomicWriteError mirrors the install error-path test for the
// unwrap loop.
func TestZedRemove_AtomicWriteError(t *testing.T) {
	requirePOSIXPermissions(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(testZedStdioConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	// Install first so there's something to unwrap.
	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := os.Chmod(dir, os.ModeDir|0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreDirPerms(dir) })

	if err := runZedCmd(t, "remove", "--path", path); err == nil {
		t.Error("expected remove to fail when target directory is not writable")
	}
}

// TestZedRemove_InvalidJSON covers the parse-error branch in removeZedPath.
func TestZedRemove_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runZedCmd(t, "remove", "--path", path); err == nil {
		t.Error("expected remove to fail on invalid JSON")
	}
}

// TestZedRemove_MalformedMetadata triggers the unwrap-error warning branch
// by hand-crafting a server entry with an unparseable _pipelock metadata
// payload. The remove path should warn (not fail) and leave that entry alone.
func TestZedRemove_MalformedMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	corrupt := `{
  "context_servers": {
    "broken-meta": {
      "type": "stdio",
      "command": "/usr/local/bin/pipelock",
      "args": ["mcp", "proxy", "--", "node"],
      "_pipelock": {"original_type": "stdio"}
    }
  }
}`
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runZedCmdOutput(t, "remove", "--path", path)
	if err != nil {
		t.Fatalf("remove should succeed even with malformed metadata: %v", err)
	}
	if !strings.Contains(stderr, "warning: could not unwrap") {
		t.Errorf("expected unwrap warning in stderr, got stderr=%q stdout=%q", stderr, stdout)
	}
}

// TestZedInstall_ConfigFlagPassthrough verifies that --config is propagated
// into the wrapped argv as `--config <path>` ahead of the `--` separator.
func TestZedInstall_ConfigFlagPassthrough(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)
	cfgFile := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte("mode: enforce\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runZedCmd(t, "install", "--path", path, "--config", cfgFile); err != nil {
		t.Fatalf("install: %v", err)
	}

	cfg, _, err := readMCPConfig(path, zedServersKey)
	if err != nil {
		t.Fatal(err)
	}
	args := interfaceSliceToStrings(cfg.Servers["my-server"]["args"])
	found := false
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			if !strings.HasSuffix(args[i+1], "pipelock.yaml") {
				t.Errorf("--config value should match the supplied path, got %q", args[i+1])
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected --config in wrapped args, got %v", args)
	}
}

// TestZedInstall_RemoveDryRunShowsPath verifies the dry-run output path is
// hit on remove and names the file that would be touched.
func TestZedRemove_DryRunShowsPath(t *testing.T) {
	path := writeZedFile(t, testZedStdioConfig)
	if err := runZedCmd(t, "install", "--path", path); err != nil {
		t.Fatalf("install: %v", err)
	}

	stdout, _, err := runZedCmdOutput(t, "remove", "--path", path, "--dry-run")
	if err != nil {
		t.Fatalf("remove --dry-run: %v", err)
	}
	if !strings.Contains(stdout, "Would write to") {
		t.Errorf("expected dry-run preview in stdout, got %q", stdout)
	}
	if !strings.Contains(stdout, path) {
		t.Errorf("dry-run output should mention the target path %q, got %q", path, stdout)
	}
}

func TestWrapClineServer_ZedConfigShape_Stdio(t *testing.T) {
	// Verify shape parity: a server in the shape Zed uses produces the same
	// wrap outcome as the Cline-shape, since wrapClineServer is the shared
	// entry point.
	server := map[string]interface{}{
		mcpFieldCommand: testNodeCmd,
		mcpFieldArgs:    []interface{}{"server.js"},
		"env":           map[string]interface{}{"FOO": "bar"},
	}

	result, meta, _, err := wrapClineServer(server, "/usr/local/bin/pipelock", "", "", "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !meta.TypeOmitted {
		t.Error("Zed-shaped server (no type) must record TypeOmitted=true")
	}
	if result[mcpFieldType] != testTypeStdio {
		t.Errorf("wrapped result should declare type=stdio for Zed launch, got %v", result[mcpFieldType])
	}
}
