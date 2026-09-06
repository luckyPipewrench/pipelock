// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const continueStdioFixture = `name: fixture
version: 0.0.1
schema: v1
mcpServers:
  - name: local
    command: node
    args: [server.js]
    env:
      FIXTURE: value
  - name: remote
    type: sse
    url: https://api.vendor.example/mcp
`

func runContinueCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := ContinueCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd.Execute()
}

func runContinueCmdWithOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := ContinueCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stderr.String(), err
}

func readContinueServers(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	raw := document[continueServersKey].([]interface{})
	servers := make([]map[string]interface{}, len(raw))
	for i, server := range raw {
		servers[i] = server.(map[string]interface{})
	}
	return servers
}

func TestContinueInstallAndRemove_GlobalAndBlockFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	global := filepath.Join(home, continueDirname, continueConfigName)
	blocks := filepath.Join(home, continueDirname, continueMCPDirname)
	if err := os.MkdirAll(blocks, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(global, []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	block := filepath.Join(blocks, "block.yml")
	if err := os.WriteFile(block, []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContinueCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	first, err := os.ReadFile(filepath.Clean(global))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{global, block} {
		servers := readContinueServers(t, path)
		if servers[0][mcpFieldPipelock] == nil || servers[1][mcpFieldPipelock] == nil {
			t.Fatalf("%s was not wrapped: %#v", path, servers)
		}
		if _, err := os.Stat(path + ".bak"); err != nil {
			t.Fatalf("backup for %s: %v", path, err)
		}
	}
	if err := runContinueCmd(t, "install"); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}
	second, err := os.ReadFile(filepath.Clean(global))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("second install changed an already wrapped config")
	}
	if err := runContinueCmd(t, "remove"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for _, path := range []string{global, block} {
		servers := readContinueServers(t, path)
		if servers[0][mcpFieldCommand] != "node" || servers[1][mcpFieldURL] != "https://api.vendor.example/mcp" {
			t.Fatalf("%s was not restored: %#v", path, servers)
		}
	}
}

func TestContinueInstall_DryRunAndMalformedFailClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, continueDirname, continueConfigName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := runContinueCmd(t, "install", "--dry-run"); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	after, _ := os.ReadFile(filepath.Clean(path))
	if !bytes.Equal(before, after) {
		t.Fatal("dry run modified config")
	}
	if err := os.WriteFile(path, []byte("mcpServers: not-a-list\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad, _ := os.ReadFile(filepath.Clean(path))
	if err := runContinueCmd(t, "install"); err == nil {
		t.Fatal("malformed config unexpectedly installed")
	}
	after, _ = os.ReadFile(filepath.Clean(path))
	if !bytes.Equal(bad, after) {
		t.Fatal("malformed config was rewritten")
	}
}

func TestContinueInstall_IgnoresLegacyJSONWhenYAMLExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, continueDirname)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, continueLegacyName), []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, continueConfigName), []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr, err := runContinueCmdWithOutput(t, "install")
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(stderr, "deprecated config.json is present and ignored") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestContinueInstall_RefusesOnlyLegacyJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, continueDirname), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, continueDirname, continueLegacyName), []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContinueCmd(t, "install"); err == nil || !strings.Contains(err.Error(), "rename or remove") {
		t.Fatalf("legacy-only install error = %v", err)
	}
}

func TestContinueHelpersRejectInvalidServers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		server map[string]interface{}
	}{
		{"both command and URL", map[string]interface{}{mcpFieldCommand: "node", mcpFieldURL: "https://api.vendor.example/mcp"}},
		{"unknown type", map[string]interface{}{mcpFieldCommand: "node", mcpFieldType: "other"}},
		{"empty command", map[string]interface{}{mcpFieldCommand: ""}},
		{"empty URL", map[string]interface{}{mcpFieldURL: ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := wrapContinueServer(tt.server, "/bin/pipelock", ""); err == nil {
				t.Fatal("invalid server was accepted")
			}
		})
	}
	if _, _, err := continuePaths("/tmp/config.json", ""); err == nil {
		t.Fatal("legacy --path was accepted")
	}
}

func TestContinueInstall_PreservesSiblingLinesAndComments(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	continueDir := filepath.Join(home, continueDirname)
	blocksDir := filepath.Join(continueDir, continueMCPDirname)
	if err := os.MkdirAll(blocksDir, 0o750); err != nil {
		t.Fatal(err)
	}
	const fixture = `# operator-owned head comment
name: preserved
models: # sibling inline comment
  - name: local-model
mcpServers:
  - name: local
    command: node
    args: [server.js]
rules:
  - preserve sibling order
`
	paths := []string{
		filepath.Join(continueDir, continueConfigName),
		filepath.Join(blocksDir, "preserve.yml"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := runContinueCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, path := range paths {
		installed, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		assertContinueSiblingLinesUnchanged(t, fixture, string(installed))
		if !strings.Contains(string(installed), "# operator-owned head comment") {
			t.Fatalf("install lost head comment in %s", path)
		}
	}
	if err := runContinueCmd(t, "remove"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for _, path := range paths {
		removed, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		assertContinueSiblingLinesUnchanged(t, fixture, string(removed))
		if !strings.Contains(string(removed), "# operator-owned head comment") {
			t.Fatalf("remove lost head comment in %s", path)
		}
	}
}

func assertContinueSiblingLinesUnchanged(t *testing.T, before, after string) {
	t.Helper()
	filter := func(text string) string {
		lines := strings.Split(text, "\n")
		kept := make([]string, 0, len(lines))
		inServers := false
		for _, line := range lines {
			if line == "mcpServers:" {
				inServers = true
				continue
			}
			if inServers && line != "" && !strings.HasPrefix(line, " ") {
				inServers = false
			}
			if !inServers {
				kept = append(kept, line)
			}
		}
		return strings.Join(kept, "\n")
	}
	if got, want := filter(after), filter(before); got != want {
		t.Fatalf("non-mcpServers lines changed (-want +got):\n- %s\n+ %s", want, got)
	}
}

func TestContinueInstall_WarnsForForeignAndUnrestorableWrappers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, continueDirname, continueConfigName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	const foreign = `mcpServers:
  - name: foreign
    command: /tmp/other-pipelock
    args: [mcp, proxy, --, node, server.js]
`
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr, err := runContinueCmdWithOutput(t, "install")
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(stderr, "that is not this pipelock binary") {
		t.Fatalf("foreign-wrapper warning missing: %q", stderr)
	}
	const unrestorable = `mcpServers:
  - name: marked-but-direct
    command: node
    _pipelock:
      original_command: node
`
	if err := os.WriteFile(path, []byte(unrestorable), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr, err = runContinueCmdWithOutput(t, "remove")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(stderr, "metadata but runs") {
		t.Fatalf("unrestorable-wrapper warning missing: %q", stderr)
	}
}

func TestPlanContinueFileNoServersAndMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	plan, err := planContinueFile(missing, "/bin/pipelock", "", false)
	if err != nil || plan.exists {
		t.Fatalf("missing file plan = %#v, %v", plan, err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("models: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err = planContinueFile(path, "/bin/pipelock", "", false)
	if err != nil || plan.changed {
		t.Fatalf("no-server plan = %#v, %v", plan, err)
	}
}
