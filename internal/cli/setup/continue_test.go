// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

type failingContinueYAMLValue struct{}

func (failingContinueYAMLValue) MarshalYAML() (interface{}, error) {
	return nil, errors.New("marshal failed")
}

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

func TestContinueInstall_RefusesCrossBoundaryAnchorFailClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, continueDirname, continueConfigName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	const fixture = `mcpServers:
  - name: local
    command: node
    args: [server.js]
    env: &shared
      FIXTURE: value
sharedElsewhere: *shared
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContinueCmd(t, "install"); err == nil || !strings.Contains(err.Error(), "referenced by anchor \"shared\"") {
		t.Fatalf("cross-boundary anchor error = %v", err)
	}
	after, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, []byte(fixture)) {
		t.Fatalf("cross-boundary anchor config changed:\n%s", after)
	}
}

func TestContinueInstall_RefusesAnchorInsideRewrittenEntry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, continueDirname, continueConfigName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	const fixture = `mcpServers:
  - name: local
    command: node
    args: [server.js]
    env: &internal
      FIXTURE: value
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContinueCmd(t, "install"); err == nil || !strings.Contains(err.Error(), "internal") {
		t.Fatalf("entry anchor error = %v", err)
	}
	after, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, []byte(fixture)) {
		t.Fatalf("entry anchor config changed:\n%s", after)
	}
}

func TestContinueInstall_PreservesDocumentMarker(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, continueDirname, continueConfigName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	fixture := "---\n" + continueStdioFixture
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContinueCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	after, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(after, []byte("---\n")) {
		t.Fatalf("document marker was dropped:\n%s", after)
	}
}

func TestContinueInstall_AllowsExternalAnchorAndRewritesFlowStyleServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, continueDirname, continueConfigName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	const fixture = `shared: &shared {FIXTURE: value}
models: {keep: true}
mcpServers: [{name: local, command: node, args: [server.js], env: *shared}, {name: remote, url: https://api.vendor.example/mcp}]
rules: [keep]
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContinueCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	after, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(after, &document); err != nil {
		t.Fatalf("rewritten flow-style document does not parse: %v", err)
	}
	servers := document[continueServersKey].([]interface{})
	for index, raw := range servers {
		if raw.(map[string]interface{})[mcpFieldPipelock] == nil {
			t.Fatalf("mcpServers[%d] was not wrapped: %#v", index, raw)
		}
	}
	if document["models"].(map[string]interface{})["keep"] != true {
		t.Fatalf("models sibling changed: %#v", document["models"])
	}
	if document["rules"].([]interface{})[0] != "keep" {
		t.Fatalf("rules sibling changed: %#v", document["rules"])
	}
	if got, want := servers[0].(map[string]interface{})["env"], document["shared"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("external anchor value was not preserved in rewritten entry: got %#v want %#v", got, want)
	}
}

func TestPlanContinueFile_RejectsUnparseableEncodedOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), continueConfigName)
	if err := os.WriteFile(path, []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	originalEncoder := encodeContinueDocument
	encodeContinueDocument = func(*yaml.Node) ([]byte, error) {
		return []byte("[unterminated"), nil
	}
	t.Cleanup(func() { encodeContinueDocument = originalEncoder })
	if _, err := planContinueFile(path, "/bin/pipelock", "", false); err == nil || !strings.Contains(err.Error(), "rewritten YAML does not parse") {
		t.Fatalf("unparseable encoded output error = %v", err)
	}
}

func TestPlanContinueFile_RejectsEncoderError(t *testing.T) {
	path := filepath.Join(t.TempDir(), continueConfigName)
	if err := os.WriteFile(path, []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	originalEncoder := encodeContinueDocument
	encodeContinueDocument = func(*yaml.Node) ([]byte, error) {
		return nil, errors.New("encoder failed")
	}
	t.Cleanup(func() { encodeContinueDocument = originalEncoder })
	if _, err := planContinueFile(path, "/bin/pipelock", "", false); err == nil || !strings.Contains(err.Error(), "encoder failed") {
		t.Fatalf("encoder error = %v", err)
	}
}

func TestContinuePlanRejectsInvalidServerShapes(t *testing.T) {
	for _, tt := range []struct {
		name    string
		fixture string
	}{
		{name: "invalid YAML", fixture: "mcpServers: ["},
		{name: "non-mapping server", fixture: "mcpServers: [plain]\n"},
		{name: "duplicate mapping key", fixture: "mcpServers:\n  - command: node\n    command: duplicate\n"},
		{name: "invalid server", fixture: "mcpServers:\n  - command: node\n    url: https://api.vendor.example/mcp\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), continueConfigName)
			if err := os.WriteFile(path, []byte(tt.fixture), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := planContinueFile(path, "/bin/pipelock", "", false); err == nil {
				t.Fatal("invalid server shape unexpectedly planned")
			}
		})
	}
}

func TestContinueHelperEdgeCases(t *testing.T) {
	if _, err := continueServerNode(map[string]interface{}{"unsupported": failingContinueYAMLValue{}}); err == nil || !strings.Contains(err.Error(), "marshal failed") {
		t.Fatalf("server node marshal error = %v", err)
	}
	if _, err := marshalContinueDocument(&yaml.Node{Kind: yaml.Kind(42)}); err == nil {
		t.Fatal("invalid document node unexpectedly encoded")
	}
	if got := continueServerName(map[string]interface{}{}, 3); got != "mcpServers[3]" {
		t.Fatalf("unnamed server = %q", got)
	}
	for _, tc := range []struct {
		data []byte
		want bool
	}{
		{data: []byte("---\n"), want: true},
		{data: []byte("---\r\n"), want: true},
		{data: []byte("mcpServers: []\n"), want: false},
	} {
		if got := continueHasDocumentMarker(tc.data); got != tc.want {
			t.Fatalf("continueHasDocumentMarker(%q) = %v, want %v", tc.data, got, tc.want)
		}
	}
}

func TestContinuePlanAndWriteErrors(t *testing.T) {
	t.Run("legacy path is rejected by command", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), continueLegacyName)
		if err := runContinueCmd(t, "install", "--path", path); err == nil || !strings.Contains(err.Error(), "deprecated") {
			t.Fatalf("legacy path error = %v", err)
		}
	})

	t.Run("non-mapping root", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), continueConfigName)
		if err := os.WriteFile(path, []byte("- not-a-mapping\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := planContinueFile(path, "/bin/pipelock", "", false); err == nil || !strings.Contains(err.Error(), "document must contain a mapping") {
			t.Fatalf("root error = %v", err)
		}
	})

	t.Run("unreadable standalone directory", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows does not enforce Unix directory modes")
		}
		home := t.TempDir()
		t.Setenv("HOME", home)
		blocksDir := filepath.Join(home, continueDirname, continueMCPDirname)
		if err := os.MkdirAll(blocksDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(blocksDir, 0o000); err != nil {
			t.Fatal(err)
		}
		usableDirMode := os.FileMode(0o700)
		usableDirMode |= 0o050
		t.Cleanup(func() { _ = os.Chmod(blocksDir, usableDirMode) })
		if err := runContinueCmd(t, "install"); err == nil || !strings.Contains(err.Error(), "reading standalone MCP directory") {
			t.Fatalf("standalone directory error = %v", err)
		}
	})

	t.Run("standalone subdirectory is ignored", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		blocksDir := filepath.Join(home, continueDirname, continueMCPDirname)
		if err := os.MkdirAll(filepath.Join(blocksDir, "nested"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := runContinueCmd(t, "install"); err != nil {
			t.Fatalf("install with standalone directory: %v", err)
		}
	})

	t.Run("legacy config stat failure", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		dir := filepath.Join(home, continueDirname)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, continueLegacyName), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(continueConfigName, filepath.Join(dir, continueConfigName)); err != nil {
			t.Fatal(err)
		}
		if err := runContinueCmd(t, "install"); err == nil || !strings.Contains(err.Error(), "checking") {
			t.Fatalf("legacy config stat error = %v", err)
		}
	})

	t.Run("directory config path", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		path := filepath.Join(home, "config-directory")
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := runContinueCmd(t, "install", "--path", path); err == nil || !strings.Contains(err.Error(), "reading") {
			t.Fatalf("directory config error = %v", err)
		}
	})

	t.Run("read-only backup directory", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		dir := filepath.Join(home, continueDirname)
		path := filepath.Join(dir, continueConfigName)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(continueStdioFixture), 0o600); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			t.Skip("Windows does not enforce Unix directory modes")
		}
		readOnlyDirMode := os.FileMode(0o400)
		readOnlyDirMode |= 0o100
		if err := os.Chmod(dir, readOnlyDirMode); err != nil {
			t.Fatal(err)
		}
		usableDirMode := os.FileMode(0o700)
		usableDirMode |= 0o050
		t.Cleanup(func() { _ = os.Chmod(dir, usableDirMode) })
		if err := runContinueCmd(t, "install"); err == nil || !strings.Contains(err.Error(), "creating backup") {
			t.Fatalf("backup write error = %v", err)
		}
	})
}

// TestContinueInstall_RestrictsExistingBackupMode covers an operator whose
// earlier backup was left world-readable: the installer must tighten it to
// 0o600 before writing copied MCP env values into it.
func TestContinueInstall_RestrictsExistingBackupMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix file modes")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, continueDirname)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, continueConfigName)
	if err := os.WriteFile(path, []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	broadMode := os.FileMode(0o600)
	broadMode |= 0o044
	if err := os.WriteFile(path+".bak", []byte("stale: backup\n"), broadMode); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode is subject to umask; chmod so the precondition holds.
	if err := os.Chmod(path+".bak", broadMode); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + ".bak"); err != nil || info.Mode().Perm() != broadMode {
		t.Fatalf("precondition: backup mode = %v, err %v", info.Mode().Perm(), err)
	}
	if err := runContinueCmd(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	info, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("backup mode = %o, want 600", got)
	}
	if data, _ := os.ReadFile(filepath.Clean(path + ".bak")); string(data) != continueStdioFixture {
		t.Fatalf("backup content = %q, want the original config", data)
	}
}

// TestContinueInstall_RejectsDuplicateKeys covers duplicate mapping keys, which
// a Node decode keeps; a duplicate mcpServers key and a duplicate inside an
// untouched sibling both refuse before any write.
func TestContinueInstall_RejectsDuplicateKeys(t *testing.T) {
	for name, doc := range map[string]string{
		"duplicate mcpServers":  "mcpServers:\n  - name: a\n    command: node\nmcpServers:\n  - name: b\n    command: node\n",
		"duplicate sibling key": "models:\n  provider: x\n  provider: y\nmcpServers:\n  - name: a\n    command: node\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), continueConfigName)
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := planContinueFile(path, "/bin/pipelock", "", false)
			if err == nil || !strings.Contains(err.Error(), "duplicate mapping key") {
				t.Fatalf("duplicate key error = %v", err)
			}
			if _, statErr := os.Stat(path + ".bak"); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("backup must not exist after a refused plan: %v", statErr)
			}
		})
	}
}
