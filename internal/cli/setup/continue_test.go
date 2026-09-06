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
	exe, err := resolvePipelockBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{global, block} {
		servers := readContinueServers(t, path)
		if servers[0][mcpFieldPipelock] == nil || servers[1][mcpFieldPipelock] == nil {
			t.Fatalf("%s was not wrapped: %#v", path, servers)
		}
		// The proxy must sit in the execution path, not only in metadata.
		for i, server := range servers {
			if server[mcpFieldCommand] != exe {
				t.Fatalf("%s mcpServers[%d] command = %v, want the pipelock binary %s", path, i, server[mcpFieldCommand], exe)
			}
		}
		stdioArgs := continueStringSlice(t, servers[0][mcpFieldArgs])
		if len(stdioArgs) < 2 || stdioArgs[0] != "mcp" || stdioArgs[1] != "proxy" {
			t.Fatalf("%s stdio args %v do not invoke the MCP proxy", path, stdioArgs)
		}
		if tail := afterSeparator(stdioArgs); !reflect.DeepEqual(tail, []string{"node", "server.js"}) {
			t.Fatalf("%s stdio args %v do not run the original command behind the proxy separator", path, stdioArgs)
		}
		remoteArgs := continueStringSlice(t, servers[1][mcpFieldArgs])
		if len(remoteArgs) < 2 || remoteArgs[0] != "mcp" || remoteArgs[1] != "proxy" {
			t.Fatalf("%s remote args %v do not invoke the MCP proxy", path, remoteArgs)
		}
		if !hasSubsequence(remoteArgs, []string{"--upstream", "https://api.vendor.example/mcp"}) {
			t.Fatalf("%s remote args %v do not proxy the original url", path, remoteArgs)
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
	original := readContinueServersFromBytes(t, []byte(continueStdioFixture))
	for _, path := range []string{global, block} {
		servers := readContinueServers(t, path)
		if !reflect.DeepEqual(servers, original) {
			t.Fatalf("%s was not restored to the original mappings:\n got %#v\nwant %#v", path, servers, original)
		}
		for i, server := range servers {
			if _, stale := server[mcpFieldPipelock]; stale {
				t.Fatalf("%s mcpServers[%d] kept pipelock metadata after remove", path, i)
			}
		}
	}
}

func readContinueServersFromBytes(t *testing.T, data []byte) []map[string]interface{} {
	t.Helper()
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

func continueStringSlice(t *testing.T, value interface{}) []string {
	t.Helper()
	raw, ok := value.([]interface{})
	if !ok {
		t.Fatalf("args = %#v, want a list", value)
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		str, ok := item.(string)
		if !ok {
			t.Fatalf("arg %#v is not a string", item)
		}
		out = append(out, str)
	}
	return out
}

// afterSeparator returns the arguments after the first "--", which is the
// original command the proxy execs; nil when there is no separator.
func afterSeparator(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func hasSubsequence(haystack, needle []string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if reflect.DeepEqual(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// snapshotTree records every file under root with its mode and bytes so a
// test can prove an operation left the whole directory untouched, not only
// the one file it happened to read back.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	scoped, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scoped.Close() }()
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if entry.IsDir() {
			snap[rel] = "dir " + info.Mode().Perm().String()
			return nil
		}
		data, err := scoped.ReadFile(rel)
		if err != nil {
			return err
		}
		snap[rel] = info.Mode().Perm().String() + " " + string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
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
	blocks := filepath.Join(home, continueDirname, continueMCPDirname)
	if err := os.MkdirAll(blocks, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocks, "block.yaml"), []byte(continueStdioFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, filepath.Join(home, continueDirname))
	if err := runContinueCmd(t, "install", "--dry-run"); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if after := snapshotTree(t, filepath.Join(home, continueDirname)); !reflect.DeepEqual(before, after) {
		t.Fatalf("dry run changed the filesystem:\nbefore %#v\nafter  %#v", before, after)
	}
	if err := os.RemoveAll(blocks); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("mcpServers: not-a-list\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad, _ := os.ReadFile(filepath.Clean(path))
	if err := runContinueCmd(t, "install"); err == nil {
		t.Fatal("malformed config unexpectedly installed")
	}
	after, _ := os.ReadFile(filepath.Clean(path))
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
	// A foreign wrapper is wrapped again (the warning explains, it does not
	// refuse); the foreign command survives as the recorded original.
	exe, err := resolvePipelockBinary()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := readContinueServers(t, path)
	if wrapped[0][mcpFieldCommand] != exe {
		t.Fatalf("foreign wrapper was not wrapped by this binary: %#v", wrapped[0])
	}
	if meta, _ := wrapped[0][mcpFieldPipelock].(map[string]interface{}); meta["original_command"] != "/tmp/other-pipelock" {
		t.Fatalf("foreign command not recorded as the original: %#v", wrapped[0][mcpFieldPipelock])
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
	if err := os.Remove(path + ".bak"); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, filepath.Dir(path))
	stderr, err = runContinueCmdWithOutput(t, "remove")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(stderr, "metadata but runs") {
		t.Fatalf("unrestorable-wrapper warning missing: %q", stderr)
	}
	// An unrestorable entry is skipped, so nothing on disk may change and no
	// backup may appear.
	if after := snapshotTree(t, filepath.Dir(path)); !reflect.DeepEqual(before, after) {
		t.Fatalf("unrestorable remove changed the filesystem:\nbefore %#v\nafter  %#v", before, after)
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
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("Unix directory modes are not enforced here (Windows or root)")
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
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("Unix directory modes are not enforced here (Windows or root)")
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
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("Unix file modes are not enforced here (Windows or root)")
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

// TestContinueInstall_DuplicateKeyInBlockLeavesGlobalUntouched drives the
// duplicate-key refusal through the command: every target is planned before
// any is written, so a bad standalone file must leave a valid global config
// byte-identical with no backup.
func TestContinueInstall_DuplicateKeyInBlockLeavesGlobalUntouched(t *testing.T) {
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
	dup := "mcpServers:\n  - name: a\n    command: node\nmcpServers:\n  - name: b\n    command: node\n"
	if err := os.WriteFile(filepath.Join(blocks, "dup.yaml"), []byte(dup), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, filepath.Join(home, continueDirname))
	err := runContinueCmd(t, "install")
	if err == nil || !strings.Contains(err.Error(), "duplicate mapping key") {
		t.Fatalf("install error = %v, want duplicate key refusal", err)
	}
	if after := snapshotTree(t, filepath.Join(home, continueDirname)); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused install changed the filesystem:\nbefore %#v\nafter  %#v", before, after)
	}
}

// TestWriteInstallerBackup_NeverFollowsTheBackupPath covers a symlink or a
// directory sitting where the backup goes. The helper writes a private temp
// file and renames it into place, so a planted symlink is replaced and its
// target is never read or written, and a directory makes the write fail.
func TestWriteInstallerBackup_NeverFollowsTheBackupPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation needs privileges on Windows")
		}
		cfg := filepath.Join(dir, "linked.yaml")
		if err := os.Symlink(target, cfg+".bak"); err != nil {
			t.Fatal(err)
		}
		if err := writeInstallerBackup(cfg, []byte("new backup\n")); err != nil {
			t.Fatalf("backup over a symlink: %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(target)); string(data) != "keep me\n" {
			t.Fatalf("symlink target was modified: %q", data)
		}
		info, err := os.Lstat(cfg + ".bak")
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("backup path is not a private regular file: %v %v", info, err)
		}
		if data, _ := os.ReadFile(filepath.Clean(cfg + ".bak")); string(data) != "new backup\n" {
			t.Fatalf("backup content = %q", data)
		}
	})
	t.Run("directory", func(t *testing.T) {
		cfg := filepath.Join(dir, "dir.yaml")
		if err := os.Mkdir(cfg+".bak", 0o750); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(cfg + ".bak")
		if err != nil {
			t.Fatal(err)
		}
		if err := writeInstallerBackup(cfg, []byte("new backup\n")); err == nil {
			t.Fatal("backup over a directory unexpectedly succeeded")
		}
		info, statErr := os.Stat(cfg + ".bak")
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != before.Mode().Perm() {
			t.Fatalf("directory was altered: %v %v", info, statErr)
		}
		leftovers, _ := filepath.Glob(filepath.Join(dir, "dir.yaml.bak.tmp-*"))
		if len(leftovers) != 0 {
			t.Fatalf("temporary backup files were left behind: %v", leftovers)
		}
	})
	t.Run("missing", func(t *testing.T) {
		cfg := filepath.Join(dir, "fresh.yaml")
		if err := writeInstallerBackup(cfg, []byte("first\n")); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(cfg + ".bak")
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("fresh backup mode = %v err %v", info, err)
		}
	})
}
