// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testArgFix = "--fix"

// errReader is an io.Reader that always returns an error.
type errReader struct {
	err error
}

func (r *errReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func TestCursorHookCmd_CleanShellCommand(t *testing.T) {
	input := `{"hook_event_name":"beforeShellExecution","command":"ls -la","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionAllow {
		t.Errorf("expected allow, got %s; message: %s", resp.Permission, resp.UserMessage)
	}
}

func TestCursorHookCmd_BlocksSecret(t *testing.T) {
	secret := "sk-ant-" + "api03-AABBCCDDEE123456789012345678901234"
	input := `{"hook_event_name":"beforeShellExecution","command":"curl -H 'Authorization: Bearer ` + secret + `' https://api.example.com","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("expected deny for secret in command, got %s", resp.Permission)
	}
	if !strings.Contains(resp.UserMessage, "Anthropic API Key") {
		t.Errorf("expected pattern name in message, got: %s", resp.UserMessage)
	}
}

func TestCursorHookCmd_BlocksRmRf(t *testing.T) {
	input := `{"hook_event_name":"beforeShellExecution","command":"rm -rf /","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("expected deny for rm -rf, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_MalformedJSON(t *testing.T) {
	input := `{not valid json`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON on malformed input: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("malformed input should deny, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_EmptyStdin(t *testing.T) {
	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader(nil))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON on empty stdin: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("empty stdin should deny, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_UnknownEvent(t *testing.T) {
	input := `{"hook_event_name":"beforeSomethingNew","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("unknown event should deny, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_OnlyJSONOnStdout(t *testing.T) {
	input := `{"hook_event_name":"beforeShellExecution","command":"echo hello","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	stdoutBuf := &strings.Builder{}
	stderrBuf := &strings.Builder{}
	cmd.SetOut(stdoutBuf)
	cmd.SetErr(stderrBuf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stdout := strings.TrimSpace(stdoutBuf.String())
	lines := strings.Split(stdout, "\n")
	if len(lines) != 1 {
		t.Errorf("expected exactly 1 line on stdout, got %d: %q", len(lines), stdout)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("stdout line is not valid JSON: %v", err)
	}
}

func TestCursorHookCmd_MCPExecution(t *testing.T) {
	input := `{"hook_event_name":"beforeMCPExecution","server":"test","tool_name":"list_files","tool_input":"{\"path\":\"/tmp\"}","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionAllow {
		t.Errorf("expected allow for clean MCP call, got %s; message: %s", resp.Permission, resp.UserMessage)
	}
}

func TestCursorHookCmd_ReadFile(t *testing.T) {
	input := `{"hook_event_name":"beforeReadFile","file_path":"/tmp/readme.txt","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionAllow {
		t.Errorf("expected allow for normal file, got %s; message: %s", resp.Permission, resp.UserMessage)
	}
}

func TestCursorHookCmd_WithConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfgContent := `version: 1
mode: balanced
mcp_tool_policy:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	input := `{"hook_event_name":"beforeShellExecution","command":"rm -rf /tmp/test","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook", "--config", cfgPath})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionAllow {
		t.Errorf("expected allow with policy disabled, got %s; message: %s", resp.Permission, resp.UserMessage)
	}
}

// --- Install command tests ---

func TestCursorInstallCmd_DryRun(t *testing.T) {
	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--dry-run"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Would write to") {
		t.Error("dry-run should show 'Would write to'")
	}
	if !strings.Contains(output, "beforeShellExecution") {
		t.Error("dry-run should show beforeShellExecution hook")
	}
	if !strings.Contains(output, "beforeMCPExecution") {
		t.Error("dry-run should show beforeMCPExecution hook")
	}
	if !strings.Contains(output, "beforeReadFile") {
		t.Error("dry-run should show beforeReadFile hook")
	}
	if !strings.Contains(output, "cursor hook") {
		t.Error("dry-run should show cursor hook command")
	}
}

func TestCursorInstallCmd_Project(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatalf("hooks.json not created: %v", err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}
	if hooks.Version != 1 {
		t.Errorf("expected version 1, got %d", hooks.Version)
	}
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 event types, got %d", len(hooks.Hooks))
	}
	for _, event := range []string{"beforeShellExecution", "beforeMCPExecution", "beforeReadFile"} {
		entries, ok := hooks.Hooks[event]
		if !ok {
			t.Errorf("missing event %s", event)
			continue
		}
		if len(entries) != 1 {
			t.Errorf("expected 1 entry for %s, got %d", event, len(entries))
		}
	}
}

func TestCursorInstallCmd_Merge(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	existing := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"other-tool check","timeout":5}]}}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}

	if hooks.Version != 1 {
		t.Errorf("expected version 1 after merge, got %d", hooks.Version)
	}
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 event types after merge, got %d", len(hooks.Hooks))
	}

	shellEntries := hooks.Hooks["beforeShellExecution"]
	if len(shellEntries) != 2 {
		t.Fatalf("expected 2 beforeShellExecution entries, got %d", len(shellEntries))
	}

	found := false
	for _, h := range shellEntries {
		if h.Command == "other-tool check" {
			found = true
			break
		}
	}
	if !found {
		t.Error("original hook was overwritten during merge")
	}
}

func TestCursorInstallCmd_Idempotent(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	for i := range 2 {
		cmd := CursorCmd()
		cmd.SetArgs([]string{"install", "--project", "--global=false"})
		cmd.SetOut(&strings.Builder{})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("run %d: unexpected error: %v", i+1, err)
		}
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}

	if hooks.Version != 1 {
		t.Errorf("expected version 1 after idempotent install, got %d", hooks.Version)
	}
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 event types after idempotent install, got %d", len(hooks.Hooks))
	}
	for event, entries := range hooks.Hooks {
		if len(entries) != 1 {
			t.Errorf("expected 1 entry for %s after idempotent install, got %d", event, len(entries))
		}
	}
}

func TestCursorInstallCmd_Backup(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	original := `{"version":1,"hooks":{}}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	backupPath := hooksPath + ".bak"
	backupData, err := os.ReadFile(filepath.Clean(backupPath))
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	if string(backupData) != original {
		t.Errorf("backup content mismatch: got %q, want %q", string(backupData), original)
	}
}

func TestCursorInstallCmd_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cursorDir := filepath.Join(dir, ".cursor")
	entries, err := os.ReadDir(cursorDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", entry.Name())
		}
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(cursorDir, "hooks.json")))
	if err != nil {
		t.Fatal(err)
	}
	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("hooks.json is invalid after atomic write: %v", err)
	}
	if hooks.Version != 1 {
		t.Errorf("expected version 1, got %d", hooks.Version)
	}
}

func TestCursorInstallCmd_UpgradePath(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	stale := `{"hooks":[` +
		`{"event":"beforeShellExecution","command":"/old/path/pipelock cursor hook","timeout":5},` +
		`{"event":"beforeMCPExecution","command":"/old/path/pipelock cursor hook","timeout":5},` +
		`{"event":"beforeReadFile","command":"/old/path/pipelock cursor hook","timeout":5}` +
		`]}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}

	if hooks.Version != 1 {
		t.Errorf("expected version 1, got %d", hooks.Version)
	}
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 event types after upgrade, got %d", len(hooks.Hooks))
	}

	for event, entries := range hooks.Hooks {
		if len(entries) != 1 {
			t.Errorf("expected 1 entry for %s, got %d", event, len(entries))
			continue
		}
		h := entries[0]
		if strings.Contains(h.Command, "/old/path") {
			t.Errorf("stale entry not updated for %s: %s", event, h.Command)
		}
		if !strings.Contains(h.Command, "cursor hook") {
			t.Errorf("hook command missing 'cursor hook' for %s: %s", event, h.Command)
		}
		if h.Timeout != cursorHookTimeout {
			t.Errorf("timeout not updated for %s: got %d, want %d", event, h.Timeout, cursorHookTimeout)
		}
	}
}

func TestCursorInstallCmd_InvalidFlags(t *testing.T) {
	t.Run("both flags", func(t *testing.T) {
		cmd := CursorCmd()
		cmd.SetArgs([]string{"install", "--global", "--project"})
		buf := &strings.Builder{}
		cmd.SetOut(buf)
		cmd.SetErr(buf)

		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error when both --global and --project are set")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestCursorInstallCmd_DefaultsToGlobal(t *testing.T) {
	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--dry-run"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, ".cursor") {
		t.Error("expected .cursor path in dry-run output")
	}
	if !strings.Contains(output, "Would write to") {
		t.Error("expected dry-run output")
	}
}

func TestCursorInstallCmd_ProjectAlone(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error with --project alone: %v", err)
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	if _, err := os.Stat(hooksPath); err != nil {
		t.Fatalf("hooks.json not created: %v", err)
	}
}

func TestCursorInstallCmd_GlobalActual(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--global"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatalf("hooks.json not created at global path: %v", err)
	}
	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}
	if hooks.Version != 1 {
		t.Errorf("expected version 1, got %d", hooks.Version)
	}
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 event types, got %d", len(hooks.Hooks))
	}
	if !strings.Contains(buf.String(), "Installed pipelock hooks") {
		t.Error("expected installation confirmation message")
	}
}

func TestCursorInstallCmd_EmbedsExplicitConfig(t *testing.T) {
	dir := t.TempDir()
	cfgName := "pipelock config.yaml"
	cfgPath := filepath.Join(dir, cfgName)
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--config", cfgName})
	var out, errOut strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(errOut.String(), cfgPath) {
		t.Fatalf("expected config provenance on stderr, got %q", errOut.String())
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatalf("hooks.json not created: %v", err)
	}
	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}
	for event, entries := range hooks.Hooks {
		if len(entries) != 1 {
			t.Fatalf("%s entries = %d, want 1", event, len(entries))
		}
		command := entries[0].Command
		if !strings.Contains(command, "cursor hook --config") {
			t.Fatalf("%s command missing --config: %q", event, command)
		}
		if !strings.Contains(command, shellQuote(cfgPath)) {
			t.Fatalf("%s command missing shell-quoted config path: %q", event, command)
		}
	}
}

func TestCursorRemoveCmd_RemovesPipelockHooksOnly(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	existing := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"lint","timeout":5},{"command":"/usr/bin/pipelock cursor hook --config /etc/pipelock/pipelock.yaml","timeout":10}],"beforeReadFile":[{"command":"/old/pipelock cursor hook","timeout":10}]}}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Removed 2") {
		t.Fatalf("expected removal count in output, got %q", buf.String())
	}

	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}
	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}
	if got := hooks.Hooks["beforeShellExecution"]; len(got) != 1 || got[0].Command != "lint" {
		t.Fatalf("non-pipelock hook not preserved exactly: %#v", got)
	}
	if len(hooks.Hooks["beforeReadFile"]) != 0 {
		t.Fatalf("pipelock read-file hook was not removed: %#v", hooks.Hooks["beforeReadFile"])
	}
	if _, err := os.Stat(hooksPath + ".bak"); err != nil {
		t.Fatalf("backup not created: %v", err)
	}
}

func TestCursorRemoveCmd_DryRunDoesNotWriteBackup(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	existing := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"lint","timeout":5},{"command":"/usr/bin/pipelock cursor hook","timeout":10}]}}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"remove", "--project", "--dry-run"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Would write to") || !strings.Contains(output, "(1 removed)") {
		t.Fatalf("expected dry-run removal output, got %q", output)
	}
	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing {
		t.Fatalf("dry-run remove changed hooks.json: got %q want %q", string(data), existing)
	}
	if _, err := os.Stat(hooksPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("dry-run remove should not create backup, stat err: %v", err)
	}
}

func TestCursorRemoveCmd_NoPipelockHooksNoops(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	existing := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"lint","timeout":5}]}}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No pipelock hooks found") {
		t.Fatalf("expected no-op message, got %q", buf.String())
	}
	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing {
		t.Fatalf("hooks.json changed on no-op remove: got %q want %q", string(data), existing)
	}
	if _, err := os.Stat(hooksPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("no-op remove should not create backup, stat err: %v", err)
	}
}

func TestCursorRemoveCmd_NoHooksJSONNoops(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no hooks.json found") {
		t.Fatalf("expected missing-file no-op message, got %q", buf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".cursor", "hooks.json")); !os.IsNotExist(err) {
		t.Fatalf("remove should not create hooks.json when it is absent, stat err: %v", err)
	}
}

func TestCursorRemoveCmd_MalformedExisting(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}
	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for malformed existing hooks.json")
	}
	if !strings.Contains(err.Error(), "parsing existing") {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestCursorRemoveCmd_InvalidFlags(t *testing.T) {
	cmd := CursorCmd()
	cmd.SetArgs([]string{"remove", "--global", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when both --global and --project are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestIsPipelockHook_Detection(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"bare pipelock hook", "/usr/bin/pipelock cursor hook", true},
		{"hook with config", "/usr/bin/pipelock cursor hook --config /etc/pipelock/pipelock.yaml", true},
		{"quoted path", "'/usr/local/bin/pipelock' cursor hook", true},
		{"trailing whitespace", "/usr/bin/pipelock cursor hook ", true},
		{"unrelated command", "lint", false},
		{"empty command", "", false},
		// Regression: a user hook that merely contains "cursor hook" mid-command
		// (not a pipelock-generated form) must not be clobbered.
		{"user hook containing the phrase", "/opt/tool cursor hook helper --verbose", false},
		{"other binary exact hook words", "/opt/tool cursor hook", false},
		{"user hook with unrelated flag after phrase", "/opt/tool cursor hook --helper", false},
		{"flag-like config operand", "/usr/bin/pipelock cursor hook --config --helper", false},
		{"trailing args after config", "/usr/bin/pipelock cursor hook --config /etc/pipelock/pipelock.yaml --helper", false},
		{"escaped space in config", `/usr/bin/pipelock cursor hook --config /tmp/has\ space.yaml`, true},
		{"escaped single quote in config", `/usr/bin/pipelock cursor hook --config '/tmp/it'\''s.yaml'`, true},
		{"unmatched quote", `/usr/bin/pipelock cursor hook --config '/tmp/bad.yaml`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPipelockHook(hookEntry{Command: tc.command}); got != tc.want {
				t.Errorf("isPipelockHook(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

func TestCursorHookCmd_StdinReadError(t *testing.T) {
	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(&errReader{err: fmt.Errorf("simulated read error")})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("expected deny for stdin read error, got %s", resp.Permission)
	}
	if !strings.Contains(resp.UserMessage, "read stdin") {
		t.Errorf("expected read stdin error message, got: %s", resp.UserMessage)
	}
}

func TestCursorInstallCmd_ReadPermError(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	hooksAsDir := filepath.Join(cursorDir, "hooks.json")
	if err := os.MkdirAll(hooksAsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unreadable hooks.json")
	}
	if !strings.Contains(err.Error(), "reading existing") {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "simple path",
			in:   "/usr/local/bin/pipelock",
			want: "/usr/local/bin/pipelock",
		},
		{
			name: "path with spaces",
			in:   "/path with spaces/pipelock",
			want: "'/path with spaces/pipelock'",
		},
		{
			name: "path with single quote",
			in:   "/it's/pipelock",
			want: `'/it'\''s/pipelock'`,
		},
		{
			name: "path with parens",
			in:   "/Program Files (x86)/pipelock",
			want: "'/Program Files (x86)/pipelock'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.in)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCursorHookCmd_WarnConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfgContent := `version: 1
mode: balanced
mcp_tool_policy:
  enabled: true
  action: warn
  rules:
    - name: Destructive Delete
      tool_pattern: "bash"
      arg_pattern: "rm\\s+-(r|f|rf|fr)"
      action: warn
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	input := `{"hook_event_name":"beforeShellExecution","command":"rm -rf /tmp/test","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook", "--config", cfgPath})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionAllow {
		t.Errorf("expected allow for warn-action policy, got %s; message: %s", resp.Permission, resp.UserMessage)
	}
	if resp.UserMessage == "" {
		t.Error("expected advisory user message for warn-action")
	}
}

func TestCursorHookCmd_ReadFileEvent(t *testing.T) {
	input := `{"hook_event_name":"beforeReadFile","file_path":"/home/user/.ssh/id_rsa","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("expected deny for credential file read, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_ReadFileCleanPath(t *testing.T) {
	input := `{"hook_event_name":"beforeReadFile","file_path":"/tmp/notes.txt","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionAllow {
		t.Errorf("expected allow for clean file path, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_ConfigError(t *testing.T) {
	input := `{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook", "--config", "/nonexistent/pipelock.yaml"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("expected deny for config error, got %s", resp.Permission)
	}
	if !strings.Contains(resp.UserMessage, "config error") {
		t.Errorf("expected config error message, got: %s", resp.UserMessage)
	}
}

func TestCursorHookCmd_MCPCleanTool(t *testing.T) {
	input := `{"hook_event_name":"beforeMCPExecution","server":"test-server","tool_name":"list_files","tool_input":"{\"path\":\"/tmp\"}","conversation_id":"abc","generation_id":"def"}`

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionAllow {
		t.Errorf("expected allow for clean MCP tool, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_OversizedStdin(t *testing.T) {
	big := make([]byte, 10<<20+100)
	for i := range big {
		big[i] = 'x'
	}

	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader(big))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("expected deny for oversized input, got %s", resp.Permission)
	}
	if !strings.Contains(resp.UserMessage, "too large") {
		t.Errorf("expected 'too large' message, got: %s", resp.UserMessage)
	}
}

func TestWriteResponse(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		var buf bytes.Buffer
		writeResponse(&buf, cursorResponse{
			Permission:  decisionAllow,
			UserMessage: "ok",
		})
		var resp cursorResponse
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp.Permission != decisionAllow {
			t.Errorf("expected allow, got %s", resp.Permission)
		}
	})
}

func TestCursorInstallCmd_MalformedExisting(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for malformed existing hooks.json")
	}
	if !strings.Contains(err.Error(), "parsing existing") {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestParseHooksJSON_V1Format(t *testing.T) {
	data := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"some-tool","timeout":5}]}}`
	hooks, err := parseHooksJSON([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hooks.Version != 1 {
		t.Errorf("expected version 1, got %d", hooks.Version)
	}
	if len(hooks.Hooks["beforeShellExecution"]) != 1 {
		t.Errorf("expected 1 entry, got %d", len(hooks.Hooks["beforeShellExecution"]))
	}
	if hooks.Hooks["beforeShellExecution"][0].Command != "some-tool" {
		t.Errorf("expected command 'some-tool', got %q", hooks.Hooks["beforeShellExecution"][0].Command)
	}
}

func TestParseHooksJSON_LegacyFormat(t *testing.T) {
	data := `{"hooks":[{"event":"beforeShellExecution","command":"old-tool","timeout":5}]}`
	hooks, err := parseHooksJSON([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hooks.Version != 1 {
		t.Errorf("expected version 1, got %d", hooks.Version)
	}
	entries := hooks.Hooks["beforeShellExecution"]
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Command != "old-tool" {
		t.Errorf("expected command 'old-tool', got %q", entries[0].Command)
	}
	if entries[0].Timeout != 5 {
		t.Errorf("expected timeout 5, got %d", entries[0].Timeout)
	}
}

func TestParseHooksJSON_Malformed(t *testing.T) {
	_, err := parseHooksJSON([]byte("{bad json"))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseHooksJSON_VersionOnlyNoHooks(t *testing.T) {
	data := `{"version":2}`
	hooks, err := parseHooksJSON([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hooks.Version != 2 {
		t.Errorf("expected version 2, got %d", hooks.Version)
	}
	if hooks.Hooks == nil {
		t.Error("expected non-nil hooks map")
	}
}

func TestParseHooksJSON_HooksMapNoVersion(t *testing.T) {
	data := `{"hooks":{"beforeReadFile":[{"command":"test-cmd"}]}}`
	hooks, err := parseHooksJSON([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hooks.Version != 1 {
		t.Errorf("expected version 1 (default), got %d", hooks.Version)
	}
	if len(hooks.Hooks["beforeReadFile"]) != 1 {
		t.Errorf("expected 1 entry, got %d", len(hooks.Hooks["beforeReadFile"]))
	}
}

func TestParseHooksJSON_V1PreservesArgs(t *testing.T) {
	data := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"lint","args":["--fix","src/"],"timeout":30}]}}`
	hooks, err := parseHooksJSON([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entry := hooks.Hooks["beforeShellExecution"][0]
	if len(entry.Args) != 2 || entry.Args[0] != testArgFix || entry.Args[1] != "src/" {
		t.Errorf("expected args [--fix src/], got %v", entry.Args)
	}
}

func TestParseHooksJSON_LegacyPreservesArgs(t *testing.T) {
	data := `{"hooks":[{"event":"beforeShellExecution","command":"lint","args":["--fix"],"timeout":5}]}`
	hooks, err := parseHooksJSON([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entry := hooks.Hooks["beforeShellExecution"][0]
	if len(entry.Args) != 1 || entry.Args[0] != testArgFix {
		t.Errorf("expected args [--fix], got %v", entry.Args)
	}
}

func TestParseHooksJSON_LegacyEmptyEvent(t *testing.T) {
	data := `{"hooks":[{"event":"","command":"skip-me"},{"event":"beforeShellExecution","command":"keep-me"}]}`
	hooks, err := parseHooksJSON([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hooks.Hooks) != 1 {
		t.Errorf("expected 1 event group, got %d", len(hooks.Hooks))
	}
	if len(hooks.Hooks["beforeShellExecution"]) != 1 {
		t.Errorf("expected 1 entry for beforeShellExecution, got %d", len(hooks.Hooks["beforeShellExecution"]))
	}
}

func TestCursorInstallCmd_MergeLegacy(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	existing := `{"hooks":[{"event":"beforeShellExecution","command":"other-tool check","timeout":5}]}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}

	if hooks.Version != 1 {
		t.Errorf("expected version 1, got %d", hooks.Version)
	}

	shellEntries := hooks.Hooks["beforeShellExecution"]
	if len(shellEntries) != 2 {
		t.Fatalf("expected 2 beforeShellExecution entries, got %d", len(shellEntries))
	}

	found := false
	for _, h := range shellEntries {
		if h.Command == "other-tool check" {
			found = true
		}
	}
	if !found {
		t.Error("legacy hook was lost during upgrade+merge")
	}
}

func TestCursorInstallCmd_MergePreservesArgs(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	existing := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"lint","args":["--fix","src/"],"timeout":30}]}}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := CursorCmd()
	cmd.SetArgs([]string{"install", "--project", "--global=false"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(hooksPath))
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}

	for _, h := range hooks.Hooks["beforeShellExecution"] {
		if h.Command == "lint" {
			if len(h.Args) != 2 || h.Args[0] != testArgFix || h.Args[1] != "src/" {
				t.Errorf("args were modified: expected [--fix src/], got %v", h.Args)
			}
			return
		}
	}
	t.Error("lint hook with args was lost during merge")
}

// ---------------------------------------------------------------------------
// writeResponse coverage - normal path produces valid JSON
// ---------------------------------------------------------------------------

func TestWriteResponse_NormalPath(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	writeResponse(&buf, cursorResponse{
		Permission:  decisionAllow,
		UserMessage: "test message",
	})

	output := strings.TrimSpace(buf.String())
	var resp cursorResponse
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if resp.Permission != decisionAllow {
		t.Errorf("permission = %q, want %q", resp.Permission, decisionAllow)
	}
	if resp.UserMessage != "test message" {
		t.Errorf("user_message = %q, want %q", resp.UserMessage, "test message")
	}
}

func TestWriteResponse_DenyPath(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	writeResponse(&buf, cursorResponse{
		Permission:  decisionDeny,
		UserMessage: "blocked for testing",
	})

	output := strings.TrimSpace(buf.String())
	var resp cursorResponse
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if resp.Permission != decisionDeny {
		t.Errorf("permission = %q, want %q", resp.Permission, decisionDeny)
	}
}
