package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	decisionAllow = "allow"
	decisionDeny  = "deny"
)

// errReader is an io.Reader that always returns an error.
type errReader struct {
	err error
}

func (r *errReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func TestCursorCmd_InRootHelp(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--help"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "cursor") {
		t.Error("root help should list cursor command")
	}
}

func TestCursorHookCmd_Help(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook", "--help"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	for _, want := range []string{"--config", "stdin", "permission"} {
		if !strings.Contains(output, want) {
			t.Errorf("help should mention %q", want)
		}
	}
}

func TestCursorHookCmd_CleanShellCommand(t *testing.T) {
	input := `{"hook_event_name":"beforeShellExecution","command":"ls -la","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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
	// Split the secret across concatenation to avoid self-scan.
	secret := "sk-ant-" + "api03-AABBCCDDEE123456789012345678901234"
	input := `{"hook_event_name":"beforeShellExecution","command":"curl -H 'Authorization: Bearer ` + secret + `' https://api.example.com","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	// Must not return error (always exit 0).
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must produce valid JSON on stdout.
	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON on malformed input: %v\noutput: %s", err, buf.String())
	}
	if resp.Permission != decisionDeny {
		t.Errorf("malformed input should deny, got %s", resp.Permission)
	}
}

func TestCursorHookCmd_EmptyStdin(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	stdoutBuf := &strings.Builder{}
	stderrBuf := &strings.Builder{}
	cmd.SetOut(stdoutBuf)
	cmd.SetErr(stderrBuf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Stdout must contain ONLY valid JSON (one line).
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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
	// Write a minimal config that disables tool policy.
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

	// rm -rf should be allowed when policy is explicitly disabled.
	input := `{"hook_event_name":"beforeShellExecution","command":"rm -rf /tmp/test","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook", "--config", cfgPath})
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
	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--dry-run"})
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

	// Change to temp dir for --project.
	chdirTemp(t, dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project", "--global=false"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	data, err := os.ReadFile(hooksPath) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("hooks.json not created: %v", err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 hooks, got %d", len(hooks.Hooks))
	}
}

func TestCursorInstallCmd_Merge(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Pre-create hooks.json with an existing non-pipelock hook.
	existing := `{"hooks":[{"event":"beforeShellExecution","command":"other-tool check","timeout":5}]}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project", "--global=false"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(hooksPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}

	// Should have the original hook + 3 pipelock hooks = 4 total.
	if len(hooks.Hooks) != 4 {
		t.Errorf("expected 4 hooks after merge, got %d", len(hooks.Hooks))
	}

	// Original hook should still be present.
	found := false
	for _, h := range hooks.Hooks {
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

	// Install twice.
	for i := range 2 {
		cmd := rootCmd()
		cmd.SetArgs([]string{"cursor", "install", "--project", "--global=false"})
		cmd.SetOut(&strings.Builder{})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("run %d: unexpected error: %v", i+1, err)
		}
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	data, err := os.ReadFile(hooksPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}

	// Should still be exactly 3 hooks, no duplicates.
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 hooks after idempotent install, got %d", len(hooks.Hooks))
	}
}

func TestCursorInstallCmd_Backup(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Pre-create hooks.json.
	original := `{"hooks":[]}`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project", "--global=false"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Backup should exist.
	backupPath := hooksPath + ".bak"
	backupData, err := os.ReadFile(backupPath) //nolint:gosec // test path
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project", "--global=false"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no temp files left behind.
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

	// Verify hooks.json is valid.
	data, err := os.ReadFile(filepath.Join(cursorDir, "hooks.json")) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("hooks.json is invalid after atomic write: %v", err)
	}
}

func TestCursorInstallCmd_UpgradePath(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Pre-create hooks.json with a stale pipelock entry (old binary path).
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project", "--global=false"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(hooksPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}

	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}

	// Should still have exactly 3 entries (replaced, not duplicated).
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 hooks after upgrade, got %d", len(hooks.Hooks))
	}

	// None should reference the old path.
	for _, h := range hooks.Hooks {
		if strings.Contains(h.Command, "/old/path") {
			t.Errorf("stale entry not updated: %s", h.Command)
		}
		if !strings.Contains(h.Command, "cursor hook") {
			t.Errorf("hook command missing 'cursor hook': %s", h.Command)
		}
		// Timeout should be updated to 10 (our default).
		if h.Timeout != 10 {
			t.Errorf("timeout not updated: got %d, want 10", h.Timeout)
		}
	}
}

func TestCursorInstallCmd_InvalidFlags(t *testing.T) {
	t.Run("both flags", func(t *testing.T) {
		cmd := rootCmd()
		cmd.SetArgs([]string{"cursor", "install", "--global", "--project"})
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
	// When neither --global nor --project is given, defaults to global.
	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--dry-run"})
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
	// --project alone (without --global) should work.
	dir := t.TempDir()
	chdirTemp(t, dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project"})
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
	// Override HOME to a temp dir so --global writes there.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--global"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hooksPath := filepath.Join(dir, ".cursor", "hooks.json")
	data, err := os.ReadFile(hooksPath) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("hooks.json not created at global path: %v", err)
	}
	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("invalid hooks.json: %v", err)
	}
	if len(hooks.Hooks) != 3 {
		t.Errorf("expected 3 hooks, got %d", len(hooks.Hooks))
	}
	// Verify output confirms global path.
	if !strings.Contains(buf.String(), "Installed pipelock hooks") {
		t.Error("expected installation confirmation message")
	}
}

func TestCursorHookCmd_StdinReadError(t *testing.T) {
	// Use an io.Reader that returns an error.
	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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
	// Create hooks.json as a directory to trigger a read error (not ENOENT).
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Create hooks.json as a directory (causes read error, not parse error).
	hooksAsDir := filepath.Join(cursorDir, "hooks.json")
	if err := os.MkdirAll(hooksAsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project"})
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
	// Config with warn-level policy action: rm -rf should be allowed with advisory.
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook", "--config", cfgPath})
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
	// Verify beforeReadFile with credential path is denied.
	input := `{"hook_event_name":"beforeReadFile","file_path":"/home/user/.ssh/id_rsa","conversation_id":"abc","generation_id":"def"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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
	// Bad config file should produce deny JSON, not crash.
	input := `{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook", "--config", "/nonexistent/pipelock.yaml"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	// Should always exit 0 (no error returned).
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

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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
	// Send >10MB to trigger the size cap.
	big := make([]byte, 10<<20+100) // 10MB + 100 bytes
	for i := range big {
		big[i] = 'x'
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "hook"})
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

	// Write invalid JSON to hooks.json.
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}

	chdirTemp(t, dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"cursor", "install", "--project", "--global=false"})
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

// chdirTemp changes the working directory to dir and registers a cleanup
// to restore the original. Returns the original directory.
func chdirTemp(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Errorf("failed to restore working directory: %v", err)
		}
	})
}
