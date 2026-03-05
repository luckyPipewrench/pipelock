package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// claudeCodeResponse is a test assertion type for Claude Code hook responses.
type claudeCodeResponse struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	} `json:"hookSpecificOutput"`
}

func TestClaudeHookCmd_CleanBash(t *testing.T) {
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la","description":"list files"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionAllow {
		t.Errorf("expected allow, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_BlocksSecretInBash(t *testing.T) {
	secret := "sk-ant-" + "api03-AABBCCDDEE123456789012345678901234"
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl -H 'Authorization: Bearer ` + secret + `' https://api.example.com"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionDeny {
		t.Errorf("expected deny, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_CleanWebFetch(t *testing.T) {
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com/docs"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionAllow {
		t.Errorf("expected allow for clean URL, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_BlocksSecretInWrite(t *testing.T) {
	secret := "ghp_" + "ABCDEFghijklmnopqrstuvwxyz0123456789"
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/config.env","content":"TOKEN=` + secret + `"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionDeny {
		t.Errorf("expected deny for secret in Write, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_MalformedJSON(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte("{not valid")))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionDeny {
		t.Errorf("malformed input should deny, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_EmptyStdin(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader(nil))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionDeny {
		t.Errorf("empty stdin should deny, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_UnknownTool_DefaultsAllow(t *testing.T) {
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"SomeNewTool","tool_input":{},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionAllow {
		t.Errorf("unknown tool should allow by default, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_ExitCodeMode(t *testing.T) {
	secret := "sk-ant-" + "api03-AABBCCDDEE123456789012345678901234"
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl ` + secret + `"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook", "--exit-code"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	// In exit-code mode, deny returns ExitError with code 2.
	if err == nil {
		t.Fatal("expected exit code error for blocked action")
	}
	if ExitCodeOf(err) != 2 {
		t.Errorf("expected exit code 2, got %d", ExitCodeOf(err))
	}
}

func TestClaudeHookCmd_MCPTool(t *testing.T) {
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"mcp__filesystem__read_file","tool_input":{"path":"/tmp/readme.txt"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionAllow {
		t.Errorf("expected allow for clean MCP tool, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_OversizedStdin(t *testing.T) {
	big := make([]byte, 10<<20+100)
	for i := range big {
		big[i] = 'x'
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader(big))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionDeny {
		t.Errorf("expected deny for oversized input, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_OnlyJSONOnStdout(t *testing.T) {
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
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

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("stdout line is not valid JSON: %v", err)
	}
}

func TestClaudeHookCmd_EditTool(t *testing.T) {
	secret := "ghp_" + "ABCDEFghijklmnopqrstuvwxyz0123456789"
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/tmp/config.py","old_string":"placeholder","new_string":"TOKEN='` + secret + `'"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionDeny {
		t.Errorf("expected deny for secret in Edit new_string, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHookCmd_ExitCodeMode_Allow(t *testing.T) {
	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"},"tool_use_id":"t1"}`

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "hook", "--exit-code"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error for allowed action in exit-code mode, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Settings.json parsing tests (Task 3)
// ---------------------------------------------------------------------------

func TestParseClaudeSettings_Empty(t *testing.T) {
	settings, err := parseClaudeSettings([]byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if settings.Hooks == nil {
		t.Error("expected non-nil hooks map")
	}
}

func TestParseClaudeSettings_WithExistingHooks(t *testing.T) {
	data := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other-tool check"}]}]}}`
	settings, err := parseClaudeSettings([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(settings.Hooks["PreToolUse"]) != 1 {
		t.Errorf("expected 1 PreToolUse group, got %d", len(settings.Hooks["PreToolUse"]))
	}
}

func TestParseClaudeSettings_Malformed(t *testing.T) {
	_, err := parseClaudeSettings([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestMergeClaudeHooks_Fresh(t *testing.T) {
	settings := &claudeSettings{Hooks: make(map[string][]claudeMatcherGroup)}
	merged := mergeClaudeHooks(settings, "/usr/local/bin/pipelock")

	groups := merged.Hooks["PreToolUse"]
	if len(groups) != 2 {
		t.Fatalf("expected 2 matcher groups (builtin + MCP), got %d", len(groups))
	}
}

func TestMergeClaudeHooks_PreservesOtherHooks(t *testing.T) {
	settings := &claudeSettings{
		Hooks: map[string][]claudeMatcherGroup{
			"PreToolUse": {
				{Matcher: "Bash", Hooks: []claudeHookEntry{{Type: "command", Command: "other-tool"}}},
			},
			"SessionStart": {
				{Hooks: []claudeHookEntry{{Type: "command", Command: "startup.sh"}}},
			},
		},
	}
	merged := mergeClaudeHooks(settings, "/usr/local/bin/pipelock")

	// SessionStart untouched.
	if len(merged.Hooks["SessionStart"]) != 1 {
		t.Error("SessionStart hooks were modified")
	}

	// PreToolUse: other-tool preserved + 2 pipelock groups added.
	groups := merged.Hooks["PreToolUse"]
	otherFound := false
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Command == "other-tool" {
				otherFound = true
			}
		}
	}
	if !otherFound {
		t.Error("non-pipelock hook was lost during merge")
	}
}

func TestMergeClaudeHooks_Idempotent(t *testing.T) {
	settings := &claudeSettings{Hooks: make(map[string][]claudeMatcherGroup)}
	first := mergeClaudeHooks(settings, "/usr/local/bin/pipelock")
	second := mergeClaudeHooks(first, "/usr/local/bin/pipelock")

	// Count pipelock groups (should be same after second merge).
	count := 0
	for _, g := range second.Hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if isClaudePipelockHook(h) {
				count++
			}
		}
	}
	// Expect exactly 2 pipelock hook entries (builtin + MCP matchers).
	if count != 2 {
		t.Errorf("expected 2 pipelock entries after idempotent merge, got %d", count)
	}
}

func TestRemoveClaudeHooks(t *testing.T) {
	settings := &claudeSettings{Hooks: make(map[string][]claudeMatcherGroup)}
	installed := mergeClaudeHooks(settings, "/usr/local/bin/pipelock")
	removed := removeClaudeHooks(installed)

	if len(removed.Hooks["PreToolUse"]) != 0 {
		t.Errorf("expected 0 PreToolUse groups after remove, got %d", len(removed.Hooks["PreToolUse"]))
	}
}

func TestMergeClaudeHooks_PreservesSharedGroupHooks(t *testing.T) {
	// A user has their own hook AND a pipelock hook in the same matcher group.
	// Merge should keep the user hook and replace only pipelock.
	settings := &claudeSettings{
		Hooks: map[string][]claudeMatcherGroup{
			"PreToolUse": {
				{Matcher: "Bash", Hooks: []claudeHookEntry{
					{Type: "command", Command: "my-linter check"},
					{Type: "command", Command: "/usr/bin/pipelock claude hook"},
				}},
			},
		},
	}
	merged := mergeClaudeHooks(settings, "/usr/local/bin/pipelock")

	// User hook preserved.
	found := false
	for _, g := range merged.Hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if h.Command == "my-linter check" {
				found = true
			}
		}
	}
	if !found {
		t.Error("user hook in shared group was lost during merge")
	}
}

func TestIsClaudePipelockHook_NoFalsePositive(t *testing.T) {
	// "echo claude hook" should NOT match; only commands ending with "claude hook".
	h := claudeHookEntry{Type: "command", Command: "echo claude hook something"}
	if isClaudePipelockHook(h) {
		t.Error("false positive: unrelated command matched as pipelock hook")
	}

	// Actual pipelock hook should match.
	h2 := claudeHookEntry{Type: "command", Command: "/usr/bin/pipelock claude hook"}
	if !isClaudePipelockHook(h2) {
		t.Error("actual pipelock hook not detected")
	}
}

func TestRemoveClaudeHooks_PreservesSharedGroupHooks(t *testing.T) {
	settings := &claudeSettings{
		Hooks: map[string][]claudeMatcherGroup{
			"PreToolUse": {
				{Matcher: "Bash", Hooks: []claudeHookEntry{
					{Type: "command", Command: "my-hook"},
					{Type: "command", Command: "/usr/bin/pipelock claude hook"},
				}},
			},
		},
	}
	removed := removeClaudeHooks(settings)

	groups := removed.Hooks["PreToolUse"]
	if len(groups) != 1 {
		t.Fatalf("expected 1 group (user hook preserved), got %d", len(groups))
	}
	if groups[0].Hooks[0].Command != "my-hook" {
		t.Error("user hook in shared group was lost during remove")
	}
}

func TestRemoveClaudeHooks_PreservesOthers(t *testing.T) {
	settings := &claudeSettings{
		Hooks: map[string][]claudeMatcherGroup{
			"PreToolUse": {
				{Matcher: "Bash", Hooks: []claudeHookEntry{{Type: "command", Command: "other-tool"}}},
				{Matcher: claudeBuiltinMatcher, Hooks: []claudeHookEntry{{Type: "command", Command: "/usr/bin/pipelock claude hook"}}},
			},
		},
	}
	removed := removeClaudeHooks(settings)

	groups := removed.Hooks["PreToolUse"]
	if len(groups) != 1 {
		t.Fatalf("expected 1 group after remove, got %d", len(groups))
	}
	if groups[0].Hooks[0].Command != "other-tool" {
		t.Error("non-pipelock hook was removed")
	}
}

// ---------------------------------------------------------------------------
// Setup command tests (Task 4)
// ---------------------------------------------------------------------------

func TestClaudeSetupCmd_DryRun(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup", "--dry-run"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Would write to") {
		t.Error("dry-run should show 'Would write to'")
	}
	if !strings.Contains(output, "claude hook") {
		t.Error("dry-run should show 'claude hook' command")
	}
}

func TestClaudeSetupCmd_Global(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup", "--global"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	data, err := os.ReadFile(filepath.Clean(settingsPath))
	if err != nil {
		t.Fatalf("settings.json not created: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid settings.json: %v", err)
	}
	if _, ok := raw["hooks"]; !ok {
		t.Error("settings.json missing hooks section")
	}
}

func TestClaudeSetupCmd_MergeExisting(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	existing := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"startup.sh"}]}]},"effortLevel":"high"}`
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(settingsPath))
	if err != nil {
		t.Fatal(err)
	}

	// effortLevel preserved.
	if !strings.Contains(string(data), `"effortLevel"`) {
		t.Error("effortLevel field was lost during merge")
	}
	// SessionStart preserved.
	if !strings.Contains(string(data), "startup.sh") {
		t.Error("SessionStart hook was lost during merge")
	}
	// PreToolUse added.
	if !strings.Contains(string(data), "PreToolUse") {
		t.Error("PreToolUse hooks not added")
	}
}

func TestClaudeSetupCmd_Idempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	for i := range 2 {
		cmd := rootCmd()
		cmd.SetArgs([]string{"claude", "setup"})
		cmd.SetOut(&strings.Builder{})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("run %d: unexpected error: %v", i+1, err)
		}
	}

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	data, err := os.ReadFile(filepath.Clean(settingsPath))
	if err != nil {
		t.Fatal(err)
	}

	// Count occurrences of "claude hook" (should be exactly 2: builtin + MCP).
	count := strings.Count(string(data), "claude hook")
	if count != 2 {
		t.Errorf("expected 2 'claude hook' entries after idempotent setup, got %d", count)
	}
}

func TestClaudeSetupCmd_Backup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	original := `{"effortLevel":"high"}`
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup"})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	backupData, err := os.ReadFile(filepath.Clean(settingsPath + ".bak"))
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if string(backupData) != original {
		t.Errorf("backup mismatch: got %q, want %q", string(backupData), original)
	}
}

func TestClaudeSetupCmd_Project(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup", "--project"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	if _, err := os.Stat(settingsPath); err != nil {
		t.Fatalf("project settings.json not created: %v", err)
	}
}

func TestClaudeSetupCmd_CorruptExisting(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for corrupt settings.json")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestClaudeSetupCmd_InvalidFlags(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup", "--global", "--project"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when both --global and --project are set")
	}
}

// ---------------------------------------------------------------------------
// Remove command tests (Task 5)
// ---------------------------------------------------------------------------

func TestClaudeRemoveCmd_RemovesHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Install first.
	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Remove.
	cmd = rootCmd()
	cmd.SetArgs([]string{"claude", "remove"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove: %v", err)
	}

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	data, err := os.ReadFile(filepath.Clean(settingsPath))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), "claude hook") {
		t.Error("pipelock hooks not removed")
	}
}

func TestClaudeRemoveCmd_PreservesOtherHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	existing := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other-tool"}]},{"matcher":"Bash|WebFetch|Write|Edit","hooks":[{"type":"command","command":"/usr/bin/pipelock claude hook","timeout":10}]}]}}`
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "remove"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(settingsPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "other-tool") {
		t.Error("non-pipelock hook was removed")
	}
	if strings.Contains(string(data), "claude hook") {
		t.Error("pipelock hook not removed")
	}
}

func TestClaudeRemoveCmd_NoSettingsFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "remove"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	// Should succeed gracefully (nothing to remove).
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no settings") {
		t.Error("expected 'no settings' message")
	}
}

func TestClaudeRemoveCmd_DryRun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Install first.
	cmd := rootCmd()
	cmd.SetArgs([]string{"claude", "setup"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// Dry-run remove.
	cmd = rootCmd()
	cmd.SetArgs([]string{"claude", "remove", "--dry-run"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(buf.String(), "Would write to") {
		t.Error("dry-run should show 'Would write to'")
	}

	// Hooks should still exist (dry-run didn't modify).
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	data, err := os.ReadFile(filepath.Clean(settingsPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "claude hook") {
		t.Error("dry-run should not modify the file")
	}
}
