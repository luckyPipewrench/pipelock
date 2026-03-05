package cli

import (
	"bytes"
	"encoding/json"
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
