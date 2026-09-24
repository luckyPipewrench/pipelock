// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"strings"
	"testing"
)

func claudePreToolUsePayload(t *testing.T, toolName string, toolInput map[string]string) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"session_id":      "s1",
		"hook_event_name": "PreToolUse",
		"tool_name":       toolName,
		"tool_input":      toolInput,
		"tool_use_id":     "t1",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(b)
}

// Only shell commands get the environment-lookup rule. The same text in an
// MCP tool call is sent to a server, so it keeps counting as a credential.
func TestClaudeHookCmd_EnvLookupScopedToShell(t *testing.T) {
	kw := "to" + "ken"
	secret := strings.Join([]string{"q7Hx", "2mPv", "9kLw", "4nRt"}, "")
	lookup := `python3 -c 'import os; ` + kw + `=os.environ.get("SLACK_BOT_TOKEN"); assert ` + kw + `'`

	if got := runClaudeHookForEvent(t, claudePreToolUsePayload(t, "Bash", map[string]string{"command": lookup})).HookSpecificOutput.PermissionDecision; got == decisionDeny {
		t.Fatalf("Bash environment lookup denied")
	}
	if got := runClaudeHookForEvent(t, claudePreToolUsePayload(t, "mcp__server__run", map[string]string{"script": lookup})).HookSpecificOutput.PermissionDecision; got != decisionDeny {
		t.Fatalf("MCP tool call with the same text: decision=%q, want deny", got)
	}
	literal := `python3 -c 'import os; ` + kw + `=` + secret + `; print(1)'`
	if got := runClaudeHookForEvent(t, claudePreToolUsePayload(t, "Bash", map[string]string{"command": literal})).HookSpecificOutput.PermissionDecision; got != decisionDeny {
		t.Fatalf("Bash literal: decision=%q, want deny", got)
	}
}
