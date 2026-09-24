// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runCursorHookPayload(t *testing.T, payload map[string]string) cursorResponse {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	cmd := CursorCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader(b))
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp cursorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
	}
	return resp
}

// Only shell commands get the environment-lookup rule. The same text in an
// MCP tool call is sent to a server, so it keeps counting as a credential.
func TestCursorHookCmd_EnvLookupScopedToShell(t *testing.T) {
	kw := "to" + "ken"
	lookup := `python3 -c 'import os; ` + kw + `=os.environ.get("SLACK_BOT_TOKEN"); assert ` + kw + `'`

	shell := runCursorHookPayload(t, map[string]string{
		"hook_event_name": "beforeShellExecution", "command": lookup, "cwd": "/tmp",
		"conversation_id": "abc", "generation_id": "def",
	})
	if shell.Permission != decisionAllow {
		t.Fatalf("shell environment lookup: permission=%q message=%q", shell.Permission, shell.UserMessage)
	}
	toolInput, err := json.Marshal(map[string]string{"script": lookup})
	if err != nil {
		t.Fatalf("marshal tool input: %v", err)
	}
	mcp := runCursorHookPayload(t, map[string]string{
		"hook_event_name": "beforeMCPExecution", "server": "test", "tool_name": "run",
		"tool_input": string(toolInput), "conversation_id": "abc", "generation_id": "def",
	})
	if mcp.Permission == decisionAllow {
		t.Fatalf("MCP tool call with the same text allowed")
	}
}
