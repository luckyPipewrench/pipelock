package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

// TestMCPFrameEnforcementIdentity_ReservedPrefixCollision proves that a tool
// literally named with a reserved identity prefix (a2a: / tool:) cannot share
// the DoW/chain/budget enforcement identity of an A2A method. Before the fix,
// mcpFrameEnforcementIdentity returned the raw tool name, so a tools/call for a
// tool named "a2a:message/send" produced the identity "a2a:message/send" — byte
// identical to a2aBaselineIdentity("message/send"). A budget/chain rule keyed on
// the A2A method would then match (and be satisfied by) that tool, and vice
// versa. Ordinary tool names must stay raw so existing raw-name budget/chain
// configs keep matching (no silent fail-open).
func TestMCPFrameEnforcementIdentity_ReservedPrefixCollision(t *testing.T) {
	toolsCall := func(name string) MCPFrame {
		return MCPFrame{Method: methodToolsCall, ToolCallName: name}
	}
	a2aFrame := func(method string) MCPFrame {
		return MCPFrame{Method: method}
	}

	tests := []struct {
		name  string
		frame MCPFrame
		want  string
	}{
		{
			// The collision case: a tool named exactly like the A2A method
			// identity must be namespaced away from it.
			name:  "tool with a2a: prefix is escaped",
			frame: toolsCall("a2a:message/send"),
			want:  "tool:a2a:message/send",
		},
		{
			name:  "tool with a2a: prefix (CamelCase method) is escaped",
			frame: toolsCall("a2a:SendMessage"),
			want:  "tool:a2a:SendMessage",
		},
		{
			name:  "tool with tool: prefix is escaped",
			frame: toolsCall("tool:foo"),
			want:  "tool:tool:foo",
		},
		{
			// No fail-open: an ordinary tool name is returned verbatim so
			// existing raw-name DoW/chain/budget configs still match.
			name:  "ordinary tool name stays raw",
			frame: toolsCall("search"),
			want:  "search",
		},
		{
			// The A2A method identity itself is unchanged.
			name:  "a2a method identity unchanged",
			frame: a2aFrame("message/send"),
			want:  "a2a:message/send",
		},
		{
			name:  "empty tool name",
			frame: toolsCall(""),
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mcpFrameEnforcementIdentity(tt.frame, "")
			if got != tt.want {
				t.Fatalf("mcpFrameEnforcementIdentity(%+v) = %q, want %q", tt.frame, got, tt.want)
			}
		})
	}

	// Explicit collision guard: the escaped tool identity must never equal the
	// A2A method identity it would otherwise impersonate.
	toolID := mcpFrameEnforcementIdentity(toolsCall("a2a:message/send"), "")
	methodID := mcpFrameEnforcementIdentity(a2aFrame("message/send"), "")
	if toolID == methodID {
		t.Fatalf("collision not closed: tool identity %q equals A2A method identity %q", toolID, methodID)
	}
}

func TestEvaluateMCPInputGates_HTTPBindingUsesRawToolInventoryForReservedPrefixTool(t *testing.T) {
	const toolName = "a2a:message/send"

	baseline := tools.NewToolBaseline()
	baseline.SetKnownTools([]string{toolName})

	frame := MCPFrame{Method: methodToolsCall, ToolCallName: toolName}
	eval := EvaluateMCPInputGates(
		t.Context(),
		frame,
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a2a:message/send","arguments":{}}}`),
		"session-1",
		MCPProxyOpts{
			ToolCfg: &tools.ToolScanConfig{
				Baseline:                baseline,
				BindingUnknownAction:    config.ActionBlock,
				BindingNoBaselineAction: config.ActionBlock,
			},
		},
		config.ActionBlock,
		config.ActionBlock,
		false,
	)

	if eval.EnforcementIdentity != "tool:a2a:message/send" {
		t.Fatalf("EnforcementIdentity = %q, want escaped tool identity", eval.EnforcementIdentity)
	}
	if eval.BindingReason != "" || eval.BindingAction != "" {
		t.Fatalf("reserved-prefix tool present in raw tools/list baseline was rejected by binding: action=%q reason=%q", eval.BindingAction, eval.BindingReason)
	}
}
