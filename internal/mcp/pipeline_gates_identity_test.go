// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

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

func TestEvaluateMCPInputGates_HTTPBindingReservedPrefixIdentity(t *testing.T) {
	const reservedTool = "a2a:message/send"
	toolsCallMsg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a2a:message/send","arguments":{}}}`)
	a2aMethodMsg := []byte(`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"messageId":"m1","role":"user","parts":[{"kind":"text","text":"hello"}]}}}`)

	tests := []struct {
		name          string
		frame         MCPFrame
		msg           []byte
		baselineTools []string
		wantIdentity  string
		// wantReason is the expected BindingReason; "" means the call is
		// accepted (no binding rejection).
		wantReason string
	}{
		{
			// Happy path: a reserved-prefix tool that IS in the raw tools/list
			// baseline is recognized (binding checks the raw name), while its
			// enforcement identity is escaped away from the A2A method space.
			name:          "tools/call reserved-prefix tool present in baseline is accepted",
			frame:         MCPFrame{Method: methodToolsCall, ToolCallName: reservedTool},
			msg:           toolsCallMsg,
			baselineTools: []string{reservedTool},
			wantIdentity:  "tool:a2a:message/send",
			wantReason:    "",
		},
		{
			// Attack path: an A2A method must fail closed as unknown even when
			// the raw baseline literally contains "a2a:<method>" as a tool name.
			// A2A methods are not members of the tools/list inventory, so the
			// escaped enforcement identity must not let a real tool named
			// "a2a:message/send" satisfy the A2A method binding.
			name:          "a2a method fails closed even with a literal a2a: tool in baseline",
			frame:         MCPFrame{Method: "message/send"},
			msg:           a2aMethodMsg,
			baselineTools: []string{reservedTool},
			wantIdentity:  "a2a:message/send",
			// No A2A method baseline was ever established (only MCP tools were
			// seeded), so the correct classification is no-baseline, not
			// unknown: an MCP tool inventory does not satisfy the A2A namespace.
			wantReason: bindingReasonNoBaseline,
		},
		{
			// Attack path: a reserved-prefix tools/call whose raw name is absent
			// from the baseline is blocked as unknown (a regression to
			// escaped-vs-raw matching would let it slip through).
			name:          "tools/call reserved-prefix tool absent from baseline is blocked",
			frame:         MCPFrame{Method: methodToolsCall, ToolCallName: reservedTool},
			msg:           toolsCallMsg,
			baselineTools: []string{"search"},
			wantIdentity:  "tool:a2a:message/send",
			wantReason:    bindingReasonUnknownTool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline := tools.NewToolBaseline()
			baseline.SetKnownTools(tt.baselineTools)
			eval := EvaluateMCPInputGates(
				t.Context(),
				tt.frame,
				tt.msg,
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

			if eval.EnforcementIdentity != tt.wantIdentity {
				t.Fatalf("EnforcementIdentity = %q, want %q", eval.EnforcementIdentity, tt.wantIdentity)
			}
			if tt.wantReason == "" {
				if eval.BindingReason != "" || eval.BindingAction != "" {
					t.Fatalf("expected acceptance, got binding action=%q reason=%q", eval.BindingAction, eval.BindingReason)
				}
				return
			}
			if eval.BindingReason != tt.wantReason {
				t.Fatalf("BindingReason = %q, want %q", eval.BindingReason, tt.wantReason)
			}
			if eval.BindingAction != config.ActionBlock {
				t.Fatalf("BindingAction = %q, want %q", eval.BindingAction, config.ActionBlock)
			}
		})
	}
}

func TestEvaluateMCPInputGates_A2ABindingAllowsPinnedMethodOnly(t *testing.T) {
	knownMsg := testA2ARequest(1, testA2AMethod)
	unknownMsg := testA2ARequest(2, testA2ASecondMethod)

	baseline := tools.NewToolBaseline()
	baseline.SetKnownTools([]string{"read_file"})
	baseline.SetKnownA2AMethods([]string{testA2AMethod})

	tests := []struct {
		name       string
		msg        []byte
		wantReason string
	}{
		{
			name:       "pinned a2a method allowed",
			msg:        knownMsg,
			wantReason: "",
		},
		{
			name:       "unknown a2a method fails closed",
			msg:        unknownMsg,
			wantReason: bindingReasonUnknownTool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := ParseMCPFrame(tt.msg)
			eval := EvaluateMCPInputGates(
				t.Context(),
				frame,
				tt.msg,
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

			if tt.wantReason == "" {
				if eval.BindingReason != "" || eval.BindingAction != "" {
					t.Fatalf("expected acceptance, got binding action=%q reason=%q", eval.BindingAction, eval.BindingReason)
				}
				return
			}
			if eval.BindingReason != tt.wantReason {
				t.Fatalf("BindingReason = %q, want %q", eval.BindingReason, tt.wantReason)
			}
			if eval.BindingAction != config.ActionBlock {
				t.Fatalf("BindingAction = %q, want %q", eval.BindingAction, config.ActionBlock)
			}
		})
	}
}

// Regression for two fail-open holes: NoBaselineAction must fire independently
// of UnknownAction, and A2A no-baseline must be decided only by the A2A method
// baseline (an MCP tool baseline must not downgrade it to "unknown").
func TestEvaluateSessionBinding_NoBaselineFailClosed(t *testing.T) {
	empty := tools.NewToolBaseline()
	mcpOnly := tools.NewToolBaseline()
	mcpOnly.SetKnownTools([]string{"search"})
	cases := []struct {
		name       string
		check      sessionBindingCheck
		wantAction string
		wantReason string
	}{
		{
			name:       "toolcall pre-baseline blocks even with UnknownAction unset",
			check:      sessionBindingCheck{Baseline: empty, Method: methodToolsCall, ToolName: "x", NoBaselineAction: config.ActionBlock, UnknownAction: ""},
			wantAction: config.ActionBlock,
			wantReason: bindingReasonNoBaseline,
		},
		{
			name:       "a2a with mcp baseline but no a2a baseline uses NoBaselineAction, not UnknownAction",
			check:      sessionBindingCheck{Baseline: mcpOnly, Method: "message/send", EnforcementIdentity: "a2a:message/send", NoBaselineAction: config.ActionBlock, UnknownAction: config.ActionAllow},
			wantAction: config.ActionBlock,
			wantReason: bindingReasonNoBaseline,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, r := evaluateSessionBinding(tc.check)
			if a != tc.wantAction || r != tc.wantReason {
				t.Fatalf("evaluateSessionBinding = (%q,%q), want (%q,%q)", a, r, tc.wantAction, tc.wantReason)
			}
		})
	}
}

func TestEvaluateSessionBinding_A2AUnknownMethodWithBaseline(t *testing.T) {
	baseline := tools.NewToolBaseline()
	baseline.SetKnownA2AMethods([]string{"SendMessage"})
	frame := MCPFrame{Method: "GetTask"}
	enforcementIdentity := mcpFrameCollisionSafeCallableIdentity(frame, frame.Method)

	if !baseline.HasA2AMethodBaseline() {
		t.Fatal("expected A2A baseline to be established")
	}
	if baseline.IsKnownA2AMethod("GetTask") {
		t.Fatal("GetTask must not be known before exercising unknown-method path")
	}
	if want := a2aBaselineIdentity("GetTask"); enforcementIdentity != want {
		t.Fatalf("production A2A identity = %q, want %q", enforcementIdentity, want)
	}

	action, reason := evaluateSessionBinding(sessionBindingCheck{
		Baseline:            baseline,
		Frame:               frame,
		EnforcementIdentity: enforcementIdentity,
		UnknownAction:       config.ActionWarn,
		NoBaselineAction:    config.ActionBlock,
	})
	if action != config.ActionWarn {
		t.Fatalf("action = %q, want %q", action, config.ActionWarn)
	}
	if reason != bindingReasonUnknownTool {
		t.Fatalf("reason = %q, want %q", reason, bindingReasonUnknownTool)
	}
}

func TestEvaluateSessionBinding_EarlyReturnsNonBlocking(t *testing.T) {
	baseline := tools.NewToolBaseline()
	baseline.SetKnownTools([]string{"search"})

	cases := []struct {
		name  string
		check sessionBindingCheck
	}{
		{
			name: "nil baseline",
			check: sessionBindingCheck{
				Baseline:         nil,
				Method:           methodToolsCall,
				ToolName:         "search",
				UnknownAction:    config.ActionBlock,
				NoBaselineAction: config.ActionBlock,
			},
		},
		{
			name: "non-callable method",
			check: sessionBindingCheck{
				Baseline:         baseline,
				Method:           "initialize",
				UnknownAction:    config.ActionBlock,
				NoBaselineAction: config.ActionBlock,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, reason := evaluateSessionBinding(tc.check)
			if action != "" || reason != "" {
				t.Fatalf("evaluateSessionBinding = (%q,%q), want non-blocking empty action and reason", action, reason)
			}
		})
	}
}
