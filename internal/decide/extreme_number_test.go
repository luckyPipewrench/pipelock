// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"context"
	"testing"
)

func TestExtremeNumberKeepsToolInputInspection(t *testing.T) {
	cfg, sc, pc := testSetup(t)
	secret := "sk-ant-" + "api03-AABBCCDDEE123456789012345678901234"
	for _, num := range []string{"1.5", "1e999", "-1e999", "1E+400", "[1e999]", "1e-999"} {
		t.Run(num, func(t *testing.T) {
			for _, text := range []string{secret, "weather forecast"} {
				input := `{"query":"` + text + `","n":` + num + `}`
				for _, action := range []Action{
					{Source: "cursor", Kind: EventMCPExecution, MCP: &MCPPayload{Server: "vendor", ToolName: "web_search", ToolInput: input}},
					{Source: "claude", Kind: EventToolUse, ToolUse: &ToolUsePayload{ToolName: "mcp__vendor__web_search", ToolInput: input}},
				} {
					d := Decide(context.Background(), cfg, sc, pc, action)
					want := "allow"
					if text == secret {
						want = "deny"
					}
					if string(d.Outcome) != want {
						t.Fatalf("kind=%s secret=%v: outcome=%s, want %s", action.Kind, text == secret, d.Outcome, want)
					}
				}
			}
		})
	}
}
