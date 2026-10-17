// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardJSONDecisionCorpus(t *testing.T) {
	cfg, sc, pc := testSetup(t)
	t.Cleanup(sc.Close)
	for _, tt := range cardtest.TransportCases() {
		t.Run(tt.Name, func(t *testing.T) {
			for _, action := range []Action{
				{Kind: EventMCPExecution, MCP: &MCPPayload{Server: "vendor", ToolName: "report", ToolInput: tt.Body}},
				{Kind: EventToolUse, ToolUse: &ToolUsePayload{ToolName: "report", ToolInput: tt.Body}},
			} {
				d := Decide(t.Context(), cfg, sc, pc, action)
				if (d.Outcome == Allow) != (tt.Clean || tt.Warn) {
					t.Fatalf("kind=%s outcome=%s clean=%v warn=%v", action.Kind, d.Outcome, tt.Clean, tt.Warn)
				}
				if tt.Warn && len(d.Evidence) == 0 {
					t.Fatal("informational evidence missing")
				}
			}
		})
	}
}
