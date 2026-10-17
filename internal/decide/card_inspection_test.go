// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestJSONInspectionDecisionAudit(t *testing.T) {
	cfg, sc, pc := testSetup(t)
	t.Cleanup(sc.Close)
	for _, enforce := range []bool{true, false} {
		cfg.Enforce = &enforce
		for _, tt := range []struct {
			body string
			want Outcome
		}{
			{`[1e10001]`, Deny}, {`[1,2]`, Allow}, {`[` + cardtest.Number()[:8] + `,` + cardtest.Number()[8:] + `]`, Allow},
		} {
			for _, action := range []Action{
				{Kind: EventMCPExecution, MCP: &MCPPayload{Server: "vendor", ToolName: "report", ToolInput: tt.body}},
				{Kind: EventToolUse, ToolUse: &ToolUsePayload{ToolName: "report", ToolInput: tt.body}},
			} {
				d := Decide(t.Context(), cfg, sc, pc, action)
				if d.Outcome != tt.want {
					t.Fatalf("enforce=%v kind=%s outcome=%s want=%s", enforce, action.Kind, d.Outcome, tt.want)
				}
			}
		}
	}
}
