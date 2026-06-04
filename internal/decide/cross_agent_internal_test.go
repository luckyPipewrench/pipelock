// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestCrossAgentSourceIsDuplicate exercises the dedup predicate directly,
// including the defensive empty-slice guard that ObserveCrossAgentContamination
// never reaches in production (a contaminated session always has >=1 source).
func TestCrossAgentSourceIsDuplicate(t *testing.T) {
	cross := session.TaintSourceRef{Kind: session.TaintSourceKindCrossAgent, MatchReason: "cross_agent_mcp_tool_call"}

	tests := []struct {
		name    string
		sources []session.TaintSourceRef
		want    bool
	}{
		{"empty slice", nil, false},
		{
			"last is different kind",
			[]session.TaintSourceRef{{Kind: "http_response"}},
			false,
		},
		{
			"last is cross_agent different boundary",
			[]session.TaintSourceRef{{Kind: session.TaintSourceKindCrossAgent, MatchReason: "cross_agent_a2a_request"}},
			false,
		},
		{
			"last is cross_agent same boundary",
			[]session.TaintSourceRef{{Kind: session.TaintSourceKindCrossAgent, MatchReason: "cross_agent_mcp_tool_call"}},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := crossAgentSourceIsDuplicate(tc.sources, cross); got != tc.want {
				t.Fatalf("crossAgentSourceIsDuplicate = %v, want %v", got, tc.want)
			}
		})
	}
}
