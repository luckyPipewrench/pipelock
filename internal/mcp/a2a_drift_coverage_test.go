// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/emit"
)

// TestLessA2ASkill_TotalOrderIgnoresSourceOrder proves the skill ordering is
// total on every non-descriptive field, so a card with duplicate or empty IDs
// hashes the same regardless of the order its skills arrived in.
func TestLessA2ASkill_TotalOrderIgnoresSourceOrder(t *testing.T) {
	pairs := map[string][2]A2ASkill{
		"name":          {{ID: "", Name: "a"}, {ID: "", Name: "b"}},
		"description":   {{ID: "x", Name: "n", Description: "a"}, {ID: "x", Name: "n", Description: "b"}},
		"input schema":  {{ID: "x", Name: "n", InputSchema: json.RawMessage(`{"a":1}`)}, {ID: "x", Name: "n", InputSchema: json.RawMessage(`{"b":1}`)}},
		"output schema": {{ID: "x", Name: "n", InputSchema: json.RawMessage(`{"a":1}`), OutputSchema: json.RawMessage(`{"a":1}`)}, {ID: "x", Name: "n", InputSchema: json.RawMessage(`{"a":1}`), OutputSchema: json.RawMessage(`{"b":1}`)}},
	}
	for name, pair := range pairs {
		t.Run(name, func(t *testing.T) {
			a, b := pair[0], pair[1]
			if lessA2ASkill(a, b) == lessA2ASkill(b, a) {
				t.Fatalf("ordering is not strict for %s tie-break", name)
			}
			forward := HashAgentCard(A2AAgentCard{Name: "v", Skills: []A2ASkill{a, b}})
			reverse := HashAgentCard(A2AAgentCard{Name: "v", Skills: []A2ASkill{b, a}})
			if forward != reverse {
				t.Fatalf("hash depends on source order for %s tie-break", name)
			}
			if cardStructuralDigest(A2AAgentCard{Skills: []A2ASkill{a, b}}) != cardStructuralDigest(A2AAgentCard{Skills: []A2ASkill{b, a}}) {
				t.Fatalf("structural digest depends on source order for %s tie-break", name)
			}
		})
	}
}

// TestForwardScanned_A2ACardDriftAdoptionEmitsAuditEvent proves an adopted
// descriptive change reaches the audit emitter, not only the MCP log line, so
// an automatic baseline update is visible where operators collect events.
func TestForwardScanned_A2ACardDriftAdoptionEmitsAuditEvent(t *testing.T) {
	cfg := enabledA2ACfg()
	cfg.ScanAgentCards = false
	cfg.DetectCardDrift = true
	sink := &recordingEmitSinkHTTP{}
	logger := audit.NewNop()
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })
	opts := MCPProxyOpts{A2ACfg: cfg, CardBaseline: NewCardBaseline(10), A2ACardURL: testCardURL, AuditLogger: logger}

	first := unsignedAgentCardRPC()
	out, _, found := forwardA2AResponse(t, first, opts)
	assertMCPResponseAllowed(t, out, found, `"Vendor Agent"`)
	second := strings.Replace(first, `"description":"does things"`, `"description":"does useful things"`, 1)
	out, _, found = forwardA2AResponse(t, second, opts)
	assertMCPResponseAllowed(t, out, found, `"Vendor Agent"`)
	_ = emitter.Close()

	for _, ev := range sink.events {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "descriptive drift adopted") {
			return
		}
	}
	t.Fatalf("no audit event recorded the adopted drift; events=%d", len(sink.events))
}
