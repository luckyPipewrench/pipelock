// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// nonMetricsBaselineChecker implements session.BaselineChecker but NOT
// session.BaselineMetricsChecker, to exercise the fail-closed path when the
// configured checker cannot answer the provisional metrics query.
type nonMetricsBaselineChecker struct{}

func (nonMetricsBaselineChecker) CheckBaselineForRecorder(string, session.Recorder) session.BaselineDecision {
	return session.BaselineDecision{}
}
func (nonMetricsBaselineChecker) RecordBaselineForRecorder(string, session.Recorder) {}

// TestCheckMCPToolCallBaselineAttempt_FailsClosedWithoutMetricsChecker proves the
// MCP baseline attempt blocks when the configured checker does not support the
// metrics interface (a misconfigured/unavailable provider must not fail open).
func TestCheckMCPToolCallBaselineAttempt_FailsClosedWithoutMetricsChecker(t *testing.T) {
	opts := MCPProxyOpts{Baseline: nonMetricsBaselineChecker{}, AddressProtectionAgent: "id-k"}
	d := checkMCPToolCallBaselineAttempt(opts, &baselineTestRecorder{}, "some_tool")
	if !d.Blocked || d.Action != config.ActionBlock {
		t.Fatalf("expected fail-closed block without a metrics checker, got %+v", d)
	}

	// No checker configured at all is a no-op (feature off), not a block.
	if d := checkMCPToolCallBaselineAttempt(MCPProxyOpts{}, &baselineTestRecorder{}, "some_tool"); d.Action != "" || d.Blocked {
		t.Fatalf("expected empty decision with no checker, got %+v", d)
	}
	// Empty tool name is a no-op.
	if d := checkMCPToolCallBaselineAttempt(opts, &baselineTestRecorder{}, "  "); d.Action != "" || d.Blocked {
		t.Fatalf("expected empty decision for blank tool name, got %+v", d)
	}
}

// TestNormalizeBaselineDecision covers the decision-normalization branches.
func TestNormalizeBaselineDecision(t *testing.T) {
	if d := normalizeBaselineDecision(session.BaselineDecision{Blocked: true}); d.Action != config.ActionBlock {
		t.Fatalf("blocked with no action should default to block, got %q", d.Action)
	}
	if d := normalizeBaselineDecision(session.BaselineDecision{}); d.Action != "" || d.Blocked {
		t.Fatalf("empty decision should stay empty, got %+v", d)
	}
	if d := normalizeBaselineDecision(session.BaselineDecision{Action: config.ActionAsk}); !d.Blocked {
		t.Fatalf("ask should be treated as blocked, got %+v", d)
	}
	if d := normalizeBaselineDecision(session.BaselineDecision{Action: config.ActionBlock}); d.Detail == "" {
		t.Fatal("a blocking decision should carry a default detail")
	}
}
