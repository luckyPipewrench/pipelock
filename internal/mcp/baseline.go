// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

type toolCallRecorder interface {
	RecordToolCall(toolName string)
}

func recordMCPToolCallAndCheckBaseline(opts MCPProxyOpts, rec session.Recorder, toolName string) session.BaselineDecision {
	if rec == nil || strings.TrimSpace(toolName) == "" {
		return session.BaselineDecision{}
	}
	if recorder, ok := rec.(toolCallRecorder); ok {
		recorder.RecordToolCall(toolName)
	}
	checker := opts.baselineChecker()
	if checker == nil {
		return session.BaselineDecision{}
	}
	agentKey := mcpBaselineAgentKey(opts)
	if agentKey == "" {
		return session.BaselineDecision{}
	}
	decision := checker.CheckBaselineForRecorder(agentKey, rec)
	if decision.Action == "" {
		if decision.Blocked {
			decision.Action = config.ActionBlock
		} else {
			return session.BaselineDecision{}
		}
	}
	if decision.Detail == "" {
		decision.Detail = "baseline deviation"
	}
	if decision.Action == config.ActionAsk {
		decision.Blocked = true
	}
	return decision
}

func recordMCPBaselineSample(opts MCPProxyOpts, rec session.Recorder) {
	if rec == nil {
		return
	}
	checker := opts.baselineChecker()
	if checker == nil {
		return
	}
	agentKey := mcpBaselineAgentKey(opts)
	if agentKey == "" {
		return
	}
	checker.RecordBaselineForRecorder(agentKey, rec)
}

func mcpBaselineAgentKey(opts MCPProxyOpts) string {
	if agent := strings.TrimSpace(opts.addressProtectionAgent()); agent != "" {
		return agent
	}
	return strings.TrimSpace(opts.captureProfile())
}
