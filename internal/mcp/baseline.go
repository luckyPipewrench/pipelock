// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

type mcpRequestBaselineRecorder struct {
	mu           sync.Mutex
	created      time.Time
	lastActivity time.Time
	toolCalls    int
	uniqueTools  map[string]struct{}
	requests     int
}

func newMCPRequestBaselineRecorder() *mcpRequestBaselineRecorder {
	now := time.Now()
	return &mcpRequestBaselineRecorder{
		created:      now,
		lastActivity: now,
		uniqueTools:  make(map[string]struct{}),
		requests:     1,
	}
}

func (r *mcpRequestBaselineRecorder) BaselineMetrics() session.BaselineMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()
	return session.BaselineMetrics{
		ToolCalls:   r.toolCalls,
		UniqueTools: len(r.uniqueTools),
		Requests:    r.requests,
		DurationSec: r.lastActivity.Sub(r.created).Seconds(),
	}
}

func (r *mcpRequestBaselineRecorder) ProvisionalToolCallMetrics(toolName string) session.BaselineMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()
	uniqueTools := len(r.uniqueTools)
	if _, ok := r.uniqueTools[toolName]; !ok {
		uniqueTools++
	}
	return session.BaselineMetrics{
		ToolCalls:   r.toolCalls + 1,
		UniqueTools: uniqueTools,
		Requests:    r.requests,
		DurationSec: r.lastActivity.Sub(r.created).Seconds(),
	}
}

func (r *mcpRequestBaselineRecorder) RecordToolCall(toolName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.toolCalls++
	r.uniqueTools[toolName] = struct{}{}
	r.lastActivity = time.Now()
}

func baselineMetricsRecorder(opts MCPProxyOpts, rec session.Recorder) session.ToolCallBaselineRecorder {
	if opts.BaselineRec != nil {
		return opts.BaselineRec
	}
	provider, _ := rec.(session.ToolCallBaselineRecorder)
	return provider
}

func checkMCPToolCallBaselineAttempt(opts MCPProxyOpts, metricsProvider session.ToolCallBaselineRecorder, toolName string) session.BaselineDecision {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return session.BaselineDecision{}
	}
	checker := opts.baselineChecker()
	if checker == nil {
		return session.BaselineDecision{}
	}
	metricsChecker, ok := checker.(session.BaselineMetricsChecker)
	if !ok {
		return baselineFailClosedDecision("baseline metrics provider unavailable")
	}
	agentKey := mcpBaselineAgentKey(opts)
	if agentKey == "" {
		return session.BaselineDecision{}
	}
	if metricsProvider == nil {
		return baselineFailClosedDecision("baseline metrics provider unavailable")
	}
	decision := metricsChecker.CheckBaselineForMetrics(agentKey, metricsProvider.ProvisionalToolCallMetrics(toolName))
	return normalizeBaselineDecision(decision)
}

func commitMCPToolCall(metricsProvider session.ToolCallBaselineRecorder, toolName string) {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return
	}
	if metricsProvider == nil {
		return
	}
	metricsProvider.RecordToolCall(toolName)
}

func baselineFailClosedDecision(detail string) session.BaselineDecision {
	return session.BaselineDecision{
		Blocked: true,
		Action:  config.ActionBlock,
		Detail:  detail,
	}
}

func normalizeBaselineDecision(decision session.BaselineDecision) session.BaselineDecision {
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
	checker := opts.baselineChecker()
	if checker == nil {
		return
	}
	metricsChecker, ok := checker.(session.BaselineMetricsChecker)
	if !ok {
		return
	}
	agentKey := mcpBaselineAgentKey(opts)
	if agentKey == "" {
		return
	}
	metricsProvider := baselineMetricsRecorder(opts, rec)
	if metricsProvider == nil {
		return
	}
	metricsChecker.RecordBaselineMetrics(agentKey, metricsProvider.BaselineMetrics())
}

func mcpBaselineAgentKey(opts MCPProxyOpts) string {
	if agent := strings.TrimSpace(opts.addressProtectionAgent()); agent != "" {
		return agent
	}
	return strings.TrimSpace(opts.captureProfile())
}
