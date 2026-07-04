// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	a2aBaselineIdentityPrefix  = "a2a:"
	toolBaselineIdentityPrefix = "tool:"
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
		ToolCalls:      r.toolCalls,
		UniqueTools:    len(r.uniqueTools),
		ToolIdentities: sortedBaselineToolIdentities(r.uniqueTools),
		Requests:       r.requests,
		DurationSec:    r.lastActivity.Sub(r.created).Seconds(),
	}
}

func (r *mcpRequestBaselineRecorder) ProvisionalToolCallMetrics(toolName string) session.BaselineMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()
	uniqueTools := len(r.uniqueTools)
	if _, ok := r.uniqueTools[toolName]; !ok {
		uniqueTools++
	}
	toolIdentities := sortedBaselineToolIdentities(r.uniqueTools)
	if !containsBaselineToolIdentity(toolIdentities, toolName) {
		toolIdentities = append(toolIdentities, toolName)
		sort.Strings(toolIdentities)
	}
	return session.BaselineMetrics{
		ToolCalls:      r.toolCalls + 1,
		UniqueTools:    uniqueTools,
		ToolIdentities: toolIdentities,
		Requests:       r.requests,
		DurationSec:    r.lastActivity.Sub(r.created).Seconds(),
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

func mcpFrameBaselineIdentity(frame MCPFrame) string {
	if toolName := strings.TrimSpace(frame.ToolCallName); toolName != "" {
		return toolBaselineIdentity(toolName)
	}
	return a2aBaselineIdentity(frame.Method)
}

func toolBaselineIdentity(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return ""
	}
	return toolBaselineIdentityPrefix + toolName
}

func a2aBaselineIdentity(method string) string {
	method = strings.TrimSpace(method)
	if method == "" || !IsA2AMethod(method) {
		return ""
	}
	// A2A is method-based rather than params.name-based. Reusing the
	// tool-call baseline machinery with an explicit namespace keeps learning,
	// ratification, locking, and persistence on one profile while preventing
	// collisions with ordinary tools, including one literally named
	// "a2a:SendMessage".
	return a2aBaselineIdentityPrefix + method
}

func sortedBaselineToolIdentities(tools map[string]struct{}) []string {
	if len(tools) == 0 {
		return nil
	}
	identities := make([]string, 0, len(tools))
	for tool := range tools {
		identities = append(identities, tool)
	}
	sort.Strings(identities)
	return identities
}

func containsBaselineToolIdentity(identities []string, want string) bool {
	for _, identity := range identities {
		if identity == want {
			return true
		}
	}
	return false
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
