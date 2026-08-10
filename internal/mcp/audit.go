// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

const (
	dowSubjectKeyDefault   = "_default"
	dowSubjectTrustDefault = "default"
	dowAuditFallbackTarget = "invalid-mcp-resource"
)

func mustMCPAuditContext(logger *audit.Logger, method, resource string) audit.LogContext {
	ctx, err := audit.NewMCPLogContext(method, resource, "")
	if err != nil {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext(method), err)
		}
		return audit.NewMethodLogContext(method)
	}
	return ctx
}

func resolvedDoWAttribution(opts MCPProxyOpts) (string, DoWAttribution) {
	agent := identitykey.CEESafeAgent(opts.DoWSubjectAgent, opts.DoWSubjectAgentAuth)
	if agent == "" {
		agent = metrics.DoWAgentDefault
	}
	attribution := opts.DoWAttribution
	if attribution.SubjectKey == "" {
		attribution.SubjectKey = dowSubjectKeyDefault
	}
	attribution.Trust = resolvedDoWTrust(attribution.Trust)
	return agent, attribution
}

func resolvedDoWTrust(trust string) string {
	switch trust {
	case config.DoWTrustNetwork.String(), config.DoWTrustAgent.String(), config.DoWTrustPrincipal.String():
		return trust
	default:
		return dowSubjectTrustDefault
	}
}

func mustMCPDoWAuditContext(logger *audit.Logger, resource string, opts MCPProxyOpts) audit.LogContext {
	return mcpDoWAuditContext(logger, resource, opts, audit.NewMCPLogContext)
}

func mcpDoWAuditContext(
	logger *audit.Logger,
	resource string,
	opts MCPProxyOpts,
	newContext func(method, resource, agent string) (audit.LogContext, error),
) audit.LogContext {
	agent, attribution := resolvedDoWAttribution(opts)
	ctx, err := newContext("MCP", resource, agent)
	if err != nil {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext("MCP"), err)
		}
		ctx, _ = audit.NewMCPLogContext("MCP", dowAuditFallbackTarget, agent)
	}
	return ctx.WithDoWAttribution(attribution.SubjectKey, attribution.Trust)
}

func recordDoWMetric(m *metrics.Metrics, action string, opts MCPProxyOpts) {
	if m == nil {
		return
	}
	agent, attribution := resolvedDoWAttribution(opts)
	m.RecordDenialOfWalletEvent(action, agent, attribution.Trust)
}
