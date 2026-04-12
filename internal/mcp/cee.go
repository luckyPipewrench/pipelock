// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// CEEDeps holds optional cross-request exfiltration detection dependencies.
// All fields are nil-safe: nil disables the feature. Passed to MCP proxy
// functions so they can record outbound payloads for entropy and fragment
// analysis without adding individual parameters to already-complex signatures.
type CEEDeps struct {
	Tracker *scanner.EntropyTracker
	Buffer  *scanner.FragmentBuffer
	Metrics *metrics.Metrics
	Config  *config.CrossRequestDetection
}

// ceeSessionKeyMCP builds a CEE session key for MCP traffic. The agent
// identifier distinguishes traffic when multiple agents share a proxy.
func ceeSessionKeyMCP(agent, sessionOrIP string) string {
	if agent != "" {
		return agent + "|" + sessionOrIP
	}
	return sessionOrIP
}

// ceeRecordMCP runs cross-request exfiltration checks on outbound MCP payload.
// Returns a non-empty reason string if the request should be blocked.
// Returns "" if clean or CEE is disabled.
func ceeRecordMCP(
	sessionKey string,
	payload []byte,
	cee *CEEDeps,
	sc *scanner.Scanner,
	logW io.Writer,
	logger *audit.Logger,
) string {
	if cee == nil || len(payload) == 0 {
		return ""
	}

	// Entropy budget check.
	if cee.Tracker != nil && cee.Config != nil && cee.Config.EntropyBudget.Enabled {
		cee.Tracker.Record(sessionKey, payload)
		if cee.Tracker.BudgetExceeded(sessionKey) {
			if cee.Metrics != nil {
				cee.Metrics.RecordCrossRequestEntropyExceeded()
			}
			reason := fmt.Sprintf("cross-request entropy budget exceeded: %.0f/%.0f bits",
				cee.Tracker.CurrentUsage(sessionKey), cee.Tracker.Budget())
			_, _ = fmt.Fprintf(logW, "pipelock: CEE: %s (session=%s)\n", reason, sessionKey)
			if cee.Config.EntropyBudget.Action == config.ActionBlock {
				if logger != nil {
					logger.LogBlocked(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_entropy", reason)
				}
				return reason
			}
			// Warn mode: emit structured anomaly event for audit trail.
			if logger != nil {
				logger.LogAnomaly(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_entropy", reason, 0)
			}
		}
	}

	// Fragment reassembly DLP check.
	if cee.Buffer != nil && cee.Config != nil && cee.Config.FragmentReassembly.Enabled {
		cee.Buffer.Append(sessionKey, payload)
		if matches := cee.Buffer.ScanForSecrets(context.Background(), sessionKey, sc); len(matches) > 0 {
			if cee.Metrics != nil {
				cee.Metrics.RecordCrossRequestDLPMatch()
			}
			reason := fmt.Sprintf("cross-request fragment DLP match: %s", matches[0].PatternName)
			_, _ = fmt.Fprintf(logW, "pipelock: CEE: %s (session=%s)\n", reason, sessionKey)
			if cee.Config.Action == config.ActionBlock {
				if logger != nil {
					logger.LogBlocked(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_fragment", reason)
				}
				return reason
			}
			// Warn mode: emit structured anomaly event for audit trail.
			if logger != nil {
				logger.LogAnomaly(mustMCPAuditContext(logger, "CEE", "mcp-input"), "cross_request_fragment", reason, 0)
			}
		}
	}

	return ""
}
