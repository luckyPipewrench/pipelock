// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// UpgradeAction applies escalation-aware enforcement to a base action.
// Higher escalation NEVER reduces enforcement (monotonic guarantee).
//
// level is the session's current escalation level:
//
//	0 = normal  (no upgrade)
//	1 = elevated
//	2 = high
//	3+ = critical
//
// Returns baseAction unchanged if cfg is nil, not enabled, or level is <= 0.
func UpgradeAction(baseAction string, level int, cfg *config.AdaptiveEnforcement) string {
	if cfg == nil || !cfg.Enabled || level <= 0 {
		return baseAction
	}

	// Map level to the corresponding EscalationActions config.
	var acts *config.EscalationActions
	switch level {
	case 1:
		acts = &cfg.Levels.Elevated
	case 2:
		acts = &cfg.Levels.High
	default: // 3+
		acts = &cfg.Levels.Critical
	}

	// block_all overrides everything, including clean and strip.
	if acts.BlockAll != nil && *acts.BlockAll {
		return config.ActionBlock
	}

	// Per-action upgrades. Nil pointer = no upgrade (defensive: treat as "").
	switch baseAction {
	case config.ActionWarn:
		if acts.UpgradeWarn != nil && *acts.UpgradeWarn == config.ActionBlock {
			return config.ActionBlock
		}
	case config.ActionAsk:
		if acts.UpgradeAsk != nil && *acts.UpgradeAsk == config.ActionBlock {
			return config.ActionBlock
		}
	}

	return baseAction
}

// EscalationParams holds the observability context needed to record an
// adaptive escalation transition. Construct once per request and reuse
// across multiple RecordEscalation calls with different signal types.
type EscalationParams struct {
	Threshold     float64
	Logger        *audit.Logger    // nil-safe: omit for transports without audit logging
	Metrics       *metrics.Metrics // nil-safe: omit when metrics are unavailable
	ConsoleWriter io.Writer        // nil-safe: when set, writes escalation status to MCP stderr
	Session       string           // session identifier for audit logs (e.g. "agent|clientIP")
	ClientIP      string
	RequestID     string
}

// RecordEscalation records an adaptive signal and handles the escalation
// side-effects: audit logging and metrics gauge updates. Returns true if
// an escalation transition occurred.
func RecordEscalation(rec session.Recorder, sig session.SignalType, p EscalationParams) bool {
	escalated, from, to := rec.RecordSignal(sig, p.Threshold)
	if !escalated {
		return false
	}
	if p.ConsoleWriter != nil {
		_, _ = fmt.Fprintf(p.ConsoleWriter, "pipelock: session escalated %s -> %s (score=%.1f)\n", from, to, rec.ThreatScore())
	}
	if p.Logger != nil {
		p.Logger.LogAdaptiveEscalation(p.Session, from, to, p.ClientIP, p.RequestID, rec.ThreatScore())
	}
	if p.Metrics != nil {
		p.Metrics.RecordSessionEscalation(from, to)
		if from != session.EscalationLabel(0) {
			p.Metrics.SetAdaptiveSessionLevel(from, -1)
		}
		p.Metrics.SetAdaptiveSessionLevel(to, 1)
	}
	return true
}
