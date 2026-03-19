// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import "github.com/luckyPipewrench/pipelock/internal/config"

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
