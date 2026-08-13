// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

// StrongestAction returns the strongest enforcement action among those given.
// Unknown and empty actions have default rank and are never selected over a
// recognized one.
func StrongestAction(actions ...string) string {
	strongest := ""
	strongestRank := 0
	for _, action := range actions {
		rank := actionRank(action)
		if rank > strongestRank {
			strongest = action
			strongestRank = rank
		}
	}
	return strongest
}

// actionRank ranks an action by ENFORCEMENT strength.
//
// It previously ranked only block and warn, leaving strip, redirect, ask and
// defer at default rank alongside genuinely unknown values. Every current
// caller is fed from a field that validation constrains to warn or block, so
// that was correct in practice, and extending the ranking is behavior-
// preserving for every reachable input today.
//
// It was a trap for the next caller. Several config fields do accept strip and
// ask, and routing one of those through StrongestAction would have discarded
// it in favor of a weaker action, which on this codebase means enforcing less
// than the operator configured. Ranking them closes that class instead of
// waiting for the instance.
//
// This deliberately does NOT delegate to reloadActionStrength, and the
// difference is not an oversight. That ordering ranks allow and forward above
// nothing, because it detects downgrades across a reload and block -> allow is
// the downgrade it exists to catch. Here, allow and forward mean NO
// enforcement: they must never be selected over a real action, and
// StrongestAction("allow") must stay empty rather than reporting that allow
// was chosen. Same words, two correct orderings, because the two callers are
// asking different questions.
func actionRank(action string) int {
	switch action {
	case ActionBlock:
		return 6
	case ActionDefer:
		return 5
	case ActionAsk:
		return 4
	case ActionRedirect:
		return 3
	case ActionStrip:
		return 2
	case ActionWarn:
		return 1
	default:
		// Includes allow, forward, empty and anything unrecognized: no
		// enforcement to contribute.
		return 0
	}
}
