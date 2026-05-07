// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import "github.com/luckyPipewrench/pipelock/internal/blockreason"

// Decision.Reason values produced by EvaluateHTTP / evaluateContractLive /
// applyModeGate. Kept private to the runtime package because the canonical
// vocabulary on the wire is blockreason.Reason; these strings are the
// untyped intermediate the evaluator uses when assembling a Decision.
const (
	decisionReasonKillSwitchActive       = "kill_switch_active"
	decisionReasonScannerDecisionMissing = "scanner_decision_missing"
	decisionReasonContractDefaultDeny    = "contract_default_deny"
	decisionReasonContractEnforceDefault = "contract_enforce_default"
	decisionReasonContractNonDefaultPort = "contract_non_default_port"
	decisionReasonContractInvalidPath    = "contract_invalid_path"
	decisionReasonContractObservedOnly   = "contract_observed_only"
)

// BlockReasonForDecision maps a Decision.Reason string to its canonical
// blockreason.Reason on the wire, returning ok=false when the input has no
// canonical typed value. Transport call sites use this helper to emit
// X-Pipelock-Block-Reason headers and to populate receipt metadata without
// each transport hard-coding the string-to-reason table.
//
// The helper is declarative: it does not consult any runtime state. Empty
// input returns ok=false rather than a zero blockreason.Reason so callers
// can distinguish "no contract reason set" from a real but unknown reason
// and pick a sensible fallback (typically blockreason.ParseError or
// blockreason.NotEnabled depending on the call site).
//
// The block-reason vocabulary is locked at v1; new typed reasons require
// updates in three places — internal/blockreason/blockreason.go (the
// vocabulary itself), this mapping, and the production-path matrix gate.
func BlockReasonForDecision(decisionReason string) (blockreason.Reason, bool) {
	switch decisionReason {
	case decisionReasonContractDefaultDeny:
		return blockreason.ContractDefaultDeny, true
	case decisionReasonContractEnforceDefault:
		return blockreason.ContractEnforceDefault, true
	case decisionReasonContractNonDefaultPort:
		return blockreason.ContractNonDefaultPort, true
	case decisionReasonContractInvalidPath:
		return blockreason.ContractInvalidPath, true
	case decisionReasonContractObservedOnly:
		return blockreason.ContractObservedOnly, true
	case decisionReasonKillSwitchActive:
		return blockreason.KillSwitchActive, true
	case decisionReasonScannerDecisionMissing:
		// Scanner is missing a verdict — fail-closed input, surface as
		// parse_error so the agent reads "your input could not be
		// classified" rather than the more specific kill-switch or
		// contract codes that imply jurisdictional enforcement.
		return blockreason.ParseError, true
	default:
		return "", false
	}
}
