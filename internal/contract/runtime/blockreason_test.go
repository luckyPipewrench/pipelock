// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// TestBlockReasonForDecision_AllSupportedStrings asserts that every Decision
// reason string the runtime emits has a typed blockreason.Reason mapping.
// New decision reason strings added to the evaluator MUST land here in the
// same change so transport call sites can look up the wire-canonical reason
// without inventing a string-to-reason table per transport.
func TestBlockReasonForDecision_AllSupportedStrings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		decisionReason string
		want           blockreason.Reason
	}{
		{"contract default deny", decisionReasonContractDefaultDeny, blockreason.ContractDefaultDeny},
		{"contract enforce default", decisionReasonContractEnforceDefault, blockreason.ContractEnforceDefault},
		{"contract non default port", decisionReasonContractNonDefaultPort, blockreason.ContractNonDefaultPort},
		{"contract invalid path", decisionReasonContractInvalidPath, blockreason.ContractInvalidPath},
		{"contract observed only", decisionReasonContractObservedOnly, blockreason.ContractObservedOnly},
		{"kill switch active", decisionReasonKillSwitchActive, blockreason.KillSwitchActive},
		{"scanner decision missing", decisionReasonScannerDecisionMissing, blockreason.ParseError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := BlockReasonForDecision(tc.decisionReason)
			if !ok {
				t.Fatalf("BlockReasonForDecision(%q): ok=false, want true", tc.decisionReason)
			}
			if got != tc.want {
				t.Fatalf("BlockReasonForDecision(%q) = %q, want %q", tc.decisionReason, got, tc.want)
			}
		})
	}
}

// TestBlockReasonForDecision_EmptyAndUnknownReturnFalse confirms the helper
// does not surface a false positive for empty input (the common case when a
// Decision carries no Reason annotation) or for an unknown string (which
// could be an evaluator string the helper has not been updated for; the
// caller must select a fallback reason explicitly).
func TestBlockReasonForDecision_EmptyAndUnknownReturnFalse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"unknown decision string", "made_up_reason"},
		{"close-but-not-equal", "contract_default"},
		{"trailing whitespace", "contract_default_deny "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := BlockReasonForDecision(tc.in)
			if ok {
				t.Fatalf("BlockReasonForDecision(%q): ok=true, want false (got %q)", tc.in, got)
			}
			if got != "" {
				t.Fatalf("BlockReasonForDecision(%q): got %q, want empty", tc.in, got)
			}
		})
	}
}

// TestBlockReasonForDecision_RuntimeStringsMatchPrivateConstants is the
// regression gate against a runtime evaluator change that updates an emitted
// Decision.Reason string but forgets the matching update in
// blockreason.go's mapping. It pins the exact wire strings the evaluator
// uses today so a drift between runtime.go and blockreason.go fails fast
// here instead of silently producing receipts with a missing Reason.
func TestBlockReasonForDecision_RuntimeStringsMatchPrivateConstants(t *testing.T) {
	t.Parallel()
	pairs := map[string]string{
		"kill_switch_active":        decisionReasonKillSwitchActive,
		"scanner_decision_missing":  decisionReasonScannerDecisionMissing,
		"contract_default_deny":     decisionReasonContractDefaultDeny,
		"contract_enforce_default":  decisionReasonContractEnforceDefault,
		"contract_non_default_port": decisionReasonContractNonDefaultPort,
		"contract_invalid_path":     decisionReasonContractInvalidPath,
		"contract_observed_only":    decisionReasonContractObservedOnly,
	}
	for wire, constant := range pairs {
		if wire != constant {
			t.Fatalf("private constant for %q drifted to %q (update runtime.go and blockreason.go together)", wire, constant)
		}
	}
}
