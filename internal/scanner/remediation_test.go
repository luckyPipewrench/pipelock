// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

func TestRemediationGuidanceCoversScannerHints(t *testing.T) {
	labels := []string{
		ScannerBlocklist,
		ScannerDLP,
		ScannerEntropy,
		ScannerSubdomainEntropy,
		ScannerSSRF,
		ScannerSSRFMetadata,
		ScannerRateLimit,
		ScannerLength,
		ScannerDataBudget,
		ScannerScheme,
		ScannerAllowlist,
		ScannerParser,
		ScannerContext,
		ScannerCRLF,
		ScannerPathTraversal,
		ScannerCoreDLP,
		ScannerCoreSSRF,
		ScannerCoreResponse,
		ScannerBodyDLP,
	}

	labelSet := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		labelSet[label] = struct{}{}
		t.Run(label, func(t *testing.T) {
			if _, ok := scannerHints[label]; !ok {
				t.Fatalf("test fixture label %q is not in scannerHints", label)
			}
			if _, ok := remediationGuidance[label]; !ok {
				t.Fatalf("remediationGuidance missing scannerHints label %q", label)
			}
		})
	}

	for label := range scannerHints {
		t.Run("scannerHints/"+label, func(t *testing.T) {
			if _, ok := labelSet[label]; !ok {
				t.Fatalf("scannerHints label %q is not enumerated in remediation guidance parity test", label)
			}
		})
	}
}

func TestRemediationGuidanceAgentReasonsAreNonProcedural(t *testing.T) {
	forbidden := []string{
		// Procedural verbs — an AgentReason must state WHY, never HOW to change
		// policy (that is the operator's job and teaches self-unblock).
		"add",
		"set",
		"disable",
		"exempt",
		"suppress",
		"remove",
		"raise",
		"lower",
		"edit",
		"change",
		"modify",
		"tune",
		"adjust",
		"enable",
		"threshold",
		// Config knobs / paths — naming any of these hands the agent a self-unblock lever.
		"allowlist",
		"exempt_domains",
		"passthrough",
		".yaml",
		"dlp.patterns",
		"api_allowlist",
		"config",
		"trusted_domains",
		"ip_allowlist",
		"fetch_proxy",
		"monitoring.",
		"suppress:",
		// Containment-posture mechanism names — telling a blocked agent whether it
		// is in blocklist mode or strict-allowlist mode is recon about how boxed-in
		// it is. The operator learns the mechanism via OperatorKnob, not the agent.
		"blocklist",
		"strict",
		" mode",
	}

	for label, guidance := range remediationGuidance {
		t.Run(label, func(t *testing.T) {
			if guidance.AgentReason == "" {
				t.Fatal("AgentReason is empty")
			}
			if len(guidance.AgentReason) > 140 {
				t.Fatalf("AgentReason length = %d, want <= 140: %q", len(guidance.AgentReason), guidance.AgentReason)
			}

			lowerReason := strings.ToLower(guidance.AgentReason)
			for _, bad := range forbidden {
				if strings.Contains(lowerReason, bad) {
					t.Fatalf("AgentReason %q contains forbidden substring %q", guidance.AgentReason, bad)
				}
			}
		})
	}
}

func TestRemediationGuidanceOperatorFieldsPresent(t *testing.T) {
	for label, guidance := range remediationGuidance {
		t.Run(label, func(t *testing.T) {
			if guidance.OperatorKnob == "" {
				t.Fatal("OperatorKnob is empty")
			}
			if guidance.Immutable && guidance.OperatorBroader != "" {
				t.Fatalf("immutable guidance has OperatorBroader = %q, want empty", guidance.OperatorBroader)
			}
		})
	}
}

func TestGuidanceFor(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  RemediationGuidance
		ok    bool
	}{
		{
			name:  "known",
			label: ScannerDLP,
			want:  remediationGuidance[ScannerDLP],
			ok:    true,
		},
		{
			name:  "unknown",
			label: "nonexistent",
			want:  RemediationGuidance{},
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := GuidanceFor(tt.label)
			if ok != tt.ok {
				t.Fatalf("GuidanceFor(%q) ok = %v, want %v", tt.label, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("GuidanceFor(%q) = %#v, want %#v", tt.label, got, tt.want)
			}
		})
	}
}
