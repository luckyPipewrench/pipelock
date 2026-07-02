// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

func TestRemediationGuidanceCoversAllLabels(t *testing.T) {
	// The canonical set of block labels a scanner emits. Every one must have
	// guidance, and the guidance table must not carry a label outside this set,
	// so a new scanner label without guidance (or a stray table entry) fails CI.
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
		DecideInjectionLabel,
		DecidePolicyLabel,
		DecideStructuralLabel,
	}

	labelSet := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		labelSet[label] = struct{}{}
		t.Run(label, func(t *testing.T) {
			if _, ok := remediationGuidance[label]; !ok {
				t.Fatalf("remediationGuidance missing label %q", label)
			}
		})
	}

	for label := range remediationGuidance {
		if _, ok := labelSet[label]; !ok {
			t.Errorf("remediationGuidance has label %q not enumerated in the canonical block-label set", label)
		}
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

func TestGuidanceForResultDisambiguatesEntropy(t *testing.T) {
	t.Run("query entropy uses the query knob", func(t *testing.T) {
		g, ok := GuidanceForResult(ScannerEntropy, `high entropy query param "sig"`)
		if !ok {
			t.Fatal("GuidanceForResult(entropy, query reason) not ok")
		}
		if !strings.Contains(g.OperatorKnob, "query_entropy_exclusions") {
			t.Fatalf("query-entropy knob = %q, want query_entropy_exclusions", g.OperatorKnob)
		}
		if OperatorHintForResult(ScannerEntropy, "query x") != queryEntropyOperatorKnob {
			t.Fatal("OperatorHintForResult should return the query knob for a query reason")
		}
	})

	t.Run("path entropy falls through to the table entry", func(t *testing.T) {
		g, _ := GuidanceForResult(ScannerEntropy, "high entropy path segment")
		if g != remediationGuidance[ScannerEntropy] {
			t.Fatalf("path-entropy guidance = %#v, want the table entry", g)
		}
	})

	t.Run("non-entropy label ignores the reason", func(t *testing.T) {
		g, _ := GuidanceForResult(ScannerDLP, "high entropy query param")
		if g != remediationGuidance[ScannerDLP] {
			t.Fatal("a non-entropy label must be reason-independent")
		}
	})

	t.Run("unknown label is fail-safe", func(t *testing.T) {
		if _, ok := GuidanceForResult("nonexistent", "query"); ok {
			t.Fatal("unknown label must return ok=false")
		}
	})
}

func TestDecideLabelGuidanceNamesOperatorKnobsOnlyToOperator(t *testing.T) {
	tests := []struct {
		label       string
		wantKnob    string
		forbidAgent string
	}{
		{DecideInjectionLabel, "response_scanning", "response_scanning"},
		{DecidePolicyLabel, "mcp_tool_policy", "mcp_tool_policy"},
		{DecideStructuralLabel, "could not be evaluated safely", "correct the action shape"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			g, ok := GuidanceFor(tt.label)
			if !ok {
				t.Fatalf("GuidanceFor(%q) not ok", tt.label)
			}
			if !strings.Contains(g.OperatorKnob, tt.wantKnob) {
				t.Fatalf("OperatorKnob = %q, want substring %q", g.OperatorKnob, tt.wantKnob)
			}
			if strings.Contains(g.AgentReason, tt.forbidAgent) {
				t.Fatalf("AgentReason %q contains operator knob substring %q", g.AgentReason, tt.forbidAgent)
			}
		})
	}
}
