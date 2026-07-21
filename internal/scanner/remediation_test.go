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
			t.Fatalf("query-entropy knob = %q, want query_entropy_exclusions fallback", g.OperatorKnob)
		}
		if !strings.Contains(g.OperatorKnob, "query_entropy_param_exclusions") {
			t.Fatalf("query-entropy knob = %q, want query_entropy_param_exclusions first", g.OperatorKnob)
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

func TestOperatorHintForResultResolvesDialTimeSSRFReasons(t *testing.T) {
	tests := []struct {
		name   string
		label  string
		reason string
	}{
		{
			name:   "dial private ip",
			label:  ScannerSSRF,
			reason: "ssrf_private_ip: SSRF blocked: api.vendor.example resolves to internal IP 10.0.0.42",
		},
		{
			name:   "dial dns rebind",
			label:  ScannerSSRF,
			reason: "ssrf_dns_rebind: SSRF blocked: api.vendor.example resolves to internal IP 10.0.0.43",
		},
		{
			name:   "url scan audit mode",
			label:  ScannerSSRF,
			reason: "destination resolves to a private IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := OperatorHintForResult(tt.label, tt.reason)
			if !strings.Contains(hint, "trusted_domains") {
				t.Fatalf("hint = %q, want trusted_domains", hint)
			}
			if !strings.Contains(hint, "ssrf.ip_allowlist") {
				t.Fatalf("hint = %q, want ssrf.ip_allowlist", hint)
			}
		})
	}
}

// A non-overridable SSRF block must NEVER hand back ssrf.ip_allowlist as the
// remediation, regardless of which SSRF label carried it. The dial-time guard
// can use the generic ScannerSSRF label with the non-overridable classification
// only in the reason string, so reason-based routing must still hold.
func TestOperatorHintForNonOverridableSSRFReasonNeverSuggestsAllowlist(t *testing.T) {
	reasons := []struct {
		name       string
		label      string
		reason     string
		isMetadata bool // want metadata-specific wording vs generic non-overridable
	}{
		{"dial generic label", ScannerSSRF, "ssrf_metadata: SSRF blocked: api.vendor.example resolves to cloud metadata endpoint 169.254.169.254", true},
		{"metadata label", ScannerSSRFMetadata, "SSRF blocked: api.vendor.example resolves to cloud metadata endpoint 169.254.169.254", true},
		{"core ssrf metadata", ScannerCoreSSRF, "core SSRF: 169.254.169.254 resolves to cloud metadata endpoint", true},
		{"non metadata non-overridable", ScannerSSRF, "SSRF blocked: api.vendor.example resolves to non-overridable internal IP 224.0.0.1", false},
	}
	for _, tt := range reasons {
		t.Run(tt.name, func(t *testing.T) {
			hint := OperatorHintForResult(tt.label, tt.reason)
			// The hint may NAME ssrf.ip_allowlist/trusted_domains to say they do
			// NOT work, but must never present either as the fix, and must state
			// the deny is non-overridable with no allow knob.
			if !strings.Contains(hint, "non-overridable") {
				t.Fatalf("hint should state it is non-overridable, got %q", hint)
			}
			if !strings.Contains(hint, "cannot exempt") {
				t.Fatalf("hint should state the knobs cannot exempt the target, got %q", hint)
			}
			if !strings.Contains(hint, "no allow knob") {
				t.Fatalf("hint should state there is no allow knob, got %q", hint)
			}
			// A non-metadata non-overridable target must not be described as an
			// instance-metadata endpoint (distinct guidance per target class).
			mentionsMetadata := strings.Contains(hint, "instance-metadata")
			if tt.isMetadata && !mentionsMetadata {
				t.Fatalf("metadata block should use metadata-specific wording, got %q", hint)
			}
			if !tt.isMetadata && mentionsMetadata {
				t.Fatalf("non-metadata non-overridable block must not claim it is an instance-metadata endpoint, got %q", hint)
			}
		})
	}
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
