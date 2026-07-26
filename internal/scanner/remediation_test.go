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
		AuditBodyEntropy,
		ScannerDenialOfWallet,
		AuditResponseScan,
		AuditHeaderDLP,
		AuditBodyPromptInjection,
		AuditAddressProtection,
		AuditChainDetection,
		AuditProvenance,
		AuditMediaPolicy,
		AuditRequestPolicy,
		AuditAgentIdentity,
		AuditTaintPolicy,
		AuditSessionAnomaly,
		AuditAdaptiveEnforcement,
		AuditMCPSessionBinding,
		AuditFrozenTool,
		AuditSNIMismatch,
		AuditKillSwitch,
		AuditAirlock,
		AuditCrossRequestEntropy,
		AuditCrossRequestFragment,
		AuditGitProtection,
		AuditAgentBudget,
		AuditResponseSize,
		AuditShieldOversize,
		AuditContract,
		AuditSSEStream,
		AuditUnscannable,
		AuditA2AScan,
		AuditA2ACardSignature,
		AuditRedaction,
		AuditScannerUnavailable,
		AuditMediationEnvelope,
		AuditReceiptEmission,
		AuditReverseSubmit,
		AuditA2AHeader,
		AuditA2AResponse,
		AuditBudgetTruncated,
		AuditTLSResponseBlocked,
		AuditSessionDeny,
		AuditTLSHandshakeError,
		AuditTLSAuthorityMismatch,
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

func TestOperatorHintForResultResolvesDenialOfWalletReasons(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		wantKnob string
	}{
		{
			name:     "tool call budget",
			reason:   "tool call limit exceeded: 11/10",
			wantKnob: "max_tool_calls_per_session",
		},
		{
			name:     "wall clock budget",
			reason:   "wall clock budget exceeded: 31m0s/30m0s",
			wantKnob: "max_wall_clock_minutes",
		},
		{
			name:     "identical call loop",
			reason:   "loop detected: expensive_tool called 6 times with same args (limit 5)",
			wantKnob: "max_retries_per_tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, ok := GuidanceForResult(ScannerDenialOfWallet, tt.reason)
			if !ok {
				t.Fatal("GuidanceForResult(denial_of_wallet) not ok")
			}
			if !strings.Contains(g.OperatorKnob, "agents._default.budget."+tt.wantKnob) {
				t.Fatalf("operator knob = %q, want agents._default.budget.%s", g.OperatorKnob, tt.wantKnob)
			}
			if hint := OperatorHintForResult(ScannerDenialOfWallet, tt.reason); hint != g.OperatorKnob {
				t.Fatalf("OperatorHintForResult() = %q, want %q", hint, g.OperatorKnob)
			}
		})
	}

	for _, reason := range []string{
		"cycle detected: a -> b -> a -> b",
		"runaway expansion: 5.2x growth per turn",
	} {
		t.Run(reason, func(t *testing.T) {
			guidance, ok := GuidanceForResult(ScannerDenialOfWallet, reason)
			if !ok {
				t.Fatal("GuidanceForResult(denial_of_wallet) not ok")
			}
			if guidance != remediationGuidance[ScannerDenialOfWallet] {
				t.Fatalf("guidance = %#v, want family fallback %#v", guidance, remediationGuidance[ScannerDenialOfWallet])
			}
			hint := guidance.OperatorKnob
			if !strings.Contains(hint, "fixed detector thresholds") {
				t.Fatalf("fallback hint = %q, want fixed-threshold disclosure", hint)
			}
			if !strings.Contains(hint, "dow_action") {
				t.Fatalf("fallback hint = %q, want the verified enforcement knob", hint)
			}
			for _, inert := range []string{"max_retries_per_tool", "loop_detection_window"} {
				if strings.Contains(hint, inert) {
					t.Fatalf("fallback hint = %q, must not present %s as a detector limit", hint, inert)
				}
			}
		})
	}
}

func TestOperatorHintForResultResolvesAuditReasons(t *testing.T) {
	tests := []struct {
		name   string
		label  string
		reason string
		want   string
	}{
		{"media image size", AuditMediaPolicy, "media_policy: image size 2048 exceeds limit 1024", "media_policy.max_image_bytes"},
		{"media audio", AuditMediaPolicy, "media_policy: audio stripped", "media_policy.strip_audio"},
		{"media video", AuditMediaPolicy, "media_policy: video stripped", "media_policy.strip_video"},
		{"media images", AuditMediaPolicy, "media_policy: images stripped", "media_policy.strip_images"},
		{"media type", AuditMediaPolicy, `media_policy: image type "image/webp" not in allowed list`, "media_policy.allowed_image_types"},
		{"media parse failure", AuditMediaPolicy, "media_policy: image parse error", "no exemption knob"},
		{"response integrity", AuditResponseScan, "compressed response cannot be scanned", "scan-integrity failure"},
		{"response size", AuditResponseScan, "response scan ceiling exceeded", "exact transport response ceiling"},
		{"size-exempt response", AuditResponseScan, "size-exempt response from api.vendor.example is too large", "response_scanning.size_exempt_scan_max_bytes"},
		{"size-exempt inflight", AuditResponseScan, "size-exempt response scan would exceed size_exempt_scan_max_inflight_bytes", "response_scanning.size_exempt_scan_max_inflight_bytes"},
		{"request budget", AuditAgentBudget, "request budget exceeded: 11/10 requests", "max_requests_per_session"},
		{"domain budget", AuditAgentBudget, "domain budget exceeded: 6/5 unique domains", "max_unique_domains_per_session"},
		{"truncated byte budget alias", AuditBudgetTruncated, "response truncated at byte budget", "max_bytes_per_session"},
		{"TLS response integrity alias", AuditTLSResponseBlocked, "compressed response cannot be scanned", "scan-integrity failure"},
		{"request policy body ceiling", AuditRequestPolicy, "request body exceeds max_body_bytes (1024)", "request_body_scanning.max_body_bytes"},
		{"request policy unreadable body", AuditRequestPolicy, "request body could not be inspected: read failed", "no exemption"},
		{"baseline deviation", AuditSessionAnomaly, "baseline_deviation", "pipelock baseline show"},
		{"domain burst", AuditSessionAnomaly, "ip_domain_burst", "session_profiling.domain_burst"},
		{"frozen tool is airlock", AuditFrozenTool, "tool not in frozen inventory", "airlock.timers"},
		{"session deny alias", AuditSessionDeny, "critical", "affected identity session"},
		{"A2A header alias", AuditA2AHeader, "a2a: A2A-Extensions header contains blocked URI", "a2a_scanning.action"},
		{"redaction non JSON route", AuditRedaction, "redaction blocked request: non_json_body", "redaction.allowlist_unparseable_routes"},
		{"MCP cross-request entropy", AuditCrossRequestEntropy, "cross-request entropy budget exceeded: 900/800 bits", "entropy_budget.bits_per_window"},
		{"submit method", AuditReverseSubmit, "submit profile: method GET not in allowed_methods", "reverse_proxy.allowed_methods"},
		{"submit path", AuditReverseSubmit, "submit profile: path /v2 not in allowed_paths", "reverse_proxy.allowed_paths[].exact"},
		{"submit body", AuditReverseSubmit, "submit profile: body exceeds effective cap", "request_body_scanning.max_body_bytes"},
		{"submit raw path", AuditReverseSubmit, "submit profile: raw path rejected", "no exemption knob"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := OperatorHintForResult(tt.label, tt.reason)
			if !strings.Contains(hint, tt.want) {
				t.Fatalf("OperatorHintForResult(%q, %q) = %q, want substring %q", tt.label, tt.reason, hint, tt.want)
			}
		})
	}

	if hint := OperatorHintForResult(AuditFrozenTool, "tool not in frozen inventory"); strings.Contains(hint, "mcp_session_binding") {
		t.Fatalf("frozen-tool hint points at inert session-binding config: %q", hint)
	}
}

func TestRemediationHintsDoNotRecommendInertKnobs(t *testing.T) {
	t.Run("core response discloses scoped suppression", func(t *testing.T) {
		hint := OperatorHintForResult(ScannerCoreResponse, "core response pattern: role_override")
		if !strings.Contains(hint, "top-level `suppress:`") || !strings.Contains(hint, "exact core pattern") {
			t.Fatalf("core-response hint = %q, want its consulted scoped suppression", hint)
		}
		if !strings.Contains(hint, "cannot be disabled wholesale") {
			t.Fatalf("core-response hint = %q, want immutable-wholesale distinction", hint)
		}
	})

	t.Run("provenance omits inert sigstore trust fields", func(t *testing.T) {
		hint := OperatorHintForResult(AuditProvenance, "provenance verification failed")
		for _, inert := range []string{"trusted_issuers", "trusted_subjects"} {
			if strings.Contains(hint, "`mcp_tool_provenance."+inert+"`") {
				t.Fatalf("provenance hint = %q, presents inert %s as a config path", hint, inert)
			}
		}
		if !strings.Contains(hint, "trusted_keys") || !strings.Contains(hint, "unsigned tools only") {
			t.Fatalf("provenance hint = %q, want consumed key and exact action scope", hint)
		}
	})

	t.Run("MCP entropy omits HTTP-only host exemption", func(t *testing.T) {
		hint := OperatorHintForResult(AuditCrossRequestEntropy, "cross-request entropy budget exceeded: 900/800 bits")
		if strings.Contains(hint, "add only that host") {
			t.Fatalf("MCP entropy hint = %q, presents HTTP-only exemption as remediation", hint)
		}
		if !strings.Contains(hint, "does not consult `entropy_budget.exempt_domains`") {
			t.Fatalf("MCP entropy hint = %q, want explicit non-consultation warning", hint)
		}
	})

	t.Run("fetch response size omits transport-only exemption", func(t *testing.T) {
		hint := OperatorHintForResult(AuditResponseSize, "response exceeds fetch_proxy.max_response_mb")
		if strings.Contains(hint, "add the trusted host") {
			t.Fatalf("fetch response-size hint = %q, presents an unconsulted host exemption", hint)
		}
		if !strings.Contains(hint, "fetch-handler response-size blocks do not consult") {
			t.Fatalf("fetch response-size hint = %q, want transport limitation", hint)
		}
	})

	t.Run("redaction distinguishes non-JSON passthrough", func(t *testing.T) {
		nonJSON := OperatorHintForResult(AuditRedaction, "redaction blocked request: non_json_body")
		if !strings.Contains(nonJSON, "allowlist_unparseable_routes") || !strings.Contains(nonJSON, "forward the body unredacted") {
			t.Fatalf("non-JSON redaction hint = %q, want consulted route carve-out and consequence", nonJSON)
		}
		generic := OperatorHintForResult(AuditRedaction, "redaction blocked request: invalid profile")
		if !strings.Contains(generic, "no exemption knob") {
			t.Fatalf("generic redaction hint = %q, want fail-closed guidance", generic)
		}
	})

	t.Run("A2A hard floors omit configurable action", func(t *testing.T) {
		for _, reason := range []string{
			"a2a: input exceeds maximum inspectable nesting depth",
			"a2a: DLP: Hostname Exfiltration",
		} {
			hint := OperatorHintForResult(AuditA2AScan, reason)
			if strings.Contains(hint, "set `a2a_scanning.action") {
				t.Fatalf("hard-floor A2A hint = %q, presents action as remediation", hint)
			}
			if !strings.Contains(hint, "does not consult `a2a_scanning.action`") {
				t.Fatalf("hard-floor A2A hint = %q, want explicit non-consultation", hint)
			}
		}
		tunable := OperatorHintForResult(AuditA2AScan, "a2a: injection: prompt_override")
		if !strings.Contains(tunable, "set `a2a_scanning.action: warn`") {
			t.Fatalf("tunable A2A hint = %q, want consulted action", tunable)
		}
	})

	t.Run("Decide injection omits suppression remediation", func(t *testing.T) {
		hint := OperatorHintForResult(DecideInjectionLabel, "prompt override")
		if strings.Contains(hint, "for example suppress") {
			t.Fatalf("Decide injection hint = %q, presents unconsulted suppression", hint)
		}
		if !strings.Contains(hint, "suppression entry is inert here") {
			t.Fatalf("Decide injection hint = %q, want explicit non-consultation", hint)
		}
	})

	t.Run("URL data budget names the consumed field", func(t *testing.T) {
		hint := OperatorHintForResult(ScannerDataBudget, "data budget exceeded")
		if !strings.Contains(hint, "fetch_proxy.monitoring.max_data_per_minute") {
			t.Fatalf("data-budget hint = %q, want consumed scanner field", hint)
		}
	})

	t.Run("kill switch distinguishes transport exemptions", func(t *testing.T) {
		hint := OperatorHintForResult(AuditKillSwitch, "sentinel")
		if !strings.Contains(hint, "kill_switch.allowlist_ips") || !strings.Contains(hint, "Raw/MCP") {
			t.Fatalf("kill-switch hint = %q, want exact HTTP carve-out scope", hint)
		}
	})

	t.Run("reverse submit omits non-admission fields", func(t *testing.T) {
		hint := OperatorHintForResult(AuditReverseSubmit, "submit profile: method GET not in allowed_methods")
		for _, inert := range []string{"trusted_upstream", "request_timeout_seconds"} {
			if strings.Contains(hint, inert) {
				t.Fatalf("reverse-submit hint = %q, presents non-admission field %s", hint, inert)
			}
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
