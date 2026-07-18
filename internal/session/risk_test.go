// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSessionRiskObserve(t *testing.T) {
	var risk session.SessionRisk

	risk.Observe(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   testGitHubCopilotDocs,
			Kind:  "http_response",
			Level: session.TaintAllowlistedReference,
		},
		MaxSources: 2,
	})

	if risk.Level != session.TaintAllowlistedReference {
		t.Fatalf("level = %v, want allowlisted", risk.Level)
	}
	if risk.Contaminated {
		t.Fatal("allowlisted reference should not contaminate the session")
	}
	if risk.LastExternalURL != testGitHubCopilotDocs {
		t.Fatalf("last external url = %q", risk.LastExternalURL)
	}

	risk.Observe(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
		PromptHit:  true,
		MediaSeen:  true,
		MaxSources: 2,
	})

	if risk.Level != session.TaintExternalHostile {
		t.Fatalf("level = %v, want hostile", risk.Level)
	}
	if !risk.Contaminated {
		t.Fatal("untrusted exposure should contaminate the session")
	}
	if !risk.PromptHit {
		t.Fatal("expected prompt hit to be sticky")
	}
	if !risk.MediaSeen {
		t.Fatal("expected media_seen to be sticky")
	}
	if got := len(risk.Sources); got != 2 {
		t.Fatalf("sources length = %d, want 2", got)
	}
	if risk.Sources[1].Level != session.TaintExternalHostile {
		t.Fatalf("latest source level = %v, want hostile", risk.Sources[1].Level)
	}
}

func TestSessionRiskSnapshotCopiesSources(t *testing.T) {
	risk := session.SessionRisk{
		Level: session.TaintExternalUntrusted,
		Sources: []session.TaintSourceRef{
			{URL: "https://example.com", Level: session.TaintExternalUntrusted, Timestamp: time.Now().UTC()},
		},
	}

	snap := risk.Snapshot()
	snap.Sources[0].URL = "https://mutated.example"

	if risk.Sources[0].URL != "https://example.com" {
		t.Fatal("snapshot should deep-copy sources")
	}
}

func TestRiskWireLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"taint trusted", session.TaintTrusted.String(), "trusted"},
		{"taint internal", session.TaintInternalGenerated.String(), "internal_generated"},
		{"taint allowlisted", session.TaintAllowlistedReference.String(), "allowlisted_reference"},
		{"taint low risk", session.TaintExternalLowRisk.String(), "external_low_risk"},
		{"taint untrusted", session.TaintExternalUntrusted.String(), "external_untrusted"},
		{"taint hostile", session.TaintExternalHostile.String(), "external_hostile"},
		{"taint unknown", session.TaintLevel(255).String(), "unknown"},
		{"action read", session.ActionClassRead.String(), "read"},
		{"action browse", session.ActionClassBrowse.String(), "browse"},
		{"action summarize", session.ActionClassSummarize.String(), "summarize"},
		{"action write", session.ActionClassWrite.String(), "write"},
		{"action exec", session.ActionClassExec.String(), "exec"},
		{"action secret", session.ActionClassSecret.String(), "secret"},
		{"action publish", session.ActionClassPublish.String(), "publish"},
		{"action network", session.ActionClassNetwork.String(), "network"},
		{"action unknown", session.ActionClass(255).String(), "unknown"},
		{"sensitivity normal", session.SensitivityNormal.String(), "normal"},
		{"sensitivity elevated", session.SensitivityElevated.String(), "elevated"},
		{"sensitivity protected", session.SensitivityProtected.String(), "protected"},
		{"sensitivity unknown", session.ActionSensitivity(255).String(), "unknown"},
		{"authority unknown", session.AuthorityUnknown.String(), "unknown"},
		{"authority external", session.AuthorityExternal.String(), "external"},
		{"authority policy", session.AuthorityPolicy.String(), "policy"},
		{"authority user broad", session.AuthorityUserBroad.String(), "user_broad"},
		{"authority user exact", session.AuthorityUserExact.String(), "user_exact"},
		{"authority operator override", session.AuthorityOperatorOverride.String(), "operator_override"},
		{"authority invalid", session.AuthorityKind(255).String(), "unknown"},
		{"decision allow", session.PolicyAllow.String(), "allow"},
		{"decision warn", session.PolicyWarn.String(), "warn"},
		{"decision ask", session.PolicyAsk.String(), "ask"},
		{"decision block", session.PolicyBlock.String(), "block"},
		{"decision unknown", session.PolicyDecision(255).String(), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Fatalf("label = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestPolicyMatrixEvaluate(t *testing.T) {
	pm := session.PolicyMatrix{Profile: "balanced"}

	tests := []struct {
		name        string
		taint       session.TaintLevel
		action      session.ActionClass
		sensitivity session.ActionSensitivity
		authority   session.AuthorityKind
		want        session.PolicyDecision
		wantReason  string
	}{
		{
			name:       "read after hostile exposure still allowed",
			taint:      session.TaintExternalHostile,
			action:     session.ActionClassRead,
			authority:  session.AuthorityUnknown,
			want:       session.PolicyAllow,
			wantReason: "taint_safe_read_only_action",
		},
		{
			name:        "protected write after untrusted exposure asks",
			taint:       session.TaintExternalUntrusted,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUserBroad,
			want:        session.PolicyAsk,
			wantReason:  "protected_write_after_untrusted_external_exposure",
		},
		{
			name:        "protected write with exact authority allowed",
			taint:       session.TaintExternalUntrusted,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUserExact,
			want:        session.PolicyAllow,
			wantReason:  "no_taint_escalation_required",
		},
		{
			name:       "mutating exec after untrusted exposure asks",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassExec,
			authority:  session.AuthorityUserExact,
			want:       session.PolicyAsk,
			wantReason: "mutating_exec_after_untrusted_external_exposure",
		},
		{
			name:       "exec with operator override allowed",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassExec,
			authority:  session.AuthorityOperatorOverride,
			want:       session.PolicyAllow,
			wantReason: "no_taint_escalation_required",
		},
		{
			name:       "secret use after untrusted exposure asks",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassSecret,
			authority:  session.AuthorityUserBroad,
			want:       session.PolicyAsk,
			wantReason: "secret_use_after_untrusted_external_exposure",
		},
		{
			name:       "publish after untrusted exposure asks",
			taint:      session.TaintExternalUntrusted,
			action:     session.ActionClassPublish,
			authority:  session.AuthorityPolicy,
			want:       session.PolicyAsk,
			wantReason: "external_publish_after_untrusted_external_exposure",
		},
		{
			name:        "hostile sensitive action blocks",
			taint:       session.TaintExternalHostile,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityOperatorOverride,
			want:        session.PolicyBlock,
			wantReason:  "sensitive_action_after_hostile_external_exposure",
		},
		{
			name:        "trusted context does not escalate",
			taint:       session.TaintTrusted,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUnknown,
			want:        session.PolicyAllow,
			wantReason:  "trusted_or_allowlisted_context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pm.Evaluate(tt.taint, tt.action, tt.sensitivity, tt.authority)
			if got.Decision != tt.want {
				t.Fatalf("decision = %v, want %v", got.Decision, tt.want)
			}
			if got.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

func TestPolicyMatrixEvaluate_PermissiveObserveOnly(t *testing.T) {
	pm := session.PolicyMatrix{Profile: "permissive"}

	tests := []struct {
		name        string
		taint       session.TaintLevel
		action      session.ActionClass
		sensitivity session.ActionSensitivity
		authority   session.AuthorityKind
		opts        session.PolicyEvaluateOptions
	}{
		{
			name:      "publish after untrusted exposure allows",
			taint:     session.TaintExternalUntrusted,
			action:    session.ActionClassPublish,
			authority: session.AuthorityPolicy,
		},
		{
			name:      "secret use after untrusted exposure allows",
			taint:     session.TaintExternalUntrusted,
			action:    session.ActionClassSecret,
			authority: session.AuthorityUserBroad,
		},
		{
			name:      "exec after untrusted exposure allows",
			taint:     session.TaintExternalUntrusted,
			action:    session.ActionClassExec,
			authority: session.AuthorityUserExact,
		},
		{
			name:        "hostile sensitive action allows",
			taint:       session.TaintExternalHostile,
			action:      session.ActionClassWrite,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUnknown,
		},
		{
			name:        "fail safe low confidence read allows",
			taint:       session.TaintExternalHostile,
			action:      session.ActionClassRead,
			sensitivity: session.SensitivityProtected,
			authority:   session.AuthorityUserBroad,
			opts: session.PolicyEvaluateOptions{
				FailSafeClassification:  true,
				ClassificationConfident: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pm.EvaluateWithOptions(tt.taint, tt.action, tt.sensitivity, tt.authority, tt.opts)
			if got.Decision != session.PolicyAllow {
				t.Fatalf("decision = %s, want allow", got.Decision)
			}
			if got.Reason != "taint_permissive_observe_only" {
				t.Fatalf("reason = %q, want permissive observe-only", got.Reason)
			}
		})
	}
}

func TestPolicyMatrixEvaluateWithOptions_FailSafeLowConfidenceRead(t *testing.T) {
	t.Parallel()

	pm := session.PolicyMatrix{Profile: "balanced"}
	withoutFailSafe := pm.EvaluateWithOptions(
		session.TaintExternalHostile,
		session.ActionClassRead,
		session.SensitivityProtected,
		session.AuthorityUserBroad,
		session.PolicyEvaluateOptions{ClassificationConfident: false},
	)
	if withoutFailSafe.Decision != session.PolicyAllow {
		t.Fatalf("without fail-safe decision = %s, want allow", withoutFailSafe.Decision)
	}

	withFailSafe := pm.EvaluateWithOptions(
		session.TaintExternalHostile,
		session.ActionClassRead,
		session.SensitivityProtected,
		session.AuthorityUserBroad,
		session.PolicyEvaluateOptions{FailSafeClassification: true, ClassificationConfident: false},
	)
	if withFailSafe.Decision != session.PolicyBlock {
		t.Fatalf("with fail-safe decision = %s, want block", withFailSafe.Decision)
	}
}
