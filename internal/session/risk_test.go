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
			URL:   "https://docs.github.com/copilot",
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
	if risk.LastExternalURL != "https://docs.github.com/copilot" {
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
