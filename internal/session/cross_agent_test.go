// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestClassifyCrossAgentObservationPropagatesLevel proves a cross-agent
// observation carries the session's existing contamination level and is tagged
// with the cross_agent source kind plus the boundary in MatchReason.
func TestClassifyCrossAgentObservationPropagatesLevel(t *testing.T) {
	tests := []struct {
		name      string
		current   session.SessionRisk
		boundary  session.CrossAgentBoundary
		wantLevel session.TaintLevel
		wantKind  string
		wantMatch string
	}{
		{
			name: "untrusted propagates at untrusted",
			current: session.SessionRisk{
				Level:        session.TaintExternalUntrusted,
				Contaminated: true,
			},
			boundary:  session.CrossAgentBoundaryMCPToolCall,
			wantLevel: session.TaintExternalUntrusted,
			wantKind:  session.TaintSourceKindCrossAgent,
			wantMatch: "cross_agent_mcp_tool_call",
		},
		{
			name: "hostile propagates at hostile",
			current: session.SessionRisk{
				Level:        session.TaintExternalHostile,
				Contaminated: true,
				PromptHit:    true,
			},
			boundary:  session.CrossAgentBoundaryA2ARequest,
			wantLevel: session.TaintExternalHostile,
			wantKind:  session.TaintSourceKindCrossAgent,
			wantMatch: "cross_agent_a2a_request",
		},
		{
			name: "floors at untrusted when current somehow lower",
			current: session.SessionRisk{
				Level: session.TaintAllowlistedReference,
			},
			boundary:  session.CrossAgentBoundaryMCPToolCall,
			wantLevel: session.TaintExternalUntrusted,
			wantKind:  session.TaintSourceKindCrossAgent,
			wantMatch: "cross_agent_mcp_tool_call",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs := session.ClassifyCrossAgentObservation(tc.current, tc.boundary)
			if obs.Source.Level != tc.wantLevel {
				t.Fatalf("level = %v, want %v", obs.Source.Level, tc.wantLevel)
			}
			if obs.Source.Kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", obs.Source.Kind, tc.wantKind)
			}
			if obs.Source.MatchReason != tc.wantMatch {
				t.Fatalf("match reason = %q, want %q", obs.Source.MatchReason, tc.wantMatch)
			}
			// PromptHit must NOT be re-asserted by the cross-agent observation:
			// it re-triggers hostile escalation inside Observe and would taint
			// the propagation classification. The session's own PromptHit stays
			// sticky from the original ingest.
			if obs.PromptHit {
				t.Fatal("cross-agent observation must not set PromptHit")
			}
		})
	}
}

// TestClassifyCrossAgentObservationEmptyBoundary proves the defensive
// empty-boundary path produces the bare "cross_agent" match reason.
func TestClassifyCrossAgentObservationEmptyBoundary(t *testing.T) {
	obs := session.ClassifyCrossAgentObservation(
		session.SessionRisk{Level: session.TaintExternalUntrusted, Contaminated: true},
		session.CrossAgentBoundary(""),
	)
	if obs.Source.MatchReason != "cross_agent" {
		t.Fatalf("match reason = %q, want bare cross_agent", obs.Source.MatchReason)
	}
}

// TestCrossAgentObservationKeepsContaminationSticky proves folding a cross-agent
// observation into a contaminated session preserves Contaminated, never lowers
// the level, and preserves the contamination origin URL for evidence.
func TestCrossAgentObservationKeepsContaminationSticky(t *testing.T) {
	origin := "https://attacker.example/inject"
	risk := session.SessionRisk{}
	// Original hostile ingest.
	risk.Observe(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   origin,
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
		PromptHit:  true,
		MaxSources: 10,
	})
	if !risk.Contaminated || risk.Level != session.TaintExternalHostile {
		t.Fatalf("setup: contaminated=%v level=%v", risk.Contaminated, risk.Level)
	}

	// Cross-agent emission.
	obs := session.ClassifyCrossAgentObservation(risk.Snapshot(), session.CrossAgentBoundaryA2ARequest)
	obs.MaxSources = 10
	risk.Observe(obs)

	if !risk.Contaminated {
		t.Fatal("contamination must remain sticky across cross-agent emit")
	}
	if risk.Level != session.TaintExternalHostile {
		t.Fatalf("level lowered to %v, want hostile preserved", risk.Level)
	}
	// The contamination origin must survive as evidence on the cross_agent ref.
	last := risk.Sources[len(risk.Sources)-1]
	if last.Kind != session.TaintSourceKindCrossAgent {
		t.Fatalf("last source kind = %q, want cross_agent", last.Kind)
	}
	if last.URL != origin {
		t.Fatalf("cross_agent ref URL = %q, want origin %q", last.URL, origin)
	}
}

// TestSignalCrossAgentContaminationHasPoints proves the new adaptive signal
// carries a non-zero score so a cross-agent flow is escalatable, not a no-op.
func TestSignalCrossAgentContaminationHasPoints(t *testing.T) {
	pts, ok := session.SignalPoints[session.SignalCrossAgentContamination]
	if !ok {
		t.Fatal("SignalCrossAgentContamination missing from SignalPoints")
	}
	if pts <= 0 {
		t.Fatalf("SignalCrossAgentContamination points = %v, want > 0", pts)
	}
}
