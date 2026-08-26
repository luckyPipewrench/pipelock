// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// TestAuditContextCarriesRequestProvenance closes the gap that let a broken
// version of this change ship a regression.
//
// The formatter tests in internal/emit build an event map and set agent_auth by
// hand, so they prove the export gate and nothing about how the grade gets
// there. That is exactly the author-shaped evidence problem: the first attempt
// added a request-aware audit helper and wired zero call sites, every event
// reported unknown, and the typed SIEM identity fields were withheld even from
// infrastructure-bound deployments. Every formatter test still passed.
//
// This asserts the propagation itself: a request context carrying a grade
// produces an audit context carrying that same grade.
func TestAuditContextCarriesRequestProvenance(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		auth envelope.ActorAuth
		want string
	}{
		{"infrastructure bound", envelope.ActorAuthBound, string(envelope.ActorAuthBound)},
		{"operator configured", envelope.ActorAuthConfigDefault, string(envelope.ActorAuthConfigDefault)},
		{"caller self declared", envelope.ActorAuthSelfDeclared, string(envelope.ActorAuthSelfDeclared)},
		{"pattern matched", envelope.ActorAuthMatched, string(envelope.ActorAuthMatched)},
		{"explicitly unknown", envelope.ActorAuthUnknown, string(envelope.ActorAuthUnknown)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.WithValue(context.Background(), ctxKeyAgentAuth, string(tc.auth))
			actx := newHTTPAuditContext(ctx, nil, "GET", "https://api.vendor.example/x", "10.0.0.1", "req-1", "agent-a")
			if got := actx.AgentAuth(); got != tc.want {
				t.Fatalf("audit context grade = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAuditContextWithoutProvenanceFailsClosed pins the safe default: a context
// that never carried a grade must report unknown, not empty, so the export gate
// treats it as untrusted rather than reading a missing value as benign.
func TestAuditContextWithoutProvenanceFailsClosed(t *testing.T) {
	t.Parallel()
	actx := newHTTPAuditContext(context.Background(), nil, "GET", "https://api.vendor.example/x", "10.0.0.1", "req-1", "agent-a")
	if got := actx.AgentAuth(); got != string(envelope.ActorAuthUnknown) {
		t.Fatalf("ungraded context should report unknown, got %q", got)
	}
}

// TestConnectAuditContextCarriesRequestProvenance covers the CONNECT surface.
// It took its context from nowhere until this change, so every CONNECT event
// reported unknown provenance no matter how the label had been established.
func TestConnectAuditContextCarriesRequestProvenance(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), ctxKeyAgentAuth, string(envelope.ActorAuthBound))
	actx := newConnectAuditContext(ctx, nil, "api.vendor.example:443", "10.0.0.1", "req-1", "agent-a")
	if got := actx.AgentAuth(); got != string(envelope.ActorAuthBound) {
		t.Fatalf("connect audit context grade = %q, want bound", got)
	}
}

// TestConnectAuditContextWithoutProvenanceFailsClosed is the CONNECT twin of
// the fail-closed default above.
func TestConnectAuditContextWithoutProvenanceFailsClosed(t *testing.T) {
	t.Parallel()
	actx := newConnectAuditContext(context.Background(), nil, "api.vendor.example:443", "10.0.0.1", "req-1", "agent-a")
	if got := actx.AgentAuth(); got != string(envelope.ActorAuthUnknown) {
		t.Fatalf("ungraded connect context should report unknown, got %q", got)
	}
}

// TestUnrecognizedGradeIsNotTrusted pins that a grade string nobody defined is
// treated as untrusted rather than passed through as if it were meaningful.
func TestUnrecognizedGradeIsNotTrusted(t *testing.T) {
	t.Parallel()
	if envelope.NormalizeActorAuth("totally-made-up").TrustedForIdentity() {
		t.Fatal("an unrecognized grade must not be trusted for identity")
	}
}
