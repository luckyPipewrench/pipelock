// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// Protocol revision 2026-07-28 removes sessions, so denial-of-wallet can no
// longer demand server-minted session evidence before billing a subject. What
// it can do is grade how well the subject is identified and let the operator
// declare the weakest grade they will bill against.
func TestDoWSubjectTrust_Grading(t *testing.T) {
	req := func() *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://listener.example/", nil)
		r.RemoteAddr = "198.51.100.7:44321"
		return r
	}

	t.Run("socket only is the weakest grade", func(t *testing.T) {
		key, trust := dowSubjectTrust(req(), MCPProxyOpts{})
		if trust != config.DoWTrustNetwork {
			t.Errorf("trust = %v, want config.DoWTrustNetwork", trust)
		}
		if key == "" {
			t.Error("subject key empty: a socket-derived key is always computable")
		}
	})

	t.Run("bound agent identity grades above socket", func(t *testing.T) {
		_, trust := dowSubjectTrust(req(), MCPProxyOpts{
			DoWSubjectAgent:     "agent-a",
			DoWSubjectAgentAuth: envelope.ActorAuthBound,
		})
		if trust != config.DoWTrustAgent {
			t.Errorf("trust = %v, want config.DoWTrustAgent", trust)
		}
	})

	// A self-declared agent name is request-supplied, so honouring it would let
	// a client mint a fresh budget bucket per name. CEESafeAgent already refuses
	// it for key construction; the trust grade must refuse it too, or an
	// operator requiring agent grade could be satisfied by an attacker's claim.
	t.Run("self-declared agent identity does not grade above socket", func(t *testing.T) {
		for _, auth := range []envelope.ActorAuth{
			envelope.ActorAuthSelfDeclared,
			envelope.ActorAuthMatched,
			envelope.ActorAuth(""),
		} {
			_, trust := dowSubjectTrust(req(), MCPProxyOpts{
				DoWSubjectAgent:     "attacker-chosen",
				DoWSubjectAgentAuth: auth,
			})
			if trust != config.DoWTrustNetwork {
				t.Errorf("auth %q graded %v, want config.DoWTrustNetwork", auth, trust)
			}
		}
	})

	t.Run("authenticated principal is the strongest grade", func(t *testing.T) {
		opts := MCPProxyOpts{
			DoWSubjectAgent:           "agent-a",
			DoWAuthenticatedPrincipal: func(*http.Request) string { return "sub-42" },
		}
		key, trust := dowSubjectTrust(req(), opts)
		if trust != config.DoWTrustPrincipal {
			t.Errorf("trust = %v, want config.DoWTrustPrincipal", trust)
		}
		if key != "sub-42" {
			t.Errorf("key = %q, want the principal", key)
		}
	})

	t.Run("an empty principal falls through rather than blanking the subject", func(t *testing.T) {
		opts := MCPProxyOpts{
			DoWSubjectAgent:           "agent-a",
			DoWSubjectAgentAuth:       envelope.ActorAuthBound,
			DoWAuthenticatedPrincipal: func(*http.Request) string { return "" },
		}
		key, trust := dowSubjectTrust(req(), opts)
		if trust != config.DoWTrustAgent {
			t.Errorf("trust = %v, want config.DoWTrustAgent when the principal resolver yields nothing", trust)
		}
		if key == "" {
			t.Error("subject key empty: an absent principal must not erase the subject")
		}
	})

	t.Run("distinct clients get distinct subjects at socket grade", func(t *testing.T) {
		a := req()
		b := req()
		b.RemoteAddr = "198.51.100.9:5555"
		keyA, _ := dowSubjectTrust(a, MCPProxyOpts{})
		keyB, _ := dowSubjectTrust(b, MCPProxyOpts{})
		if keyA == keyB {
			t.Error("distinct client addresses produced the same subject key")
		}
	})

	t.Run("subject never collapses to the shared default bucket", func(t *testing.T) {
		for _, opts := range []MCPProxyOpts{
			{},
			{DoWSubjectAgent: "agent-a"},
			{DoWSubjectAgent: "agent-a", DoWSubjectAgentAuth: envelope.ActorAuthBound},
		} {
			if key, _ := dowSubjectTrust(req(), opts); key == "" {
				t.Errorf("empty subject key for opts %+v: an empty key shares one budget across every client", opts)
			}
		}
	})
}

// The operator declares the weakest grade they will bill against. Meeting or
// exceeding it proceeds; falling below it is refused. The default must be the
// weakest grade, or enabling budgets would refuse all sessionless traffic.
func TestDoWSubjectTrust_MeetsMinimum(t *testing.T) {
	for _, tc := range []struct {
		name    string
		have    config.DoWSubjectTrust
		min     config.DoWSubjectTrust
		allowed bool
	}{
		{"socket meets socket", config.DoWTrustNetwork, config.DoWTrustNetwork, true},
		{"agent exceeds socket", config.DoWTrustAgent, config.DoWTrustNetwork, true},
		{"principal exceeds all", config.DoWTrustPrincipal, config.DoWTrustNetwork, true},
		{"socket below agent", config.DoWTrustNetwork, config.DoWTrustAgent, false},
		{"socket below principal", config.DoWTrustNetwork, config.DoWTrustPrincipal, false},
		{"agent below principal", config.DoWTrustAgent, config.DoWTrustPrincipal, false},
		{"principal meets principal", config.DoWTrustPrincipal, config.DoWTrustPrincipal, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.have.Meets(tc.min); got != tc.allowed {
				t.Errorf("%v.Meets(%v) = %v, want %v", tc.have, tc.min, got, tc.allowed)
			}
		})
	}
}
