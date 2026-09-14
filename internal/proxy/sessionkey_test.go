// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

func TestSessionKeyFor(t *testing.T) {
	tests := []struct {
		name     string
		agent    string
		clientIP string
		auth     envelope.ActorAuth
		want     string
	}{
		{
			name:     "named agent namespaces ahead of ip",
			agent:    "agent-a",
			clientIP: "10.0.0.1",
			auth:     envelope.ActorAuthBound,
			want:     "agent-a|10.0.0.1",
		},
		{
			name:     "empty agent keys on ip alone",
			agent:    "",
			clientIP: "10.0.0.1",
			auth:     envelope.ActorAuthUnknown,
			want:     "10.0.0.1",
		},
		{
			name:     "anonymous agent keys on ip alone",
			agent:    agentAnonymous,
			clientIP: "10.0.0.1",
			auth:     envelope.ActorAuthUnknown,
			want:     "10.0.0.1",
		},
		{
			name:     "bound named agents on same ip stay distinct",
			agent:    "agent-b",
			clientIP: "10.0.0.1",
			auth:     envelope.ActorAuthBound,
			want:     "agent-b|10.0.0.1",
		},
		{
			name:     "named agent with empty ip",
			agent:    "agent-a",
			clientIP: "",
			auth:     envelope.ActorAuthBound,
			want:     "agent-a|",
		},
		{
			name:     "empty agent and empty ip",
			agent:    "",
			clientIP: "",
			auth:     envelope.ActorAuthUnknown,
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sessionKeyFor(tt.agent, tt.clientIP, tt.auth); got != tt.want {
				t.Errorf("sessionKeyFor(%q, %q, %q) = %q, want %q", tt.agent, tt.clientIP, tt.auth, got, tt.want)
			}
		})
	}
}

func TestSessionKeyForFoldsRequestControlledNames(t *testing.T) {
	const clientIP = "192.0.2.10"

	for _, auth := range []envelope.ActorAuth{envelope.ActorAuthSelfDeclared, envelope.ActorAuthMatched, envelope.ActorAuthUnknown} {
		t.Run(string(auth), func(t *testing.T) {
			first := sessionKeyFor("caller-a", clientIP, auth)
			second := sessionKeyFor("caller-b", clientIP, auth)
			if first != clientIP || second != clientIP {
				t.Fatalf("request-controlled names must fold to client key %q, got %q and %q", clientIP, first, second)
			}
		})
	}
}

func TestSessionKeyForKeepsBoundAndSelfDeclaredIdentitySeparate(t *testing.T) {
	const (
		agent    = "agent-a"
		clientIP = "192.0.2.10"
	)

	bound := sessionKeyFor(agent, clientIP, envelope.ActorAuthBound)
	selfDeclared := sessionKeyFor(agent, clientIP, envelope.ActorAuthSelfDeclared)
	if bound != agent+"|"+clientIP {
		t.Fatalf("bound key = %q, want %q", bound, agent+"|"+clientIP)
	}
	if selfDeclared != clientIP {
		t.Fatalf("self-declared key = %q, want client key %q", selfDeclared, clientIP)
	}
	if bound == selfDeclared {
		t.Fatalf("bound and self-declared identities shared key %q", bound)
	}
}
