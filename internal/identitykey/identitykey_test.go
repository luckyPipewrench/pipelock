// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package identitykey

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

func TestCEESafeKey_OnlyTrustedAgentAuthNamespacesBucket(t *testing.T) {
	tests := []struct {
		name string
		auth envelope.ActorAuth
		want string
	}{
		{name: "bound", auth: envelope.ActorAuthBound, want: "agent-a|203.0.113.10"},
		{name: "config default", auth: envelope.ActorAuthConfigDefault, want: "agent-a|203.0.113.10"},
		{name: "matched", auth: envelope.ActorAuthMatched, want: "203.0.113.10"},
		{name: "self declared", auth: envelope.ActorAuthSelfDeclared, want: "203.0.113.10"},
		{name: "unset", auth: "", want: "203.0.113.10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CEESafeKey("agent-a", "203.0.113.10", tt.auth); got != tt.want {
				t.Fatalf("CEESafeKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCEEIdentity_AuthGradeControlsOwnerAndStreamDoesNot(t *testing.T) {
	const agent, client = "agent-a", "203.0.113.10"
	selfDeclared := NewCEEIdentity(agent, client, envelope.ActorAuthSelfDeclared)
	otherSelfDeclared := NewCEEIdentity("agent-b", client, envelope.ActorAuthSelfDeclared)
	bound := NewCEEIdentity(agent, client, envelope.ActorAuthBound)

	if selfDeclared != otherSelfDeclared {
		t.Fatalf("self-declared identities partitioned: %q != %q", selfDeclared, otherSelfDeclared)
	}
	if selfDeclared == bound {
		t.Fatalf("bound identity unexpectedly folded into %q", selfDeclared)
	}
	if selfDeclared.Stream("|keys") == selfDeclared.Stream("|path") {
		t.Fatal("stream partitions collapsed")
	}
}

func TestCEEIdentity_ClassificationAndResetCandidates(t *testing.T) {
	const client = "203.0.113.10"
	for _, auth := range []envelope.ActorAuth{"", "unrecognized", envelope.ActorAuthSelfDeclared, envelope.ActorAuthMatched, envelope.ActorAuthBound, envelope.ActorAuthConfigDefault} {
		t.Run(string(auth), func(t *testing.T) {
			identity := NewCEEIdentity("agent-a", client, auth)
			trusted := auth == envelope.ActorAuthBound || auth == envelope.ActorAuthConfigDefault
			want := client
			if trusted {
				want = "agent-a|" + client
			}
			if identity.Key() != want {
				t.Fatalf("key=%q, want %q", identity.Key(), want)
			}
			stream := identity.Stream("|keys")
			if stream.Owner() != identity || stream.Key() != want+"|keys" {
				t.Fatal("stream lost its classified owner")
			}
			found := false
			for _, candidate := range CEECandidateIdentities("agent-a", client) {
				found = found || candidate == identity
			}
			if !found {
				t.Fatal("reset cannot reach a live identity")
			}
		})
	}
	if got := CEECandidateIdentities("", client); len(got) != 1 {
		t.Fatalf("unnamed reset candidates=%v, want one identity", got)
	}
	if id := NewMCPCEEIdentity("server-session"); id.Key() != "server-session" || id.Stream("").Owner() != id {
		t.Fatal("MCP server session did not preserve its owner")
	}
}

func TestCEECandidateKeys(t *testing.T) {
	tests := []struct {
		name   string
		agent  string
		client string
		want   []string
	}{
		{
			name:   "named agent yields both folded and namespaced keys",
			agent:  "myagent",
			client: "10.0.0.5",
			want:   []string{"myagent|10.0.0.5", "10.0.0.5"},
		},
		{
			name:   "anonymous agent yields a single folded key",
			agent:  "",
			client: "10.0.0.5",
			want:   []string{"10.0.0.5"},
		},
		{
			name:   "anonymous sentinel folds to the client too",
			agent:  AnonymousAgent,
			client: "10.0.0.5",
			want:   []string{"10.0.0.5"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CEECandidateKeys(tt.agent, tt.client)
			if len(got) != len(tt.want) {
				t.Fatalf("CEECandidateKeys() = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("CEECandidateKeys()[%d] = %q, want %q (full %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

// The candidate set must contain whatever CEESafeKey produces for every grade,
// so reset (which enumerates the set) can never miss the key the live path wrote.
func TestCEECandidateKeysCoverEveryGrade(t *testing.T) {
	const agent, client = "myagent", "10.0.0.5"
	candidates := CEECandidateKeys(agent, client)
	inSet := func(k string) bool {
		for _, c := range candidates {
			if c == k {
				return true
			}
		}
		return false
	}
	for _, auth := range []envelope.ActorAuth{
		envelope.ActorAuthBound, envelope.ActorAuthConfigDefault,
		envelope.ActorAuthMatched, envelope.ActorAuthSelfDeclared, "",
	} {
		live := CEESafeKey(agent, client, auth)
		if !inSet(live) {
			t.Fatalf("grade %q live key %q not in candidate set %v", auth, live, candidates)
		}
	}
}
