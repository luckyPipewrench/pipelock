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

// TestNewScanAPIIdentity_NamespaceCannotCollideWithOtherTransports proves the
// Scan API identity namespace is disjoint from every key shape the other CEE
// constructors in this package can produce: NewCEEIdentity (proxy) folds
// caller-supplied agent identities to the client address or "agent|client",
// and NewMCPCEEIdentity wraps a server-issued session string verbatim, so
// neither ever contains the 0x1f separator this constructor uses.
func TestNewScanAPIIdentity_NamespaceCannotCollideWithOtherTransports(t *testing.T) {
	scanAPIKey := NewScanAPIIdentity("caller-1").Key()

	proxyKeys := []string{
		NewCEEIdentity("agent-a", "203.0.113.10", envelope.ActorAuthBound).Key(),
		NewCEEIdentity("agent-a", "203.0.113.10", envelope.ActorAuthSelfDeclared).Key(),
		NewCEEIdentity("", "203.0.113.10", envelope.ActorAuthBound).Key(),
	}
	for _, k := range proxyKeys {
		if k == scanAPIKey {
			t.Errorf("proxy CEE key %q collided with Scan API key %q", k, scanAPIKey)
		}
	}

	mcpKeys := []string{
		NewMCPCEEIdentity("sess-123").Key(),
		NewMCPCEEIdentity("scanapi").Key(),
		NewMCPCEEIdentity("caller-1session-1").Key(), // no separator byte: cannot forge our prefix
	}
	for _, k := range mcpKeys {
		if k == scanAPIKey {
			t.Errorf("MCP CEE key %q collided with Scan API key %q", k, scanAPIKey)
		}
	}

	// An MCP session identifier is minted by the proxy protocol, not
	// attacker-chosen, so it cannot be made to equal our literal namespaced
	// string in practice. If it somehow did, the two transports still keep
	// physically separate FragmentBuffer instances (see
	// internal/scanapi/crossrequest.go and internal/mcp/cee.go), so an equal
	// key string alone would not let one transport's state leak into the
	// other's buffer.
}

// TestNewScanAPIIdentity_DifferentCallersOrSessionsDoNotCollide is a
// straightforward uniqueness check on the constructor's own key shape.
func TestNewScanAPIIdentity_DifferentCallersOrSessionsDoNotCollide(t *testing.T) {
	a := NewScanAPIIdentity("caller-a").Stream("session-1").Key()
	b := NewScanAPIIdentity("caller-b").Stream("session-1").Key()
	c := NewScanAPIIdentity("caller-a").Stream("session-2").Key()
	if a == b {
		t.Errorf("different callers with the same session_id produced the same key: %q", a)
	}
	if a == c {
		t.Errorf("different session_ids for the same caller produced the same key: %q", a)
	}
}

func TestBaselineKeyForSessionKey(t *testing.T) {
	tests := []struct {
		name, sessionKey, want string
	}{
		{"bound identity", "agent-a|203.0.113.1", "agent-a"},
		{"ipv4 folded", "203.0.113.1", "ip4-cb007101"},
		{"ipv6 folded", "2001:db8::1", "ip6-20010db8000000000000000000000001"},
		{"bracketed ipv6 folded", "[2001:db8::1]", "ip6-20010db8000000000000000000000001"},
		{"ipv4-mapped ipv6 folds to the ipv4 key", "::ffff:203.0.113.1", "ip4-cb007101"},
		{"non-IP peer identifier", "unix-peer", "ip-756e69782d70656572"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BaselineKeyForSessionKey(tt.sessionKey); got != tt.want {
				t.Fatalf("BaselineKeyForSessionKey(%q) = %q, want %q", tt.sessionKey, got, tt.want)
			}
		})
	}
}

func TestIsFoldedBaselineKey(t *testing.T) {
	for _, tt := range []struct {
		key  string
		want bool
	}{
		{key: "ip4-cb007101", want: true},
		{key: "ip6-20010db8000000000000000000000001", want: true},
		{key: "ip-756e69782d70656572", want: true},
		{key: "agent-a", want: false},
		{key: "ip4-nothex", want: false},
	} {
		if got := IsFoldedBaselineKey(tt.key); got != tt.want {
			t.Errorf("IsFoldedBaselineKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
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

func TestBaselineKeyForSessionKeyDelimiterInPeerIdentifier(t *testing.T) {
	t.Parallel()

	// A non-IP peer identifier containing the delimiter must not be read as a
	// named agent session: "svc|worker" is one opaque peer, not agent "svc" on
	// client "worker", and treating it as the former would let it share a
	// behavioral-baseline profile with a configured agent named "svc".
	named := BaselineKeyForSessionKey("svc|203.0.113.5")
	if named != "svc" {
		t.Fatalf("named session key = %q, want the agent component", named)
	}
	opaque := BaselineKeyForSessionKey("svc|worker")
	if opaque == "svc" {
		t.Fatalf("opaque peer identifier collided with the agent name %q", opaque)
	}
	if !IsFoldedBaselineKey(opaque) {
		t.Fatalf("opaque peer key = %q, want the reserved folded namespace", opaque)
	}
}
