// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// eventWithAgent builds a blocked event carrying an agent label and grade.
// The grade is omitted entirely when auth is "", which reproduces an emitter
// that never recorded provenance.
func eventWithAgent(agent, auth string) Event {
	fields := map[string]any{"agent": agent, "reason": "dlp"}
	if auth != "" {
		fields["agent_auth"] = auth
	}
	return Event{
		Severity:   SeverityCritical,
		Type:       "blocked",
		Timestamp:  time.Unix(0, 0).UTC(),
		InstanceID: "test-instance",
		Fields:     fields,
	}
}

// TestOCSFActorOnlyFromTrustedProvenance is the core regression guard: a
// caller-controlled agent label must never populate OCSF actor.user.name,
// because a SIEM reads that field as the identity that performed the action.
func TestOCSFActorOnlyFromTrustedProvenance(t *testing.T) {
	cases := []struct {
		name      string
		auth      string
		wantActor bool
	}{
		{"infrastructure bound", string(envelope.ActorAuthBound), true},
		{"operator configured", string(envelope.ActorAuthConfigDefault), true},
		{"caller named a known profile", string(envelope.ActorAuthMatched), false},
		{"caller self declared", string(envelope.ActorAuthSelfDeclared), false},
		{"grade never recorded", "", false},
		{"unrecognized grade", "totally-made-up", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actor := ocsfActorFromEvent(eventWithAgent("agent-a", tc.auth))
			if tc.wantActor {
				if actor == nil {
					t.Fatalf("grade %q is trusted; want actor.user.name populated", tc.auth)
				}
				if actor.User.Name != "agent-a" {
					t.Fatalf("actor.user.name = %q, want %q", actor.User.Name, "agent-a")
				}
				return
			}
			if actor != nil {
				t.Fatalf("grade %q is untrusted; actor.user.name leaked %q", tc.auth, actor.User.Name)
			}
		})
	}
}

// TestOCSFRetainsUntrustedLabelAdvisory proves the suppression above does not
// blind the operator: the label survives in the Pipelock-namespaced block with
// its grade, so it stays searchable without looking authenticated.
func TestOCSFRetainsUntrustedLabelAdvisory(t *testing.T) {
	out := FormatOCSFEvent(eventWithAgent("evil-actor", string(envelope.ActorAuthSelfDeclared)), "test")

	var probe map[string]any
	if err := json.Unmarshal([]byte(out), &probe); err != nil {
		t.Fatalf("OCSF output is not valid JSON: %v", err)
	}
	if _, present := probe["actor"]; present {
		t.Fatal("untrusted label produced an OCSF actor object")
	}
	if strings.Contains(out, `"user":{"name":"evil-actor"}`) {
		t.Fatal("untrusted label reached the OCSF user identity field")
	}
	if !strings.Contains(out, "evil-actor") {
		t.Fatal("label was dropped entirely; operator loses visibility")
	}
	if !strings.Contains(out, string(envelope.ActorAuthSelfDeclared)) {
		t.Fatal("advisory label emitted without its provenance grade")
	}
}

// TestCEFSuserOnlyFromTrustedProvenance covers the sibling export path. CEF
// suser is the source user; the same rule applies.
func TestCEFSuserOnlyFromTrustedProvenance(t *testing.T) {
	trusted := FormatCEFEvent(eventWithAgent("agent-a", string(envelope.ActorAuthBound)), "test")
	if !strings.Contains(trusted, "suser=agent-a") {
		t.Fatalf("bound identity should populate suser, got %q", trusted)
	}

	untrusted := FormatCEFEvent(eventWithAgent("evil-actor", string(envelope.ActorAuthSelfDeclared)), "test")
	if strings.Contains(untrusted, "suser=evil-actor") {
		t.Fatalf("self-declared label reached CEF suser: %q", untrusted)
	}
	if !strings.Contains(untrusted, "evil-actor") {
		t.Fatalf("label dropped entirely from CEF: %q", untrusted)
	}
	if !strings.Contains(untrusted, string(envelope.ActorAuthSelfDeclared)) {
		t.Fatalf("CEF advisory label missing its grade: %q", untrusted)
	}
}

// TestEventAgentIdentityFailsClosed states the invariant the whole fix rests
// on: an emitter that forgets to record provenance loses the identity field
// rather than laundering an ungraded name into it.
func TestEventAgentIdentityFailsClosed(t *testing.T) {
	label, auth, trusted := eventAgentIdentity(eventWithAgent("agent-a", ""))
	if label != "agent-a" {
		t.Fatalf("label = %q, want agent-a", label)
	}
	if auth != string(envelope.ActorAuthUnknown) {
		t.Fatalf("missing grade should normalize to unknown, got %q", auth)
	}
	if trusted {
		t.Fatal("ungraded label must not be trusted for identity")
	}
}
