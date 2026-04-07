// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"strings"
	"testing"
)

func TestEnvelope_Serialize(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     "write",
		Verdict:    "allow",
		SideEffect: "external_write",
		Actor:      "agent:claude-code",
		ActorAuth:  ActorAuthBound,
		PolicyHash: []byte{0x62, 0x7e, 0x66, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		ReceiptID:  "01961f3a-7b2c-7000-8000-000000000001",
		Timestamp:  1712345678,
	}

	got, err := env.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	for _, key := range []string{"v=", "act=", "vd=", "se=", "actor=", "aa=", "ph=", "rid=", "ts="} {
		if !strings.Contains(got, key) {
			t.Errorf("Serialize() missing key %q in %q", key, got)
		}
	}

	if len(got) > 512 {
		t.Errorf("Serialize() = %d bytes, want <= 512", len(got))
	}
}

func TestEnvelope_Serialize_RoundTrip(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     "read",
		Verdict:    "allow",
		SideEffect: "none",
		Actor:      "agent:test",
		ActorAuth:  ActorAuthSelfDeclared,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		ReceiptID:  "01961f3a-7b2c-7000-8000-000000000002",
		Timestamp:  1712345679,
	}

	serialized, err := env.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error: %v", err)
	}

	parsed, err := Parse(serialized)
	if err != nil {
		t.Fatalf("Parse(%q) error: %v", serialized, err)
	}

	if parsed.Version != env.Version {
		t.Errorf("Version = %d, want %d", parsed.Version, env.Version)
	}
	if parsed.Action != env.Action {
		t.Errorf("Action = %q, want %q", parsed.Action, env.Action)
	}
	if parsed.Verdict != env.Verdict {
		t.Errorf("Verdict = %q, want %q", parsed.Verdict, env.Verdict)
	}
	if parsed.Actor != env.Actor {
		t.Errorf("Actor = %q, want %q", parsed.Actor, env.Actor)
	}
	if parsed.ActorAuth != env.ActorAuth {
		t.Errorf("ActorAuth = %q, want %q", parsed.ActorAuth, env.ActorAuth)
	}
	if parsed.ReceiptID != env.ReceiptID {
		t.Errorf("ReceiptID = %q, want %q", parsed.ReceiptID, env.ReceiptID)
	}
	if parsed.Timestamp != env.Timestamp {
		t.Errorf("Timestamp = %d, want %d", parsed.Timestamp, env.Timestamp)
	}
}

func TestEnvelope_ToMCPMeta(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     "write",
		Verdict:    "allow",
		SideEffect: "external_write",
		Actor:      "agent:claude-code",
		ActorAuth:  ActorAuthMatched,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		ReceiptID:  "01961f3a-7b2c-7000-8000-000000000001",
		Timestamp:  1712345678,
	}

	meta := env.ToMCPMeta()

	if meta["act"] != "write" {
		t.Errorf("act = %v, want %q", meta["act"], "write")
	}
	if meta["vd"] != "allow" {
		t.Errorf("vd = %v, want %q", meta["vd"], "allow")
	}
	if meta["aa"] != string(ActorAuthMatched) {
		t.Errorf("aa = %v, want %q", meta["aa"], ActorAuthMatched)
	}
	if _, ok := meta["v"]; !ok {
		t.Error("missing version field 'v'")
	}
}

func TestActorAuth_Constants(t *testing.T) {
	t.Parallel()

	levels := []ActorAuth{ActorAuthBound, ActorAuthMatched, ActorAuthSelfDeclared}
	seen := make(map[ActorAuth]bool)
	for _, l := range levels {
		if seen[l] {
			t.Errorf("duplicate ActorAuth value: %q", l)
		}
		seen[l] = true
	}
}
