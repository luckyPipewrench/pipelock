// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestEnvelope_Serialize(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     testActionWrite,
		Verdict:    testVerdictAllow,
		SideEffect: testSideEffectExt,
		Actor:      "agent:claude-code",
		ActorAuth:  ActorAuthBound,
		PolicyHash: []byte{0x62, 0x7e, 0x66, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		ReceiptID:  testReceiptID1,
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
		Action:     testActionRead,
		Verdict:    testVerdictAllow,
		SideEffect: "none",
		Actor:      testActorAgentTest,
		ActorAuth:  ActorAuthSelfDeclared,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		ReceiptID:  testReceiptID2,
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
	if parsed.SideEffect != env.SideEffect {
		t.Errorf("SideEffect = %q, want %q", parsed.SideEffect, env.SideEffect)
	}
	if !bytes.Equal(parsed.PolicyHash, env.PolicyHash) {
		t.Errorf("PolicyHash = %x, want %x", parsed.PolicyHash, env.PolicyHash)
	}
}

func TestEnvelope_ToMCPMeta(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     testActionWrite,
		Verdict:    testVerdictAllow,
		SideEffect: testSideEffectExt,
		Actor:      "agent:claude-code",
		ActorAuth:  ActorAuthMatched,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		ReceiptID:  testReceiptID1,
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

func TestEnvelope_ToMCPMeta_OmitsOptionalEmptyFields(t *testing.T) {
	t.Parallel()

	meta := Envelope{
		Version:    1,
		Action:     testActionRead,
		Verdict:    testVerdictAllow,
		SideEffect: "none",
		Actor:      testActorAgentTest,
		ActorAuth:  ActorAuthSelfDeclared,
		PolicyHash: []byte{0x01},
		ReceiptID:  "01961f3a-7b2c-7000-8000-000000000003",
		Timestamp:  1712345680,
	}.ToMCPMeta()

	for _, key := range []string{"taint", "auth", "authr", "reauth"} {
		if _, ok := meta[key]; ok {
			t.Fatalf("unexpected optional field %q in MCP meta", key)
		}
	}
}

func TestActorAuth_Constants(t *testing.T) {
	t.Parallel()

	levels := []ActorAuth{ActorAuthBound, ActorAuthMatched, ActorAuthConfigDefault, ActorAuthSelfDeclared}
	seen := make(map[ActorAuth]bool)
	for _, l := range levels {
		if seen[l] {
			t.Errorf("duplicate ActorAuth value: %q", l)
		}
		seen[l] = true
	}
}

func TestParse_RejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"missing version", `act="read", vd="allow", rid="id-1"`, `missing required field "v"`},
		{"missing action", `v=1, vd="allow", rid="id-1"`, `missing required field "act"`},
		{"missing verdict", `v=1, act="read", rid="id-1"`, `missing required field "vd"`},
		{"missing receipt_id", `v=1, act="read", vd="allow"`, `missing required field "rid"`},
		{"missing timestamp", `v=1, act="read", vd="allow", rid="id-1"`, `missing required field "ts"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should contain %q", err, tt.want)
			}
		})
	}
}

func TestParse_RejectsUnknownActorAuth(t *testing.T) {
	t.Parallel()

	_, err := Parse(`v=1, act="read", vd="allow", rid="id-1", ts=1712345678, aa="root"`)
	if err == nil {
		t.Fatal("expected error for unknown actor_auth, got nil")
	}
	if !strings.Contains(err.Error(), "unknown actor_auth") {
		t.Errorf("error %q should mention actor_auth", err)
	}
}

func TestParse_AcceptsValidActorAuth(t *testing.T) {
	t.Parallel()

	for _, aa := range []string{"bound", "matched", "config-default", "self-declared", ""} {
		input := `v=1, act="read", vd="allow", rid="id-1", ts=1712345678`
		if aa != "" {
			input += `, aa="` + aa + `"`
		}
		env, err := Parse(input)
		if err != nil {
			t.Errorf("ActorAuth=%q: unexpected error: %v", aa, err)
			continue
		}
		if string(env.ActorAuth) != aa {
			t.Errorf("ActorAuth = %q, want %q", env.ActorAuth, aa)
		}
	}
}

// TestEnvelope_Hop_RoundTrip proves Hop is omitted when zero and
// round-trips losslessly when positive. Hop is how downstream
// verifiers distinguish an original envelope from one rebuilt by the
// redirect-refresh path at internal/proxy/proxy.go:328.
func TestEnvelope_Hop_RoundTrip(t *testing.T) {
	t.Parallel()

	// Hop == 0 must not appear on the wire at all.
	zero := Envelope{
		Version:    1,
		Action:     testActionRead,
		Verdict:    testVerdictAllow,
		ActorAuth:  ActorAuthBound,
		ReceiptID:  "id-zero",
		Timestamp:  1712345678,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}
	out, err := zero.Serialize()
	if err != nil {
		t.Fatalf("Serialize zero hop: %v", err)
	}
	if strings.Contains(out, "hop=") {
		t.Errorf("hop=0 should be omitted from the wire, got %q", out)
	}

	// Hop == 3 must survive Serialize → Parse intact.
	refreshed := zero
	refreshed.Hop = 3
	out2, err := refreshed.Serialize()
	if err != nil {
		t.Fatalf("Serialize hop=3: %v", err)
	}
	if !strings.Contains(out2, "hop=3") {
		t.Errorf("expected hop=3 in serialized envelope, got %q", out2)
	}
	parsed, err := Parse(out2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Hop != 3 {
		t.Errorf("parsed Hop = %d, want 3", parsed.Hop)
	}
}

// TestParse_RejectsNegativeHop confirms the hop wire key cannot
// deserialize to a negative value. Negative hop is either a parser
// bug or an attacker-crafted inbound envelope; either way, fail closed.
func TestParse_RejectsNegativeHop(t *testing.T) {
	t.Parallel()

	input := `v=1, act="read", vd="allow", rid="id-1", ts=1712345678, hop=-1`
	_, err := Parse(input)
	if err == nil {
		t.Error("Parse should reject hop=-1")
	}
}

// TestSerialize_RejectsNegativeHop mirrors the Parse-side guard on the
// Serialize side. Serialize never saw a negative Hop until the PR #403
// refactor split redirect refresh out; guard it loudly so a future
// caller that does `env.Hop--` below zero gets a build-time crash
// rather than a silently-dropped wire key.
func TestSerialize_RejectsNegativeHop(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     testActionRead,
		Verdict:    testVerdictAllow,
		ActorAuth:  ActorAuthBound,
		ReceiptID:  "id-neg",
		Timestamp:  1712345678,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		Hop:        -1,
	}
	if _, err := env.Serialize(); err == nil {
		t.Error("Serialize should reject Hop = -1")
	}
}

// TestParse_RejectsNonIntegerHop covers the typed rejection path: a hop
// key that's structurally valid RFC 8941 but not an integer (e.g. a
// string) must be refused. The parse path branches on item type, and
// leaving the non-Integer case silent would be a soft-downgrade vector.
func TestParse_RejectsNonIntegerHop(t *testing.T) {
	t.Parallel()

	// hop as a string instead of an integer.
	input := `v=1, act="read", vd="allow", rid="id-str-hop", ts=1712345678, hop="three"`
	if _, err := Parse(input); err == nil {
		t.Error("Parse should reject non-integer hop value")
	}
}

func TestParse_RejectsInnerListHop(t *testing.T) {
	t.Parallel()
	input := `v=1, act="read", vd="allow", rid="id-list-hop", ts=1712345678, hop=(1)`
	_, err := Parse(input)
	if err == nil || !strings.Contains(err.Error(), "unexpected member type") {
		t.Fatalf("Parse error = %v, want hop member-type rejection", err)
	}
}

func TestEnvelope_OptionalFieldsRoundTrip(t *testing.T) {
	t.Parallel()
	env := Envelope{
		Version:        1,
		Action:         testActionRead,
		Verdict:        testVerdictAllow,
		ActorAuth:      ActorAuthBound,
		ReceiptID:      "id-opt",
		Timestamp:      1712345678,
		PolicyHash:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		SessionTaint:   "taint-1",
		TaskID:         "task-1",
		AuthorityKind:  "hitl",
		AuthorityRef:   "ticket-9",
		RequiresReauth: true,
		Hop:            2,
	}
	wire, err := env.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	for _, key := range []string{"taint=", "task=", "auth=", "authr=", "reauth", "hop=2"} {
		if !strings.Contains(wire, key) {
			t.Fatalf("serialized envelope missing %q: %s", key, wire)
		}
	}
	got, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.SessionTaint != env.SessionTaint || got.TaskID != env.TaskID ||
		got.AuthorityKind != env.AuthorityKind || got.AuthorityRef != env.AuthorityRef ||
		got.RequiresReauth != env.RequiresReauth || got.Hop != env.Hop {
		t.Fatalf("parsed optional fields = %+v, want %+v", got, env)
	}
}

func TestEnvelope_ToMCPMetaOptionalFields(t *testing.T) {
	t.Parallel()
	meta := Envelope{
		Version:        1,
		Action:         testActionRead,
		Verdict:        testVerdictAllow,
		SessionTaint:   "taint-1",
		TaskID:         "task-1",
		AuthorityKind:  "hitl",
		AuthorityRef:   "ticket-9",
		RequiresReauth: true,
		Hop:            4,
	}.ToMCPMeta()
	if meta["taint"] != "taint-1" || meta["task"] != "task-1" || meta["auth"] != "hitl" || meta["authr"] != "ticket-9" {
		t.Fatalf("optional string fields = %#v", meta)
	}
	if meta["reauth"] != true {
		t.Fatalf("reauth = %v, want true", meta["reauth"])
	}
	if meta["hop"] != 4 {
		t.Fatalf("hop = %v, want 4", meta["hop"])
	}
}

func TestParseActorRejectsEmptyQueryAndBareDomain(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "  ", want: "actor must not be empty"},
		{name: "bare_domain", raw: "spiffe://trust.example", want: "workload path must not be empty"},
		{name: "query", raw: "spiffe://trust.example/agent/x?q=1", want: "query or fragment"},
		{name: "fragment", raw: "spiffe://trust.example/agent/x#frag", want: "query or fragment"},
		{name: "bad_percent", raw: "spiffe://trust.example/%zz", want: "parse SPIFFE actor"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseActor(tt.raw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseActor(%q) = %v, want %q", tt.raw, err, tt.want)
			}
		})
	}
}

func TestIsValidTrustDomainRejectsIPv4(t *testing.T) {
	t.Parallel()
	if IsValidTrustDomain("192.0.2.1") {
		t.Fatal("IPv4 trust domain accepted")
	}
	if !IsValidTrustDomain("trust.example") {
		t.Fatal("valid DNS trust domain rejected")
	}
}

func TestFormatActorRejectsInvalidExistingSPIFFE(t *testing.T) {
	t.Parallel()
	_, err := FormatActor("spiffe://trust.example", ActorFormatSPIFFE, "trust.example")
	if err == nil || !strings.Contains(err.Error(), "workload path must not be empty") {
		t.Fatalf("FormatActor error = %v, want invalid existing SPIFFE", err)
	}
}

func TestNewReplayCacheUsesDefaults(t *testing.T) {
	t.Parallel()
	c := NewReplayCache(0, 0)
	if c == nil || c.window != 5*time.Minute || c.max != 10000 {
		t.Fatalf("defaults = %+v", c)
	}
	if err := c.CheckAndStore("n1", time.Time{}); err != nil {
		t.Fatalf("CheckAndStore: %v", err)
	}
	if err := c.CheckAndStore("n1", time.Time{}); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("second store error = %v, want replay", err)
	}
}
