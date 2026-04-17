// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dunglas/httpsfv"
)

func TestInjectHTTP(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     "write",
		Verdict:    "allow",
		SideEffect: "external_write",
		Actor:      "agent:test",
		ActorAuth:  ActorAuthBound,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		ReceiptID:  "01961f3a-7b2c-7000-8000-000000000001",
		Timestamp:  1712345678,
	}

	h := http.Header{}
	if err := InjectHTTP(h, env); err != nil {
		t.Fatalf("InjectHTTP() error: %v", err)
	}

	got := h.Get(HeaderName)
	if got == "" {
		t.Fatal("InjectHTTP() did not set header")
	}

	parsed, err := Parse(got)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if parsed.Action != env.Action {
		t.Errorf("Action = %q, want %q", parsed.Action, env.Action)
	}
	if parsed.ReceiptID != env.ReceiptID {
		t.Errorf("ReceiptID = %q, want %q", parsed.ReceiptID, env.ReceiptID)
	}
}

func TestStripInbound(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	// Byte-sequence items in Signature / Signature-Input must carry
	// valid base64 between the ":" delimiters, otherwise the RFC 8941
	// dict parse in StripInbound rejects the whole header value. The
	// literal bytes here are not verifiable signatures — they are just
	// placeholder payloads that parse cleanly.
	h.Set(HeaderName, "v=1, act=\"write\", vd=\"allow\"")
	h.Set("Signature-Input", "pipelock1=(\"@method\");tag=\"pipelock-mediation\"")
	h.Set("Signature", "pipelock1=:cGlwZWxvY2stZmFrZQ==:")
	h.Add("Signature-Input", "sig1=(\"@method\");tag=\"web-bot-auth\"")
	h.Add("Signature", "sig1=:dXBzdHJlYW0tcmVhbA==:")

	StripInbound(h)

	if got := h.Get(HeaderName); got != "" {
		t.Errorf("StripInbound() did not remove %s: %q", HeaderName, got)
	}

	// Non-pipelock signatures must be preserved. Check ALL values, not just first.
	for _, sigInput := range h.Values("Signature-Input") {
		if strings.Contains(sigInput, "pipelock") {
			t.Errorf("StripInbound() left pipelock member in Signature-Input: %q", sigInput)
		}
	}
	if len(h.Values("Signature-Input")) == 0 {
		t.Error("StripInbound() removed non-pipelock Signature-Input")
	}

	for _, sig := range h.Values("Signature") {
		if strings.Contains(sig, "pipelock") {
			t.Errorf("StripInbound() left pipelock member in Signature: %q", sig)
		}
	}
	if len(h.Values("Signature")) == 0 {
		t.Error("StripInbound() removed non-pipelock Signature")
	}
}

func TestStripInbound_NoHeaders(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	StripInbound(h) // Must not panic.
}

// TestStripInbound_PipelockMemberWithQuotedComma is the regression test
// for the strings.Split comma bug in stripPipelockSignatureMembers. An
// attacker-controlled inbound request can carry a pipelock* dictionary
// member whose quoted parameter value contains a literal comma — RFC 8941
// permits this. strings.Split(val, ",") treats that comma as a top-level
// member separator, producing a post-comma fragment (e.g. `b"`) that no
// longer has the "pipelock" prefix. The buggy loop preserves the fragment
// because HasPrefix(trimmed, "pipelock") is false, leaving broken noise
// in the outbound Signature-Input. That both corrupts any surviving sig1
// member and creates a downstream dictionary-parse failure — either of
// which is a bypass vector for inbound sanitisation.
func TestStripInbound_PipelockMemberWithQuotedComma(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Add("Signature-Input", `pipelock1=("@method");tag="a,b", sig1=("@method");tag="web-bot-auth"`)
	h.Add("Signature", `pipelock1=:cGlwZQ==:, sig1=:c2ln:`)

	StripInbound(h)

	// No output value may contain any lingering "pipelock" residue. The
	// buggy path leaves a stray fragment like `b"` that still *parses*
	// as a member but whose name is a broken quoted string.
	for _, v := range h.Values("Signature-Input") {
		if strings.Contains(v, "pipelock") {
			t.Errorf("Signature-Input still references pipelock after strip: %q", v)
		}
	}

	// The stripped header must parse cleanly as an RFC 8941 dictionary.
	// The buggy strip yields `b", sig1=...` which fails dict parse.
	dict, err := httpsfv.UnmarshalDictionary(h.Values("Signature-Input"))
	if err != nil {
		t.Fatalf("Signature-Input no longer parses as dictionary after strip: %v\nvalues=%q",
			err, h.Values("Signature-Input"))
	}

	// Only sig1 should remain. No pipelock* and no fragment keys.
	names := dict.Names()
	if len(names) != 1 || names[0] != "sig1" {
		t.Errorf("Signature-Input members = %v, want [sig1]", names)
	}

	// And the sig1 inner list's tag must still be "web-bot-auth" — the
	// buggy path can truncate or drop it when dropping the pipelock1
	// fragment ahead of it.
	member, ok := dict.Get("sig1")
	if !ok {
		t.Fatal("sig1 member missing after strip")
	}
	inner, ok := member.(httpsfv.InnerList)
	if !ok {
		t.Fatalf("sig1 is %T, want httpsfv.InnerList", member)
	}
	tagVal, ok := inner.Params.Get("tag")
	if !ok {
		t.Fatal("sig1 lost its tag parameter after strip")
	}
	if tagStr, _ := tagVal.(string); tagStr != "web-bot-auth" {
		t.Errorf("sig1 tag = %q, want %q", tagStr, "web-bot-auth")
	}

	// The Signature companion header must also round-trip cleanly.
	sigDict, err := httpsfv.UnmarshalDictionary(h.Values("Signature"))
	if err != nil {
		t.Fatalf("Signature no longer parses as dictionary after strip: %v\nvalues=%q",
			err, h.Values("Signature"))
	}
	if _, ok := sigDict.Get("sig1"); !ok {
		t.Fatal("sig1 missing from Signature after strip")
	}
	if _, ok := sigDict.Get("pipelock1"); ok {
		t.Error("pipelock1 survived strip in Signature")
	}
}

// TestStripInbound_MultiLineDict exercises the multi-header-value form of
// a Structured-Fields dictionary. httpsfv.UnmarshalDictionary accepts a
// []string and must merge them. The old comma-split path processed each
// value in isolation, so a member split across lines could survive.
func TestStripInbound_MultiLineDict(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	// Two separate header lines, one with pipelock1 and one with sig1.
	h.Add("Signature-Input", `pipelock1=("@method");tag="pipelock-mediation"`)
	h.Add("Signature-Input", `sig1=("@method");tag="web-bot-auth"`)
	h.Add("Signature", `pipelock1=:cGlwZQ==:`)
	h.Add("Signature", `sig1=:YWJj:`)

	StripInbound(h)

	for _, v := range h.Values("Signature-Input") {
		if strings.Contains(v, "pipelock") {
			t.Errorf("Signature-Input still contains pipelock across multi-line: %q", v)
		}
	}
	if len(h.Values("Signature-Input")) == 0 {
		t.Error("StripInbound removed the surviving sig1 Signature-Input")
	}
	for _, v := range h.Values("Signature") {
		if strings.Contains(v, "pipelock") {
			t.Errorf("Signature still contains pipelock across multi-line: %q", v)
		}
	}
	if len(h.Values("Signature")) == 0 {
		t.Error("StripInbound removed the surviving sig1 Signature")
	}
}

// TestStripInbound_MalformedNonPipelockHeaderSurvives is the regression
// test for the pre-tag gate-found bug where the entire Signature header was
// deleted whenever httpsfv parsing failed, even when no pipelock member
// was present. Cloudflare Web Bot Auth sig1 values with non-strict-base64
// or otherwise parse-fragile members were silently dropped — turning
// pipelock into a signature-stripping middlebox for unrelated auth
// schemes.
//
// The surgical fail-closed behaviour: drop only when the raw header
// bytes contain the pipelock member prefix. Otherwise preserve the
// header so downstream verifiers still see the upstream signature.
func TestStripInbound_MalformedNonPipelockHeaderSurvives(t *testing.T) {
	t.Parallel()

	// "legit" is not valid base64 → httpsfv.UnmarshalDictionary returns
	// an error. Under the old fail-closed path, pipelock would delete the
	// whole header. No pipelock member is present, so the new behaviour
	// must preserve the bytes unchanged.
	h := http.Header{}
	h.Set("Signature", `sig1=:legit:`)
	h.Set("Signature-Input", `sig1=("@method");created=1776380100;keyid="bot";tag="web-bot-auth"`)

	StripInbound(h)

	if got := h.Get("Signature"); got != `sig1=:legit:` {
		t.Errorf("Signature mutated on non-pipelock malformed input: got %q, want sig1=:legit:", got)
	}
	if got := h.Get("Signature-Input"); !strings.Contains(got, "sig1") {
		t.Errorf("Signature-Input lost sig1 member: got %q", got)
	}
}

// TestStripInbound_MalformedPipelockHeaderDropped confirms the fail-closed
// branch still fires when pipelock IS implicated in an unparseable header.
// An attacker who sends malformed pipelock bytes should still see the
// header removed, because any surviving representation could confuse a
// downstream verifier.
func TestStripInbound_MalformedPipelockHeaderDropped(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("Signature", `pipelock1=:!!!notbase64!!!:, sig1=:dGVzdA==:`)

	StripInbound(h)

	got := h.Get("Signature")
	if strings.Contains(strings.ToLower(got), "pipelock") {
		t.Errorf("pipelock survived malformed-input strip: got %q", got)
	}
}

// TestStripInbound_MalformedPipelockFormattingVariants exercises the
// variations that the previous HasPrefix / "," / ", " heuristic missed:
// tabs, other OWS between comma and pipelock member, uppercase PIPELOCK,
// and pipelock appearing after a malformed leading fragment. All must
// trigger fail-closed drop because the raw bytes mention the pipelock
// namespace and the dictionary parse already failed.
func TestStripInbound_MalformedPipelockFormattingVariants(t *testing.T) {
	t.Parallel()

	cases := []string{
		"sig1=:bad:,\tpipelock1=:x:",       // tab OWS between comma and member
		"sig1=:bad:,\n\tpipelock1=:x:",     // line folding + tab
		"sig1=:bad:,   pipelock1=:x:",      // multiple spaces
		"PIPELOCK1=:x:, sig1=:dGVzdA==:",   // uppercase
		"Pipelock1=:x:, sig1=:dGVzdA==:",   // title case
		"garbage not-a-dict pipelock1=:x:", // wholly malformed, pipelock mid-value
	}
	for _, raw := range cases {
		h := http.Header{}
		h.Set("Signature", raw)
		StripInbound(h)
		if got := h.Get("Signature"); strings.Contains(strings.ToLower(got), "pipelock") {
			t.Errorf("pipelock survived strip of %q: got %q", raw, got)
		}
	}
}

func TestInjectMCP(t *testing.T) {
	t.Parallel()

	env := Envelope{
		Version:    1,
		Action:     "read",
		Verdict:    "allow",
		SideEffect: "external_read",
		Actor:      "agent:test",
		ActorAuth:  ActorAuthSelfDeclared,
		PolicyHash: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		ReceiptID:  "01961f3a-7b2c-7000-8000-000000000002",
		Timestamp:  1712345679,
	}

	meta := make(map[string]any)
	InjectMCP(meta, env)

	mediation, ok := meta[MCPMetaKey]
	if !ok {
		t.Fatalf("InjectMCP() did not set %s key", MCPMetaKey)
	}
	m, ok := mediation.(map[string]any)
	if !ok {
		t.Fatalf("value is %T, want map[string]any", mediation)
	}
	if m["act"] != "read" {
		t.Errorf("act = %v, want %q", m["act"], "read")
	}
}

func TestStripInboundMCP(t *testing.T) {
	t.Parallel()

	meta := map[string]any{
		MCPMetaKey:                map[string]any{"act": "fake"},
		"com.pipelock/provenance": map[string]any{"real": "data"},
	}

	StripInboundMCP(meta)

	if _, ok := meta[MCPMetaKey]; ok {
		t.Error("StripInboundMCP() did not remove mediation key")
	}
	if _, ok := meta["com.pipelock/provenance"]; !ok {
		t.Error("StripInboundMCP() removed provenance key")
	}
}
