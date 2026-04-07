// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"net/http"
	"strings"
	"testing"
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
	if parsed.Action != "write" {
		t.Errorf("Action = %q, want %q", parsed.Action, "write")
	}
	if parsed.ReceiptID != env.ReceiptID {
		t.Errorf("ReceiptID = %q, want %q", parsed.ReceiptID, env.ReceiptID)
	}
}

func TestStripInbound(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set(HeaderName, "act=\"write\", vd=\"allow\"")
	h.Set("Signature-Input", "pipelock1=(\"@method\");tag=\"pipelock-mediation\"")
	h.Set("Signature", "pipelock1=:fakesig:")
	h.Add("Signature-Input", "sig1=(\"@method\");tag=\"web-bot-auth\"")
	h.Add("Signature", "sig1=:realsig:")

	StripInbound(h)

	if got := h.Get(HeaderName); got != "" {
		t.Errorf("StripInbound() did not remove %s: %q", HeaderName, got)
	}

	// Non-pipelock signatures must be preserved.
	sigInput := h.Get("Signature-Input")
	if sigInput == "" {
		t.Error("StripInbound() removed non-pipelock Signature-Input")
	}
	if strings.Contains(sigInput, "pipelock") {
		t.Errorf("StripInbound() left pipelock member in Signature-Input: %q", sigInput)
	}

	sig := h.Get("Signature")
	if sig == "" {
		t.Error("StripInbound() removed non-pipelock Signature")
	}
	if strings.Contains(sig, "pipelock") {
		t.Errorf("StripInbound() left pipelock member in Signature: %q", sig)
	}
}

func TestStripInbound_NoHeaders(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	StripInbound(h) // Must not panic.
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
