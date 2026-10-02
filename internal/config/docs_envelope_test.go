// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// The guide's HTTP and MCP examples describe the same illustrative decision.
// Compare their actual fenced bytes with the production serializers so copied
// examples retain the policy fingerprint width and agree across transports.
func checkGuideEnvelopeExamples(t *testing.T) {
	t.Helper()
	body := readDocAccuracyFile(t, repoRootForDocsAccuracy(t), "docs/guides/mediation-envelope.md")
	want := envelope.Envelope{
		Version:    1,
		Action:     "read",
		Verdict:    "allow",
		SideEffect: "external_read",
		Actor:      "agent-1",
		ActorAuth:  envelope.ActorAuthBound,
		PolicyHash: envelope.PolicyHashFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		ReceiptID:  "01961f3a-7b2c-7000-8000-000000000001",
		Timestamp:  1712764800,
	}

	t.Run("HTTP", func(t *testing.T) {
		snippet := envelopeDocFence(t, body, "HTTP header format", "")
		header, ok := strings.CutPrefix(snippet, envelope.HeaderName+": ")
		if !ok {
			t.Fatalf("example must begin with %s header", envelope.HeaderName)
		}
		header = strings.Join(strings.Fields(header), " ")
		got, err := envelope.Parse(header)
		if err != nil {
			t.Fatalf("parse documented header: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("documented envelope = %+v, want %+v", got, want)
		}
		serialized, err := want.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if header != serialized {
			t.Errorf("documented header = %s; serializer produces %s", header, serialized)
		}
	})

	t.Run("MCP", func(t *testing.T) {
		snippet := envelopeDocFence(t, body, "MCP meta format", "json")
		var got map[string]any
		if err := json.Unmarshal([]byte(snippet), &got); err != nil {
			t.Fatalf("parse documented MCP metadata: %v", err)
		}
		actual, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := json.Marshal(map[string]any{
			"_meta": map[string]any{envelope.MCPMetaKey: want.ToMCPMeta()},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, expected) {
			t.Errorf("documented MCP metadata = %s; serializer produces %s", actual, expected)
		}
	})
}

func envelopeDocFence(t *testing.T, body, heading, language string) string {
	t.Helper()
	_, section, ok := strings.Cut(body, "\n## "+heading+"\n")
	if !ok {
		t.Fatalf("missing documentation section %q", heading)
	}
	section, _, _ = strings.Cut(section, "\n## ")
	_, block, ok := strings.Cut(section, "\n```"+language+"\n")
	if !ok {
		t.Fatalf("missing %q code fence in %q", language, heading)
	}
	block, _, ok = strings.Cut(block, "\n```")
	if !ok {
		t.Fatalf("unclosed code fence in %q", heading)
	}
	return block
}
