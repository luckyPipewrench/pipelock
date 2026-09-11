// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestHashAgentCard_FramesFieldsUnambiguously proves the structural digest
// cannot be collided by moving a NUL byte across a field boundary. Agent Card
// fields are attacker-controlled JSON strings and JSON permits NUL (\x00), so
// a NUL-delimited encoding would hash ("a<NUL>b", "") and ("a", "b<NUL>")
// identically. cardStructuralDigest decides whether an endpoint CHANGED, so a
// collision there downgrades a blocking structural change into an adopted
// descriptive one.
func TestHashAgentCard_FramesFieldsUnambiguously(t *testing.T) {
	const nul = "\x00"
	base := A2AAgentCard{URL: "https://agent.vendor.example/a2a"}

	shifted := func(a, b string) A2AAgentCard {
		card := base
		card.SupportedInterfaces = []A2AInterface{{URL: a, ProtocolBinding: b}}
		return card
	}
	left := shifted("https://a.example"+nul+"https://b.example", "")
	right := shifted("https://a.example", nul+"https://b.example")

	if got := HashAgentCard(left); got == HashAgentCard(right) {
		t.Fatalf("distinct interface values collided: both hashed to %s", got)
	}
	if got := cardStructuralDigest(left); got == cardStructuralDigest(right) {
		t.Fatalf("distinct interfaces collided in the structural digest: both %s", got)
	}

	// Determinism is preserved: the same card still hashes to the same value.
	again := shifted("https://a.example"+nul+"https://b.example", "")
	if got, want := HashAgentCard(left), HashAgentCard(again); got != want {
		t.Fatalf("hash is not deterministic: %s vs %s", got, want)
	}
}

// TestScanAgentCard_RejectedCardDoesNotLearnBaseline proves the baseline is
// written only after the FULL verdict is clean. A card that fails signature
// verification is rejected, so it must not leave its descriptive text behind as
// the trusted baseline, and must not report an adoption that the audit event
// and the OnCardDriftAdopted callback would both act on.
func TestScanAgentCard_RejectedCardDoesNotLearnBaseline(t *testing.T) {
	// A trusted key must be configured for signature verification to run at
	// all; require_signed_agent_cards then rejects an unsigned card.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := &config.A2AScanning{
		Enabled:                 true,
		Action:                  config.ActionBlock,
		DetectCardDrift:         true,
		RequireSignedAgentCards: true,
		TrustedAgentCardKeys: []config.A2ATrustedCardKey{
			{KeyID: "k1", PublicKey: signing.EncodePublicKey(pub), AllowedOrigins: []string{"https://agent.vendor.example"}},
		},
	}
	key := CardCacheKeyFromRequest("https://agent.vendor.example/.well-known/agent-card.json", "")
	baseline := NewCardBaseline(4)

	const card = `{"name":"Vendor Agent","description":"Searches vendor documentation.","url":"https://agent.vendor.example/a2a"}`

	// First fetch: unsigned under require_signed_agent_cards, so it is
	// rejected. A rejected card must not be learned as the first-seen baseline.
	first := ScanAgentCard(context.Background(), []byte(card), nil, baseline, key, cfg)
	if first.Clean {
		t.Fatalf("unsigned card under require_signed_agent_cards must be rejected: %+v", first)
	}
	if first.FirstSeen {
		t.Fatalf("a rejected card reported FirstSeen, so callers would treat it as learned: %+v", first)
	}
	if _, learned := baseline.entries[key]; learned {
		t.Fatal("a rejected card was written into the trusted baseline")
	}

	// Seed a trusted baseline the way an accepted card would, then feed a
	// rejected card whose description differs but introduces no cue class.
	trusted := A2AAgentCard{
		Name:        "Vendor Agent",
		Description: "Searches vendor documentation.",
		URL:         "https://agent.vendor.example/a2a",
	}
	baseline.Commit(key, cardStructuralDigest(trusted), cardDescriptiveText(trusted), nil)
	before := baseline.entries[key].descriptive

	const changed = `{"name":"Vendor Agent","description":"Searches vendor documentation and returns passages.","url":"https://agent.vendor.example/a2a"}`
	out := ScanAgentCard(context.Background(), []byte(changed), nil, baseline, key, cfg)
	if out.Clean {
		t.Fatalf("unsigned changed card must still be rejected: %+v", out)
	}
	if out.DriftAdopted {
		t.Fatalf("a rejected card reported DriftAdopted; the audit event and callback would claim an adoption that never happened: %+v", out)
	}
	if got := baseline.entries[key].descriptive; got != before {
		t.Fatalf("a rejected card replaced the trusted baseline: %q -> %q", before, got)
	}
}
