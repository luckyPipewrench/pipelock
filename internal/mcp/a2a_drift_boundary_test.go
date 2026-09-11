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
	baseline.Commit(key, cardStructuralDigest(trusted), cardDescriptiveDigest(trusted), cardDescriptiveText(trusted), nil)
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

// TestCardDescriptiveDigest_FramesFieldBoundaries proves the descriptive
// IDENTITY cannot be collided by moving a delimiter across a field boundary.
// cardDescriptiveText joins attacker-controlled fields with newlines, so
// {Name: "A\nB", Description: ""} and {Name: "A", Description: "B\n"} flatten
// identically. A baseline comparing that text reports "no drift" for a card
// whose fields changed, recording no adoption and no audit event.
func TestCardDescriptiveDigest_FramesFieldBoundaries(t *testing.T) {
	left := A2AAgentCard{Name: "A\nB", Description: "", URL: "https://agent.vendor.example/a2a"}
	right := A2AAgentCard{Name: "A", Description: "B\n", URL: "https://agent.vendor.example/a2a"}

	// Calibration: the ambiguity is real in the flattened text.
	if cardDescriptiveText(left) != cardDescriptiveText(right) {
		t.Fatal("flattened text is no longer ambiguous; this test's premise needs rechecking")
	}
	if got := cardDescriptiveDigest(left); got == cardDescriptiveDigest(right) {
		t.Fatalf("distinct descriptive fields collided in the identity digest: both %s", got)
	}

	// Seed through Evaluate+Commit, the path ScanAgentCard uses, so the stored
	// entry carries the canonical digest. Seeding through an API that derived
	// its own digest would make this test pass on the MISMATCH between two
	// derivations rather than on the field-boundary case it claims to cover.
	baseline := NewCardBaseline(4)
	key := CardCacheKeyFromRequest("https://agent.vendor.example/.well-known/agent-card.json", "")
	structural := cardStructuralDigest(left)
	if out := baseline.Evaluate(key, structural, cardDescriptiveDigest(left), cardDescriptiveText(left), nil); !out.firstSeen {
		t.Fatalf("seed outcome = %+v, want first-seen", out)
	}
	if !baseline.Commit(key, structural, cardDescriptiveDigest(left), cardDescriptiveText(left), nil) {
		t.Fatal("seed commit did not apply")
	}
	// Control: the SAME card must now report no drift. If this fires, the
	// seeded digest and the evaluated digest disagree and every assertion below
	// would be meaningless.
	if out := baseline.Evaluate(key, structural, cardDescriptiveDigest(left), cardDescriptiveText(left), nil); out.changed {
		t.Fatalf("the same card reported drift against its own baseline: %+v", out)
	}
	if out := baseline.Evaluate(key, structural, cardDescriptiveDigest(right), cardDescriptiveText(right), nil); !out.changed {
		t.Fatalf("a card with different descriptive fields reported no drift: %+v", out)
	}
}

// TestHashAgentCard_FramesCollectionBoundaries proves two structurally
// different cards cannot collide because their collections happen to emit the
// same empty frames. Four empty skills and five empty interfaces both contribute
// only empty fields; without a collection tag and item count the digest matches
// and cardStructuralDigest reports "no structural change" for a card that gained
// or moved a capability surface.
func TestHashAgentCard_FramesCollectionBoundaries(t *testing.T) {
	skills := A2AAgentCard{URL: "https://agent.vendor.example/a2a", Skills: make([]A2ASkill, 4)}
	ifaces := A2AAgentCard{URL: "https://agent.vendor.example/a2a", SupportedInterfaces: make([]A2AInterface, 5)}
	if got := HashAgentCard(skills); got == HashAgentCard(ifaces) {
		t.Fatalf("four empty skills collided with five empty interfaces: both %s", got)
	}
	if got := cardStructuralDigest(skills); got == cardStructuralDigest(ifaces) {
		t.Fatalf("collections collided in the structural digest: both %s", got)
	}

	// Item count alone must move the digest.
	four := A2AAgentCard{URL: "https://agent.vendor.example/a2a", Skills: make([]A2ASkill, 4)}
	five := A2AAgentCard{URL: "https://agent.vendor.example/a2a", Skills: make([]A2ASkill, 5)}
	if got := HashAgentCard(four); got == HashAgentCard(five) {
		t.Fatalf("adding an empty skill did not move the digest: both %s", got)
	}
}

// TestApplyFreshDriftOutcome_CapacityForcesBlock covers the race path: Commit
// declined because the baseline moved, and the re-evaluation came back with the
// baseline full. The card could not be verified against any baseline, so the
// verdict must be BLOCK even when the operator configured warn. A fall-back to
// cfg.Action here is a fail-open that only shows up under the race, which is
// exactly the kind of branch that never gets exercised in production testing.
func TestApplyFreshDriftOutcome_CapacityForcesBlock(t *testing.T) {
	cfg := &config.A2AScanning{Enabled: true, Action: config.ActionWarn, DetectCardDrift: true}

	result := AgentCardScanResult{Clean: true}
	applyFreshDriftOutcome(&result, cardDriftOutcome{capacityExceeded: true}, cfg)

	if result.Clean {
		t.Fatal("a card that could not be verified against any baseline was reported clean")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("action = %q, want %q; a configured warn must not forward an unverifiable card", result.Action, config.ActionBlock)
	}
	if !result.BaselineCapacityExceeded {
		t.Fatal("BaselineCapacityExceeded was not set, so callers cannot tell why it blocked")
	}

	// Control: an ordinary structural block still honours the configured
	// action, so the override above is scoped to capacity and is not a blanket
	// "always block" that would make the assertion meaningless.
	structural := AgentCardScanResult{Clean: true}
	applyFreshDriftOutcome(&structural, cardDriftOutcome{changed: true, block: true, structuralChange: true}, cfg)
	if structural.Action != config.ActionWarn {
		t.Fatalf("structural drift action = %q, want the configured %q", structural.Action, config.ActionWarn)
	}

	// A clean re-evaluation must not invent a block.
	ok := AgentCardScanResult{Clean: true}
	applyFreshDriftOutcome(&ok, cardDriftOutcome{}, cfg)
	if !ok.Clean || ok.Action != "" {
		t.Fatalf("a clean re-evaluation produced %+v, want clean with no action", ok)
	}
}
