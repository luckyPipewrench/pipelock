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

const testCardURL = "https://agent.example.com/.well-known/agent-card.json"

// sigScanCfg builds an A2AScanning config that isolates signature verification:
// content scanning and drift are off so only the signature outcome moves Clean.
func sigScanCfg(pub ed25519.PublicKey, require bool) *config.A2AScanning {
	cfg := &config.A2AScanning{
		Enabled:                 true,
		Action:                  config.ActionBlock,
		ScanAgentCards:          false,
		DetectCardDrift:         false,
		RequireSignedAgentCards: require,
	}
	if pub != nil {
		cfg.TrustedAgentCardKeys = []config.A2ATrustedCardKey{
			{KeyID: testKeyID, PublicKey: signing.EncodePublicKey(pub), AllowedOrigins: []string{testCardOrigin}},
		}
	}
	return cfg
}

func TestScanAgentCard_ValidSignatureVerified(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	key := CardCacheKeyFromRequest(testCardURL, "")
	res := ScanAgentCard(context.Background(), card, testA2AScanner(t), nil, key, sigScanCfg(pub, false))
	if !res.Clean {
		t.Fatalf("valid signature should keep card clean, got reason %q", res.Reason)
	}
	if !res.SignatureVerified || res.SignatureKeyID != testKeyID {
		t.Fatalf("expected SignatureVerified with key %q, got %v/%q", testKeyID, res.SignatureVerified, res.SignatureKeyID)
	}
}

func TestScanAgentCard_ForgedSignatureBlocks(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	card = replaceSig(t, card, b64u(make([]byte, ed25519.SignatureSize)))
	key := CardCacheKeyFromRequest(testCardURL, "")
	res := ScanAgentCard(context.Background(), card, testA2AScanner(t), nil, key, sigScanCfg(pub, false))
	if res.Clean {
		t.Fatal("forged signature must make the card not clean")
	}
	if res.Action != config.ActionBlock {
		t.Fatalf("expected block action, got %q", res.Action)
	}
}

func TestScanAgentCard_UnsignedRequiredBlocks(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"name":"Vendor Agent","description":"does things"}`)
	key := CardCacheKeyFromRequest(testCardURL, "")
	res := ScanAgentCard(context.Background(), body, testA2AScanner(t), nil, key, sigScanCfg(pub, true))
	if res.Clean {
		t.Fatal("unsigned card must be blocked when require_signed_agent_cards is set")
	}
}

// TestScanAgentCard_UnparseableRequiredBlocks proves the unparseable-card early
// return still enforces require_signed_agent_cards (regression for the fail-open
// gap an independent review found: a malformed body must not skip the signature
// requirement).
func TestScanAgentCard_UnparseableRequiredBlocks(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"name":"x" TRAILING GARBAGE`) // fails struct unmarshal
	key := CardCacheKeyFromRequest(testCardURL, "")
	res := ScanAgentCard(context.Background(), body, testA2AScanner(t), nil, key, sigScanCfg(pub, true))
	if res.Clean {
		t.Fatal("unparseable card must be blocked when require_signed_agent_cards is set")
	}
}

func TestScanAgentCard_UnsignedNotRequiredClean(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"name":"Vendor Agent","description":"does things"}`)
	key := CardCacheKeyFromRequest(testCardURL, "")
	res := ScanAgentCard(context.Background(), body, testA2AScanner(t), nil, key, sigScanCfg(pub, false))
	if !res.Clean {
		t.Fatalf("unsigned card must be clean when require_signed is off, got %q", res.Reason)
	}
	if res.SignatureVerified {
		t.Fatal("unsigned card must not report SignatureVerified")
	}
}

func TestScanAgentCard_NoTrustedKeysSkipsVerification(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	key := CardCacheKeyFromRequest(testCardURL, "")
	// No trusted keys -> verification inactive -> signed card not verified, not blocked.
	res := ScanAgentCard(context.Background(), card, testA2AScanner(t), nil, key, sigScanCfg(nil, false))
	if !res.Clean {
		t.Fatalf("with no trusted keys, a signed card must not be blocked, got %q", res.Reason)
	}
	if res.SignatureVerified {
		t.Fatal("verification should not run without trusted keys")
	}
}
