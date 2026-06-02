// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

const (
	testMediatorID  = "pipelock-prod-1"
	testTrustDomain = "example.org"
	testIssuedAt    = "2026-06-01T00:00:00Z"
	testKeyID       = "mediator-key-1"
)

// digest64 returns a deterministic 64-hex string from a single seed byte, for
// subject fields where the exact value is irrelevant to the test.
func digest64(seed byte) string {
	return strings.Repeat(string("0123456789abcdef"[seed%16]), 64)
}

// genKey returns a fresh Ed25519 keypair.
func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// baseEnvelope returns a structurally valid, unsigned envelope.
func baseEnvelope() Envelope {
	return Envelope{
		Profile: Profile,
		Subject: Subject{
			ActionRecordSHA256:    digest64(1),
			ReceiptEnvelopeSHA256: digest64(2),
			ReceiptSignerKey:      digest64(3),
			ReceiptType:           ReceiptTypeActionV1,
		},
		Assertion: Assertion{
			Claimed:           []string{"mediated", "complete-mediation"},
			MediatorID:        testMediatorID,
			TrustDomain:       testTrustDomain,
			CompleteMediation: true,
			IssuedAt:          testIssuedAt,
		},
	}
}

// signedEnvelopeWithKey signs a base envelope with one Ed25519 mediator key and
// returns the envelope plus that key's public half so tests can build their own
// verify options.
func signedEnvelopeWithKey(t *testing.T) (Envelope, ed25519.PublicKey) {
	t.Helper()
	pub, priv := genKey(t)
	signer, err := NewEd25519Signer(testKeyID, "mediator", priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	env, err := Sign(baseEnvelope(), signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return env, pub
}

// signedEnvelope returns a base envelope signed by one Ed25519 mediator key,
// plus verify options trusting that key with a matching mediator trust entry.
func signedEnvelope(t *testing.T) (Envelope, VerifyOptions) {
	t.Helper()
	env, pub := signedEnvelopeWithKey(t)
	opts := VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub},
		Trust: map[string]TrustEntry{
			testKeyID: {MediatorID: testMediatorID, Role: "mediator", TrustDomain: testTrustDomain},
		},
	}
	return env, opts
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
