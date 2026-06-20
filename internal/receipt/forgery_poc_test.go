// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

// TestVerifyRejectsUntrustedAttackerKey is the regression for the fleet-report
// receipt self-trust vulnerability. A receipt can be internally self-consistent
// while still being signed by an attacker-controlled key. Production callers
// must verify against an enrolled/configured public key with VerifyWithKey.
func TestVerifyRejectsUntrustedAttackerKey(t *testing.T) {
	// An attacker keypair that is NOT enrolled / NOT in any trusted key set.
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	enrolledPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen enrolled key: %v", err)
	}

	// Forge a receipt over a well-formed action record, signed by the attacker.
	forged, err := Sign(validActionRecord(), attackerPriv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := Verify(forged); err == nil {
		t.Fatal("Verify() accepted a receipt without an external trust anchor")
	}
	if err := VerifyInternalConsistencyOnly(forged); err != nil {
		t.Fatalf("internal consistency check should still distinguish malformed receipts from untrusted receipts: %v", err)
	}
	if err := VerifyWithKey(forged, hexPublicKeyForTest(enrolledPub)); err == nil {
		t.Fatal("VerifyWithKey accepted a receipt signed by a key other than the enrolled key")
	}
}

func hexPublicKeyForTest(pub ed25519.PublicKey) string {
	return fmt.Sprintf("%x", []byte(pub))
}
