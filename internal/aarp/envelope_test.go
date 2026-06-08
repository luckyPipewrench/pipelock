// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	env, opts := signedEnvelope(t)

	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("AssertionSigned = false, want true")
	}
	if !contains(ap.VerifiedClaims, ClaimReceiptSignatureValid) {
		t.Errorf("missing %s in %v", ClaimReceiptSignatureValid, ap.VerifiedClaims)
	}
	if !contains(ap.VerifiedClaims, ClaimMediatorKeyPinned) {
		t.Errorf("missing %s in %v", ClaimMediatorKeyPinned, ap.VerifiedClaims)
	}
	// complete-mediation is always claim-only and must never be verified.
	if contains(ap.VerifiedClaims, "complete_mediation") || contains(ap.VerifiedClaims, "complete-mediation") {
		t.Error("complete_mediation must never be verified")
	}
	if !contains(ap.ClaimedUnverified, "complete-mediation") {
		t.Errorf("complete-mediation should be claimed-unverified, got %v", ap.ClaimedUnverified)
	}
	// does_not_assert must be present and never empty.
	for _, want := range []string{"complete_mediation", "absence_of_bypass", "action_safety"} {
		if !contains(ap.DoesNotAssert, want) {
			t.Errorf("does_not_assert missing %q", want)
		}
	}
	// The result must never carry a "trusted"/"safe" notion: the struct has no
	// such field by construction. Sanity-check the JSON has no such key.
	raw, _ := json.Marshal(ap)
	for _, banned := range []string{`"trusted"`, `"safe"`} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("appraisal JSON contains banned key %s", banned)
		}
	}
}

func TestVerify_MarshalRoundTripThenVerify(t *testing.T) {
	env, opts := signedEnvelope(t)
	data, err := Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	ap, err := Verify(got, opts)
	if err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("AssertionSigned = false after marshal round-trip")
	}
}

func TestVerify_TamperedPayloadFails(t *testing.T) {
	env, opts := signedEnvelope(t)
	// Mutate the assertion AFTER signing: the signature covers the payload
	// digest, so verification must fail.
	env.Assertion.MediatorID = "attacker"
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify returned error (want appraisal with failed sig): %v", err)
	}
	if ap.AssertionSigned {
		t.Fatal("AssertionSigned = true after payload tamper")
	}
	if ap.Signatures[0].Status != SigFailed {
		t.Errorf("signature status = %q, want %q", ap.Signatures[0].Status, SigFailed)
	}
}

func TestVerify_UntrustedKey(t *testing.T) {
	env, _ := signedEnvelope(t)
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.AssertionSigned {
		t.Fatal("AssertionSigned = true with empty trust set")
	}
	if ap.Signatures[0].Status != SigUnknownKey {
		t.Errorf("status = %q, want %q", ap.Signatures[0].Status, SigUnknownKey)
	}
	// With no verified signature, even a claim like mediated is unverified.
	if contains(ap.VerifiedClaims, ClaimMediatorKeyPinned) {
		t.Error("mediator_key_pinned verified without a verified signature")
	}
}

func TestVerify_WrongKeyForKeyID(t *testing.T) {
	env, _ := signedEnvelope(t)
	otherPub, _ := genKey(t)
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: otherPub}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.Signatures[0].Status != SigFailed {
		t.Errorf("status = %q, want %q", ap.Signatures[0].Status, SigFailed)
	}
}

func TestVerify_MediatorPinnedRequiresMatchingTrustEntry(t *testing.T) {
	env, pub := signedEnvelopeWithKey(t)
	// Trusted key but NO trust entry → signature verifies but mediated is not pinned.
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("AssertionSigned = false with trusted key")
	}
	if contains(ap.VerifiedClaims, ClaimMediatorKeyPinned) {
		t.Error("mediator_key_pinned verified without a trust entry")
	}
	if !contains(ap.ClaimedUnverified, "mediated") {
		t.Errorf("mediated should be claimed-unverified, got %v", ap.ClaimedUnverified)
	}
}

func TestVerify_MediatorIDMismatchRejectsPin(t *testing.T) {
	env, pub := signedEnvelopeWithKey(t)
	opts := VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub},
		// Trust entry names a DIFFERENT mediator than the assertion.
		Trust: map[string]TrustEntry{testKeyID: {MediatorID: "other-mediator"}},
	}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if contains(ap.VerifiedClaims, ClaimMediatorKeyPinned) {
		t.Error("mediator_key_pinned verified despite mediator_id mismatch")
	}
}

func TestSign_RejectsNoSigners(t *testing.T) {
	if _, err := Sign(baseEnvelope()); !errors.Is(err, ErrSchema) {
		t.Fatalf("Sign with no signers = %v, want ErrSchema", err)
	}
}

func TestSign_RejectsDuplicateKeyID(t *testing.T) {
	_, priv := genKey(t)
	s1, err := NewEd25519Signer(testKeyID, "mediator", priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer s1: %v", err)
	}
	s2, err := NewEd25519Signer(testKeyID, "issuer", priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer s2: %v", err)
	}
	if _, err := Sign(baseEnvelope(), s1, s2); !errors.Is(err, ErrSchema) {
		t.Fatalf("Sign with duplicate key_id = %v, want ErrSchema", err)
	}
}

func TestSign_RejectsInvalidPayload(t *testing.T) {
	_, priv := genKey(t)
	signer, err := NewEd25519Signer(testKeyID, "mediator", priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	bad := baseEnvelope()
	bad.Subject.ActionRecordSHA256 = "not-a-digest"
	if _, err := Sign(bad, signer); !errors.Is(err, ErrSchema) {
		t.Fatalf("Sign with invalid subject = %v, want ErrSchema", err)
	}
}
