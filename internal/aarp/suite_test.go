// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestMultiSig_TwoEd25519BothVerify(t *testing.T) {
	pubA, privA := genKey(t)
	pubB, privB := genKey(t)
	sA, _ := NewEd25519Signer("key-a", "mediator", privA)
	sB, _ := NewEd25519Signer("key-b", "issuer", privB)
	env, err := Sign(baseEnvelope(), sA, sB)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("got %d signatures, want 2", len(env.Signatures))
	}
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{"key-a": pubA, "key-b": pubB}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("AssertionSigned = false with two valid sigs")
	}
	for i, sr := range ap.Signatures {
		if sr.Status != SigVerified {
			t.Errorf("signature[%d] status = %q, want verified", i, sr.Status)
		}
	}
}

// TestMultiSig_PQStubSlotDoesNotBreakEd25519 proves the envelope shape is
// first-class for a second suite: a typed PQ signature can sit alongside an
// Ed25519 one. The PQ slot is reported unimplemented (never verified, never a
// fallback), and the Ed25519 signature still verifies.
func TestMultiSig_PQStubSlotDoesNotBreakEd25519(t *testing.T) {
	pub, priv := genKey(t)
	signer, _ := NewEd25519Signer("key-a", "mediator", priv)
	env, err := Sign(baseEnvelope(), signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Manually attach a typed PQ signature slot (its signer is unimplemented, so
	// it cannot be produced via Sign; an envelope may still carry one from a
	// future producer). It must not require a format bump or break verification.
	env.Signatures = append(env.Signatures, Signature{
		Protected: ProtectedHeader{
			Profile: Profile, Canon: CanonID,
			Alg: string(AlgMLDSA65), KeyType: "ml-dsa",
			KeyID: "pq-key-1", SignerRole: "mediator",
		},
		Sig: "ml-dsa-65:AAAA",
	})
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{"key-a": pub}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("AssertionSigned = false; PQ slot broke Ed25519 verification")
	}
	var sawUnimplemented bool
	for _, sr := range ap.Signatures {
		if sr.Alg == string(AlgMLDSA65) {
			sawUnimplemented = sr.Status == SigUnimplemented
		}
	}
	if !sawUnimplemented {
		t.Error("PQ signature not reported unimplemented")
	}
}

// TestPQOnly_FailsClosed proves an envelope with ONLY a recognized-but-
// unimplemented suite produces no verified signature (no fallback verify).
func TestPQOnly_FailsClosed(t *testing.T) {
	env := baseEnvelope()
	env.Signatures = []Signature{{
		Protected: ProtectedHeader{
			Profile: Profile, Canon: CanonID,
			Alg: string(AlgMLDSA65), KeyType: "ml-dsa",
			KeyID: "pq-key-1", SignerRole: "mediator",
		},
		Sig: "ml-dsa-65:AAAA",
	}}
	ap, err := Verify(env, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.AssertionSigned {
		t.Fatal("AssertionSigned = true for a PQ-only (unimplemented) envelope")
	}
	if ap.Signatures[0].Status != SigUnimplemented {
		t.Errorf("status = %q, want unimplemented", ap.Signatures[0].Status)
	}
}

// TestUnknownSuite_DoesNotPoisonValidSig proves a parallel signature under an
// unrecognized algorithm is reported unknown_suite but does not reject an
// envelope that also carries a verifiable Ed25519 signature.
func TestUnknownSuite_DoesNotPoisonValidSig(t *testing.T) {
	pub, priv := genKey(t)
	signer, _ := NewEd25519Signer("key-a", "mediator", priv)
	env, _ := Sign(baseEnvelope(), signer)
	env.Signatures = append(env.Signatures, Signature{
		Protected: ProtectedHeader{
			Profile: Profile, Canon: CanonID,
			Alg: "rsa-pkcs1", KeyType: "rsa",
			KeyID: "rsa-key", SignerRole: "mediator",
		},
		Sig: "rsa-pkcs1:AAAA",
	})
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{"key-a": pub}})
	if err != nil {
		t.Fatalf("Verify rejected envelope with one unknown suite: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("valid Ed25519 sig did not verify alongside unknown suite")
	}
	var sawUnknown bool
	for _, sr := range ap.Signatures {
		if sr.Alg == "rsa-pkcs1" {
			sawUnknown = sr.Status == SigUnknownSuite
		}
	}
	if !sawUnknown {
		t.Error("unknown suite not reported unknown_suite")
	}
}

// TestAlgSubstitution_Fails proves relabeling an Ed25519 signature as a
// different suite cannot make it verify: the alg label is in the signed bytes
// and the verifier dispatches on it before any verify attempt.
func TestAlgSubstitution_Fails(t *testing.T) {
	pub, priv := genKey(t)
	signer, _ := NewEd25519Signer("key-a", "mediator", priv)
	env, _ := Sign(baseEnvelope(), signer)
	// Relabel the alg to the PQ suite but keep the Ed25519 signature bytes and a
	// mismatched key_type. The verifier sees key_type != ml-dsa → malformed,
	// never a verify.
	env.Signatures[0].Protected.Alg = string(AlgMLDSA65)
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{"key-a": pub}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.AssertionSigned {
		t.Fatal("alg substitution produced a verified signature")
	}
}

// TestUnknownCriticalExtension_PerSignature: an unknown critical extension in a
// signature's protected header makes only that signature unverifiable, not the
// whole envelope (the signatures array is appendable, so it must not be fatal).
func TestUnknownCriticalExtension_PerSignature(t *testing.T) {
	env, opts := signedEnvelope(t)
	env.Signatures[0].Protected.Crit = []string{"x-attacker-ext"}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify returned envelope error (want per-signature status): %v", err)
	}
	if ap.AssertionSigned {
		t.Fatal("AssertionSigned = true despite the only signature having an unknown critical extension")
	}
	if ap.Signatures[0].Status != SigUnknownSuite {
		t.Fatalf("status = %q, want unknown_suite", ap.Signatures[0].Status)
	}
}

// TestEnvelopeLevelUnknownCriticalExtension_Rejects: an unknown ENVELOPE-level
// critical extension is in the signed payload (not appendable) and stays
// envelope-fatal.
func TestEnvelopeLevelUnknownCriticalExtension_Rejects(t *testing.T) {
	env, opts := signedEnvelope(t)
	env.CritExt = []string{"x-envelope-crit"}
	_, err := Verify(env, opts)
	if !errors.Is(err, ErrUnknownCriticalExtension) {
		t.Fatalf("Verify = %v, want ErrUnknownCriticalExtension", err)
	}
}

func TestProfileMismatch_PerSignature(t *testing.T) {
	env, opts := signedEnvelope(t)
	env.Signatures[0].Protected.Profile = "aarp/v9.9"
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify returned envelope error (want per-signature status): %v", err)
	}
	if ap.AssertionSigned || ap.Signatures[0].Status != SigUnknownSuite {
		t.Fatalf("profile mismatch: signed=%v status=%q, want signed=false status=unknown_suite", ap.AssertionSigned, ap.Signatures[0].Status)
	}
}

func TestCanonMismatch_PerSignature(t *testing.T) {
	env, opts := signedEnvelope(t)
	env.Signatures[0].Protected.Canon = "weird-canon"
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify returned envelope error (want per-signature status): %v", err)
	}
	if ap.AssertionSigned || ap.Signatures[0].Status != SigUnknownSuite {
		t.Fatalf("canon mismatch: signed=%v status=%q, want signed=false status=unknown_suite", ap.AssertionSigned, ap.Signatures[0].Status)
	}
}

// TestAppendedJunkSignature_DoesNotPoisonValidSig is the availability regression
// for the per-signature rule: a MITM can append a signature (the array is not
// signed), but a junk appended signature with a bogus protected suite must NOT
// deny an envelope that carries a verifiable signature.
func TestAppendedJunkSignature_DoesNotPoisonValidSig(t *testing.T) {
	env, opts := signedEnvelope(t) // one valid mediator signature
	env.Signatures = append(env.Signatures, Signature{
		Protected: ProtectedHeader{
			Profile: "aarp/v9.9", Canon: "weird-canon",
			Alg: string(AlgEd25519), KeyType: "ed25519",
			KeyID: "attacker", SignerRole: "mediator",
			Crit: []string{"x-attacker-ext"},
		},
		Sig: "ed25519:AAAA",
	})
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("appended junk signature rejected the envelope: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("valid signature no longer verifies after a junk signature was appended")
	}
	if ap.Signatures[1].Status != SigUnknownSuite {
		t.Errorf("appended junk signature status = %q, want unknown_suite", ap.Signatures[1].Status)
	}
}

func TestNewEd25519Signer_Rejects(t *testing.T) {
	_, priv := genKey(t)
	if _, err := NewEd25519Signer("", "mediator", priv); !errors.Is(err, ErrMalformedSuite) {
		t.Errorf("empty key_id: got %v", err)
	}
	if _, err := NewEd25519Signer("k", "bogus-role", priv); !errors.Is(err, ErrMalformedSuite) {
		t.Errorf("bad role: got %v", err)
	}
	if _, err := NewEd25519Signer("k", "mediator", ed25519.PrivateKey{1, 2, 3}); !errors.Is(err, ErrMalformedSuite) {
		t.Errorf("bad key size: got %v", err)
	}
}

// TestTrustEntryRole_Enforced proves a trust entry scoped to a role does NOT
// confirm mediator_key_pinned for a signature carrying a different role.
func TestTrustEntryRole_Enforced(t *testing.T) {
	env, pub := signedEnvelopeWithKey(t) // signed with signer_role "mediator"
	opts := VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub},
		// Entry authorizes this key only for the "issuer" role.
		Trust: map[string]TrustEntry{testKeyID: {MediatorID: testMediatorID, Role: "issuer", TrustDomain: testTrustDomain}},
	}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("AssertionSigned = false; signature should still verify")
	}
	if contains(ap.VerifiedClaims, ClaimMediatorKeyPinned) {
		t.Error("mediator_key_pinned verified despite role mismatch (role scoping not enforced)")
	}
}

// TestTrustEntryRole_MatchVerifies confirms the matching-role path still pins.
func TestTrustEntryRole_MatchVerifies(t *testing.T) {
	env, pub := signedEnvelopeWithKey(t) // signer_role "mediator"
	opts := VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub},
		Trust:       map[string]TrustEntry{testKeyID: {MediatorID: testMediatorID, Role: "mediator"}},
	}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !contains(ap.VerifiedClaims, ClaimMediatorKeyPinned) {
		t.Error("mediator_key_pinned not verified despite matching role")
	}
}

// TestCritExtIsSigned proves the envelope-level crit_ext is covered by the
// signature: changing it after signing breaks verification (a MITM cannot strip
// or alter a flagged critical extension). Uses a hand-set known extension so the
// envelope is not rejected outright for an unknown critical extension.
func TestCritExtIsSigned(t *testing.T) {
	_, priv := genKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	signer, _ := NewEd25519Signer(testKeyID, "mediator", priv)
	// Temporarily register a known critical extension for this test only.
	knownCriticalExtensions["x-test-crit"] = true
	defer delete(knownCriticalExtensions, "x-test-crit")

	e := baseEnvelope()
	e.CritExt = []string{"x-test-crit"}
	env, err := Sign(e, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	opts := VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub}}

	// Signed as-is: verifies.
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ap.AssertionSigned {
		t.Fatal("AssertionSigned = false for valid crit_ext envelope")
	}

	// MITM strips the critical extension after signing → signature must break.
	stripped := env
	stripped.CritExt = nil
	ap2, err := Verify(stripped, opts)
	if err != nil {
		t.Fatalf("Verify(stripped): %v", err)
	}
	if ap2.AssertionSigned {
		t.Fatal("stripping signed crit_ext did not break the signature")
	}
}

func TestSign_RejectsNilSigner(t *testing.T) {
	// Untyped nil and a typed-nil *Ed25519Signer must both fail closed, not panic.
	if _, err := Sign(baseEnvelope(), nil); !errors.Is(err, ErrSchema) {
		t.Fatalf("Sign(nil) = %v, want ErrSchema", err)
	}
	var typedNil *Ed25519Signer
	if _, err := Sign(baseEnvelope(), typedNil); !errors.Is(err, ErrSchema) {
		t.Fatalf("Sign(typed-nil ed25519) = %v, want ErrSchema", err)
	}
	var pqNil *MLDSA65Signer
	if _, err := Sign(baseEnvelope(), pqNil); !errors.Is(err, ErrSchema) {
		t.Fatalf("Sign(typed-nil ml-dsa) = %v, want ErrSchema", err)
	}
}

// TestMalformedCritPerSignature: a malformed per-signature crit list (duplicate
// names) is reported SigMalformed for that signature, not envelope-fatal.
func TestMalformedCritPerSignature(t *testing.T) {
	env, opts := signedEnvelope(t)
	env.Signatures[0].Protected.Crit = []string{"dup", "dup"}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify returned envelope error (want per-signature status): %v", err)
	}
	if ap.Signatures[0].Status != SigMalformed {
		t.Fatalf("status = %q, want malformed", ap.Signatures[0].Status)
	}
}

func TestMLDSA65Signer_SignFailsClosed(t *testing.T) {
	signer, err := NewMLDSA65Signer("pq-1", "mediator")
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	if _, err := Sign(baseEnvelope(), signer); !errors.Is(err, ErrSuiteUnimplemented) {
		t.Fatalf("Sign with PQ signer = %v, want ErrSuiteUnimplemented", err)
	}
}
