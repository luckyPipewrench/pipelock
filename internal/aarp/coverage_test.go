// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func TestSubjectValidate_Branches(t *testing.T) {
	good := Subject{
		ActionRecordSHA256:    digest64(1),
		ReceiptEnvelopeSHA256: digest64(2),
		ReceiptSignerKey:      digest64(3),
		ReceiptType:           ReceiptTypeActionV1,
	}
	if err := good.validate(); err != nil {
		t.Fatalf("good subject: %v", err)
	}
	mutate := []func(*Subject){
		func(s *Subject) { s.ActionRecordSHA256 = "bad" },
		func(s *Subject) { s.ReceiptEnvelopeSHA256 = "bad" },
		func(s *Subject) { s.ReceiptSignerKey = "bad" },
		func(s *Subject) { s.ReceiptType = "unknown_type" },
	}
	for i, m := range mutate {
		s := good
		m(&s)
		if err := s.validate(); !errors.Is(err, ErrSchema) {
			t.Errorf("mutation %d: got %v, want ErrSchema", i, err)
		}
	}
}

func TestAssertionValidate_Branches(t *testing.T) {
	good := Assertion{MediatorID: testMediatorID, IssuedAt: testIssuedAt, TrustDomain: testTrustDomain}
	if err := good.validate(); err != nil {
		t.Fatalf("good assertion: %v", err)
	}
	mutate := []func(*Assertion){
		func(a *Assertion) { a.MediatorID = "" },
		func(a *Assertion) { a.IssuedAt = "not-a-time" },
		func(a *Assertion) { a.TrustDomain = "10.0.0.1" }, // IP literal
		func(a *Assertion) { a.TrustDomain = "bad domain with spaces" },
	}
	for i, m := range mutate {
		a := good
		m(&a)
		if err := a.validate(); !errors.Is(err, ErrSchema) {
			t.Errorf("mutation %d: got %v, want ErrSchema", i, err)
		}
	}
	// Empty trust domain is allowed (optional in core).
	a := good
	a.TrustDomain = ""
	if err := a.validate(); err != nil {
		t.Errorf("empty trust domain should be allowed: %v", err)
	}
}

func TestValidateSuiteShape_Branches(t *testing.T) {
	good := ProtectedHeader{Profile: Profile, Canon: CanonID, Alg: string(AlgEd25519), KeyType: "ed25519", KeyID: "k", SignerRole: "mediator"}
	if err := good.validateSuiteShape(); err != nil {
		t.Fatalf("good header: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*ProtectedHeader)
		errIs  error
	}{
		{"profile", func(h *ProtectedHeader) { h.Profile = "x" }, ErrUnknownSuite},
		{"canon", func(h *ProtectedHeader) { h.Canon = "x" }, ErrUnknownSuite},
		{"alg", func(h *ProtectedHeader) { h.Alg = "rsa" }, ErrUnknownSuite},
		{"keytype", func(h *ProtectedHeader) { h.KeyType = "rsa" }, ErrMalformedSuite},
		{"keyid", func(h *ProtectedHeader) { h.KeyID = "" }, ErrMalformedSuite},
		{"role", func(h *ProtectedHeader) { h.SignerRole = "bogus" }, ErrMalformedSuite},
		{"crit", func(h *ProtectedHeader) { h.Crit = []string{"unknown"} }, ErrUnknownCriticalExtension},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := good
			tc.mutate(&h)
			if err := h.validateSuiteShape(); !errors.Is(err, tc.errIs) {
				t.Fatalf("got %v, want %v", err, tc.errIs)
			}
		})
	}
}

func TestCheckCriticalExtensions_Branches(t *testing.T) {
	if err := checkCriticalExtensions(nil); err != nil {
		t.Errorf("nil crit: %v", err)
	}
	if err := checkCriticalExtensions([]string{""}); !errors.Is(err, ErrMalformedSuite) {
		t.Errorf("empty name: got %v", err)
	}
	if err := checkCriticalExtensions([]string{"a", "a"}); !errors.Is(err, ErrMalformedSuite) {
		t.Errorf("duplicate: got %v", err)
	}
	if err := checkCriticalExtensions([]string{"unknown"}); !errors.Is(err, ErrUnknownCriticalExtension) {
		t.Errorf("unknown: got %v", err)
	}
}

func TestValidateTrustDomainName_Branches(t *testing.T) {
	if err := validateTrustDomainName("example.org"); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := validateTrustDomainName("10.0.0.1"); err == nil {
		t.Error("IP literal should be rejected")
	}
	if err := validateTrustDomainName("bad domain"); err == nil {
		t.Error("malformed domain should be rejected")
	}
}

func TestCheckSafeNumber_DefensiveBranches(t *testing.T) {
	if err := checkSafeNumber("", "$"); !errors.Is(err, ErrUnsafeNumber) {
		t.Errorf("empty: got %v", err)
	}
	if err := checkSafeNumber("12x", "$"); !errors.Is(err, ErrUnsafeNumber) {
		t.Errorf("non-integer: got %v", err)
	}
	if err := checkSafeNumber("0", "$"); err != nil {
		t.Errorf("zero: %v", err)
	}
}

func TestParseSeq_Branches(t *testing.T) {
	n, err := parseSeq("42")
	if err != nil || n != 42 {
		t.Fatalf("parseSeq(42) = %d, %v", n, err)
	}
	if _, err := parseSeq("-1"); !errors.Is(err, ErrBadGrammar) {
		t.Errorf("parseSeq(-1) = %v, want ErrBadGrammar", err)
	}
}

func TestDecodeSigWire_Branches(t *testing.T) {
	if _, err := decodeSigWire("ed25519", "wrongprefix:AAAA"); !errors.Is(err, ErrSchema) {
		t.Errorf("bad prefix: got %v", err)
	}
	if _, err := decodeSigWire("ed25519", "ed25519:not!base64"); !errors.Is(err, ErrSchema) {
		t.Errorf("bad base64: got %v", err)
	}
	raw, err := decodeSigWire("ed25519", "ed25519:AAAA")
	if err != nil || len(raw) == 0 {
		t.Errorf("good wire: %v", err)
	}
}

func TestMLDSA65Signer_DirectSignInputFailsClosed(t *testing.T) {
	signer, err := NewMLDSA65Signer("pq-1", "mediator")
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	if _, err := signer.signInput([]byte("x")); !errors.Is(err, ErrSuiteUnimplemented) {
		t.Fatalf("signInput = %v, want ErrSuiteUnimplemented", err)
	}
	// Header is well-formed and shape-valid even though signing is unimplemented.
	if err := signer.Header().validateSuiteShape(); err != nil {
		t.Fatalf("PQ header shape: %v", err)
	}
}

func TestNewMLDSA65Signer_Rejects(t *testing.T) {
	if _, err := NewMLDSA65Signer("", "mediator"); !errors.Is(err, ErrMalformedSuite) {
		t.Errorf("empty key_id: %v", err)
	}
	if _, err := NewMLDSA65Signer("k", "bogus"); !errors.Is(err, ErrMalformedSuite) {
		t.Errorf("bad role: %v", err)
	}
}

func TestValidateUint64String_Overflow(t *testing.T) {
	// One past max uint64.
	if err := ValidateUint64String("18446744073709551616"); !errors.Is(err, ErrBadGrammar) {
		t.Fatalf("overflow: %v", err)
	}
	// A very long all-digit string also overflows.
	if err := ValidateUint64String(strings.Repeat("9", 40)); !errors.Is(err, ErrBadGrammar) {
		t.Fatalf("long overflow: %v", err)
	}
}

func TestAppraiseSignature_WrongSizeTrustedKey(t *testing.T) {
	env, _ := signedEnvelopeWithKey(t)
	// Trusted key registered with a wrong size → malformed, never verified.
	opts := VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: {1, 2, 3}}}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.Signatures[0].Status != SigMalformed {
		t.Fatalf("status = %q, want malformed", ap.Signatures[0].Status)
	}
}

func TestAppraiseSignature_WrongLengthSignature(t *testing.T) {
	env, pub := signedEnvelopeWithKey(t)
	// A correctly-prefixed but wrong-length signature must fail (not panic).
	env.Signatures[0].Sig = "ed25519:AAAA"
	opts := VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub}}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.Signatures[0].Status != SigFailed {
		t.Fatalf("status = %q, want failed", ap.Signatures[0].Status)
	}
}

func TestAppraiseSignature_BadWireEncoding(t *testing.T) {
	env, pub := signedEnvelopeWithKey(t)
	env.Signatures[0].Sig = "ed25519:not!base64!"
	opts := VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub}}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.Signatures[0].Status != SigMalformed {
		t.Fatalf("status = %q, want malformed", ap.Signatures[0].Status)
	}
}

func TestSign_RejectsInvalidChain(t *testing.T) {
	_, priv := genKey(t)
	signer, _ := NewEd25519Signer(testKeyID, "issuer", priv)
	e := baseEnvelope()
	e.Chain = &ChainLink{IssuerID: "i", Seq: "-1", PriorHash: digest64(1)} // bad seq
	if _, err := Sign(e, signer); !errors.Is(err, ErrChainSchema) {
		t.Fatalf("Sign with bad chain = %v, want ErrChainSchema", err)
	}
}

func TestVerify_EmptySignatureSetRejected(t *testing.T) {
	e := baseEnvelope()
	e.Signatures = nil
	if _, err := Verify(e, VerifyOptions{}); !errors.Is(err, ErrSchema) {
		t.Fatalf("Verify(no sigs) = %v, want ErrSchema", err)
	}
}

func TestSign_AutoSetsProfile(t *testing.T) {
	_, priv := genKey(t)
	signer, _ := NewEd25519Signer(testKeyID, "mediator", priv)
	e := baseEnvelope()
	e.Profile = "" // Sign fills it with the package default.
	signed, err := Sign(e, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.Profile != Profile {
		t.Fatalf("profile = %q, want %q", signed.Profile, Profile)
	}
}

func TestMediatorKeyPinned_TrustDomainMismatch(t *testing.T) {
	env, pub := signedEnvelopeWithKey(t)
	opts := VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub},
		// Trust entry pins a DIFFERENT trust domain than the assertion carries.
		Trust: map[string]TrustEntry{testKeyID: {MediatorID: testMediatorID, TrustDomain: "other.example"}},
	}
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if contains(ap.VerifiedClaims, ClaimMediatorKeyPinned) {
		t.Error("mediator_key_pinned verified despite trust-domain mismatch")
	}
}

func TestVerifyChain_InvalidGrammarLink(t *testing.T) {
	e := baseEnvelope()
	e.Chain = &ChainLink{IssuerID: "i", Seq: "01", PriorHash: digest64(1)} // leading-zero seq
	if err := VerifyChain([]Envelope{e}); !errors.Is(err, ErrChainSchema) {
		t.Fatalf("VerifyChain(bad grammar) = %v, want ErrChainSchema", err)
	}
}

func TestVerify_EnvelopeProfileMismatch(t *testing.T) {
	env, opts := signedEnvelope(t)
	env.Profile = "aarp/v9.9"
	if _, err := Verify(env, opts); !errors.Is(err, ErrSchema) {
		t.Fatalf("Verify(envelope profile mismatch) = %v, want ErrSchema", err)
	}
}

func TestSign_RejectsInvalidAssertion(t *testing.T) {
	_, priv := genKey(t)
	signer, _ := NewEd25519Signer(testKeyID, "mediator", priv)
	e := baseEnvelope()
	e.Assertion.MediatorID = "" // valid subject, invalid assertion
	if _, err := Sign(e, signer); !errors.Is(err, ErrSchema) {
		t.Fatalf("Sign with empty mediator_id = %v, want ErrSchema", err)
	}
}

// TestAppraiseSignature_AttackerCraftedHeader proves a hand-crafted envelope
// whose signature header has an empty key_id or an unknown role (which Sign
// would never emit, but Unmarshal accepts structurally) is reported malformed,
// never verified.
func TestAppraiseSignature_AttackerCraftedHeader(t *testing.T) {
	mk := func(mut func(*ProtectedHeader)) Envelope {
		env, _ := signedEnvelope(t)
		mut(&env.Signatures[0].Protected)
		return env
	}
	t.Run("empty_key_id", func(t *testing.T) {
		env := mk(func(h *ProtectedHeader) { h.KeyID = "" })
		ap, err := Verify(env, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if ap.Signatures[0].Status != SigMalformed {
			t.Fatalf("status = %q, want malformed", ap.Signatures[0].Status)
		}
	})
	t.Run("unknown_role", func(t *testing.T) {
		env := mk(func(h *ProtectedHeader) { h.SignerRole = "bogus-role" })
		ap, err := Verify(env, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if ap.Signatures[0].Status != SigMalformed {
			t.Fatalf("status = %q, want malformed", ap.Signatures[0].Status)
		}
	})
}

func TestAppraisalJSON_NoTrustedOrSafeKeys(t *testing.T) {
	ap := newAppraisal()
	if ap.Profile != Profile {
		t.Fatalf("profile = %q", ap.Profile)
	}
	if len(ap.DoesNotAssert) == 0 {
		t.Fatal("does_not_assert must not be empty")
	}
}
