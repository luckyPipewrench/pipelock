// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package coveragecert

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// genTestKey generates a deterministic test key pair.
func genTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func validBody(pub ed25519.PublicKey) Body {
	now := time.Now().UTC()
	return Body{
		Schema:      Schema,
		KeyPurpose:  KeyPurpose,
		Agent:       "agent-a",
		WindowStart: now.Add(-1 * time.Hour),
		WindowEnd:   now,
		Sessions: []SessionCoverage{
			{
				ID:                 "session-001",
				ReceiptCount:       42,
				ChainIntact:        true,
				Anchored:           "local",
				CompletenessStatus: "LIMITED",
				CompletenessReason: "bounded_closed",
			},
			{
				ID:                 "session-002",
				ReceiptCount:       18,
				ChainIntact:        false,
				Anchored:           "none",
				CompletenessStatus: "BROKEN",
				CompletenessReason: "chain_broken",
			},
		},
		TotalReceipts:      60,
		ChainGaps:          1,
		SessionsCovered:    2,
		ChainsIntact:       1,
		ChainsBroken:       1,
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           DefaultBoundary(),
		StandingExclusions: DefaultStandingExclusions(),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	trustedKeys := map[string]struct{}{
		hex.EncodeToString(pub): {},
	}
	result, err := Verify(cert, trustedKeys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.SignatureValid {
		t.Error("expected SignatureValid=true")
	}
	if !result.SignerTrusted {
		t.Error("expected SignerTrusted=true")
	}
	if len(result.Lines) == 0 {
		t.Error("expected non-empty Lines")
	}

	// Lines must contain bounded per-fact statements.
	hasSignature := false
	hasSigner := false
	hasAgent := false
	for _, line := range result.Lines {
		if strings.HasPrefix(line, "Signature:") {
			hasSignature = true
		}
		if strings.HasPrefix(line, "Signer:") {
			hasSigner = true
		}
		if strings.HasPrefix(line, "Agent:") {
			hasAgent = true
		}
	}
	if !hasSignature {
		t.Error("Lines missing Signature line")
	}
	if !hasSigner {
		t.Error("Lines missing Signer line")
	}
	if !hasAgent {
		t.Error("Lines missing Agent line")
	}

	// No aggregate mismatch should appear in a well-formed cert.
	for _, line := range result.Lines {
		if strings.HasPrefix(line, "MISMATCH:") {
			t.Errorf("unexpected mismatch line: %s", line)
		}
	}
}

func TestVerify_BodyTamper_InvalidSignature(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper: change the agent name.
	cert.Body.Agent = "agent-tampered"

	trustedKeys := map[string]struct{}{
		hex.EncodeToString(pub): {},
	}
	result, err := Verify(cert, trustedKeys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.SignatureValid {
		t.Error("expected SignatureValid=false after tamper")
	}
}

func TestVerify_UntrustedSigner_NotTOFU(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Use a different key as trusted (the signer is not trusted).
	otherPub, _ := genTestKey(t)
	trustedKeys := map[string]struct{}{
		hex.EncodeToString(otherPub): {},
	}
	result, err := Verify(cert, trustedKeys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.SignatureValid {
		t.Error("signature should still be valid even if signer is untrusted")
	}
	if result.SignerTrusted {
		t.Error("expected SignerTrusted=false for untrusted key (NOT TOFU)")
	}

	// With nil trustedKeys, SignerTrusted should be false.
	resultNil, err := Verify(cert, nil)
	if err != nil {
		t.Fatalf("Verify with nil keys: %v", err)
	}
	if resultNil.SignerTrusted {
		t.Error("expected SignerTrusted=false with nil trusted keys")
	}
}

func TestVerify_AggregateMismatch_Flagged(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Tamper one session while leaving the signed aggregate at 60.
	cert.Body.Sessions[0].ReceiptCount = 999

	result, err := Verify(cert, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	hasMismatch := false
	for _, line := range result.Lines {
		if strings.Contains(line, "MISMATCH") && strings.Contains(line, "total_receipts") {
			hasMismatch = true
		}
	}
	if !hasMismatch {
		t.Error("expected MISMATCH line for total_receipts aggregate")
	}
	if result.SignatureValid {
		t.Error("tampering a session count should also invalidate the signature")
	}
	if result.AggregateValid {
		t.Error("AggregateValid should be false when sessions and signed totals differ")
	}
}

func TestVerify_TrustedSignatureWithInvalidBodyFailsClosed(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)
	body.Boundary = "Coverage of all agent activity and mediated egress inside the declared Pipelock boundary"

	cert := signCoverageCertBodyUnchecked(t, body, pub, priv)
	_, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err == nil {
		t.Fatal("trusted valid signature over invalid body should fail closed")
	}
	if !strings.Contains(err.Error(), ErrBodyInvalid.Error()) {
		t.Fatalf("error = %q, want body validation failure", err.Error())
	}
}

func TestVerify_TrustedSignerKeyMustMatchEnvelopeSigner(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	otherPub, _ := genTestKey(t)
	body := validBody(pub)
	body.TrustedSignerKey = hex.EncodeToString(otherPub)

	cert := signCoverageCertBodyUnchecked(t, body, pub, priv)
	_, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err == nil {
		t.Fatal("trusted signature with mismatched trusted_signer_key should fail closed")
	}
	if !strings.Contains(err.Error(), "trusted_signer_key") {
		t.Fatalf("error = %q, want trusted_signer_key mismatch", err.Error())
	}
}

func TestValidate_TrustedSignerKeyMalformedFailsClosed(t *testing.T) {
	t.Parallel()
	pub, _ := genTestKey(t)

	tests := []struct {
		name      string
		signerKey string
		wantErr   string
	}{
		{
			name:      "non hex",
			signerKey: "not-hex",
			wantErr:   "decode",
		},
		{
			name:      "wrong length",
			signerKey: "abcd",
			wantErr:   "length",
		},
		{
			name:      "uppercase",
			signerKey: strings.ToUpper(hex.EncodeToString(pub)),
			wantErr:   "lowercase hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := validBody(pub)
			body.TrustedSignerKey = tt.signerKey

			err := body.Validate()
			if err == nil {
				t.Fatal("expected malformed trusted_signer_key to fail closed")
			}
			if !strings.Contains(err.Error(), "trusted_signer_key") {
				t.Fatalf("error = %q, want trusted_signer_key context", err.Error())
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func signCoverageCertBodyUnchecked(t *testing.T, body Body, pub ed25519.PublicKey, priv ed25519.PrivateKey) Certificate {
	t.Helper()
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	return Certificate{
		Body:      body,
		Signature: hex.EncodeToString(ed25519.Sign(priv, preimage)),
		SignerKey: hex.EncodeToString(pub),
	}
}

func TestSign_AggregateOverclaimRejected(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)
	body.TotalReceipts = 999

	_, err := Sign(body, priv)
	if err == nil {
		t.Fatal("expected Sign to reject overclaimed aggregate totals")
	}
	if !strings.Contains(err.Error(), ErrAggregateMismatch.Error()) {
		t.Fatalf("error = %q, want aggregate mismatch", err.Error())
	}
}

func TestSign_InvalidPrivateKeyRejected(t *testing.T) {
	t.Parallel()
	pub, _ := genTestKey(t)
	body := validBody(pub)

	_, err := Sign(body, ed25519.PrivateKey("short"))
	if err == nil {
		t.Fatal("expected invalid private key to be rejected")
	}
	if !strings.Contains(err.Error(), "private key length") {
		t.Fatalf("error = %q, want private key length", err.Error())
	}
}

func TestSign_Validation(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)

	tests := []struct {
		name    string
		modify  func(*Body)
		wantErr string
	}{
		{
			name:    "wrong schema",
			modify:  func(b *Body) { b.Schema = "wrong" },
			wantErr: "schema=",
		},
		{
			name:    "wrong key purpose",
			modify:  func(b *Body) { b.KeyPurpose = "wrong" },
			wantErr: "key_purpose=",
		},
		{
			name:    "empty agent",
			modify:  func(b *Body) { b.Agent = "" },
			wantErr: "agent is required",
		},
		{
			name: "window end before start",
			modify: func(b *Body) {
				b.WindowEnd = b.WindowStart.Add(-1 * time.Hour)
			},
			wantErr: "window_end",
		},
		{
			name:    "missing boundary phrase",
			modify:  func(b *Body) { b.Boundary = "wrong boundary" },
			wantErr: requiredBoundaryPhrase,
		},
		{
			name:    "aggregate overclaim",
			modify:  func(b *Body) { b.SessionsCovered = len(b.Sessions) + 1 },
			wantErr: ErrAggregateMismatch.Error(),
		},
		{
			name: "over-claiming boundary",
			modify: func(b *Body) {
				b.Boundary = "Coverage of all agent activity inside the declared Pipelock boundary and mediated egress inside the declared Pipelock boundary"
			},
			wantErr: "all agent activity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := validBody(pub)
			tt.modify(&body)
			_, err := Sign(body, priv)
			if err == nil {
				t.Fatal("expected Sign to refuse ill-formed body")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	data, err := Marshal(cert)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Re-verify the round-tripped cert.
	trustedKeys := map[string]struct{}{
		hex.EncodeToString(pub): {},
	}
	result, err := Verify(got, trustedKeys)
	if err != nil {
		t.Fatalf("Verify round-tripped cert: %v", err)
	}
	if !result.SignatureValid {
		t.Error("round-tripped cert signature should be valid")
	}
	if !result.SignerTrusted {
		t.Error("round-tripped cert signer should be trusted")
	}
}

func TestAbsentFieldsRenderBounded(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	now := time.Now().UTC()

	// Minimal body with no sessions.
	body := Body{
		Schema:             Schema,
		KeyPurpose:         KeyPurpose,
		Agent:              "agent-a",
		WindowStart:        now.Add(-1 * time.Hour),
		WindowEnd:          now,
		Sessions:           nil,
		TotalReceipts:      0,
		ChainGaps:          0,
		SessionsCovered:    0,
		ChainsIntact:       0,
		ChainsBroken:       0,
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           DefaultBoundary(),
		StandingExclusions: DefaultStandingExclusions(),
	}

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result, err := Verify(cert, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Should have lines, never fabricated data.
	found := false
	for _, line := range result.Lines {
		if strings.Contains(line, "Sessions covered: 0") {
			found = true
		}
	}
	if !found {
		t.Error("expected bounded 'Sessions covered: 0' line for absent sessions")
	}
}

func TestBoundaryPhraseEnforced(t *testing.T) {
	t.Parallel()
	_, priv := genTestKey(t)
	now := time.Now().UTC()

	body := Body{
		Schema:      Schema,
		KeyPurpose:  KeyPurpose,
		Agent:       "agent-a",
		WindowStart: now.Add(-1 * time.Hour),
		WindowEnd:   now,
		Boundary:    "some boundary without the required phrase",
	}

	_, err := Sign(body, priv)
	if err == nil {
		t.Fatal("expected error for missing boundary phrase")
	}
	if !strings.Contains(err.Error(), requiredBoundaryPhrase) {
		t.Errorf("error should mention required phrase, got: %v", err)
	}
}

func TestVerify_BadSignatureFormat(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cert.Signature = "not-hex"
	_, verErr := Verify(cert, nil)
	if verErr == nil {
		t.Fatal("expected error for bad signature hex")
	}
}

func TestVerify_BadSignerKeyFormat(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cert.SignerKey = "not-hex"
	_, verErr := Verify(cert, nil)
	if verErr == nil {
		t.Fatal("expected error for bad signer key hex")
	}
}

func TestVerify_ShortSignerKey(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cert.SignerKey = hex.EncodeToString([]byte("short"))
	_, verErr := Verify(cert, nil)
	if verErr == nil {
		t.Fatal("expected error for short signer key")
	}
}

func TestUnmarshal_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := Unmarshal([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestUnmarshal_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	_, err := Unmarshal([]byte(`{
		"body": {
			"schema": "pipelock.coverage_cert.v1",
			"key_purpose": "coverage-cert-signing",
			"agent": "agent-a",
			"window_start": "2026-01-01T00:00:00Z",
			"window_end": "2026-01-01T01:00:00Z",
			"sessions": [],
			"total_receipts": 0,
			"chain_gaps": 0,
			"sessions_covered": 0,
			"chains_intact": 0,
			"chains_broken": 0,
			"trusted_signer_key": "",
			"boundary": "mediated egress inside the declared Pipelock boundary",
			"standing_exclusions": [],
			"unverified_extra_claim": "everything verified"
		},
		"signature": "",
		"signer_key": ""
	}`))
	if err == nil {
		t.Fatal("expected unknown body field to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %q, want unknown field", err.Error())
	}
}

func TestSign_SetsSignerKeyFromPrivate(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if cert.SignerKey != hex.EncodeToString(pub) {
		t.Errorf("SignerKey should match public key; got %s, want %s",
			cert.SignerKey, hex.EncodeToString(pub))
	}
}

func TestMarshal_ProducesValidJSON(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)

	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	data, err := Marshal(cert)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if !json.Valid(data) {
		t.Error("Marshal output is not valid JSON")
	}
}

func TestVerify_AllAggregateMismatchTypes(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)

	tests := []struct {
		name    string
		modify  func(*Body)
		wantSub string
	}{
		{
			name:    "chains_intact mismatch",
			modify:  func(b *Body) { b.ChainsIntact = 999 },
			wantSub: "chains_intact",
		},
		{
			name:    "chains_broken mismatch",
			modify:  func(b *Body) { b.ChainsBroken = 999 },
			wantSub: "chains_broken",
		},
		{
			name:    "sessions_covered mismatch",
			modify:  func(b *Body) { b.SessionsCovered = 999 },
			wantSub: "sessions_covered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := validBody(pub)

			cert, err := Sign(body, priv)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			tt.modify(&cert.Body)

			result, err := Verify(cert, nil)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}

			hasMismatch := false
			for _, line := range result.Lines {
				if strings.Contains(line, "MISMATCH") && strings.Contains(line, tt.wantSub) {
					hasMismatch = true
				}
			}
			if !hasMismatch {
				t.Errorf("expected MISMATCH line for %s", tt.wantSub)
			}
			if result.AggregateValid {
				t.Errorf("AggregateValid should be false for %s", tt.wantSub)
			}
		})
	}
}

func TestDefaultBoundaryContainsRequiredPhrase(t *testing.T) {
	t.Parallel()
	b := DefaultBoundary()
	if !strings.Contains(b, requiredBoundaryPhrase) {
		t.Errorf("DefaultBoundary() should contain %q", requiredBoundaryPhrase)
	}
}

func TestDefaultStandingExclusions(t *testing.T) {
	t.Parallel()
	exclusions := DefaultStandingExclusions()
	if len(exclusions) != 2 {
		t.Fatalf("expected 2 standing exclusions, got %d", len(exclusions))
	}
	if exclusions[0] != standingExclusionMediated {
		t.Errorf("first exclusion should be mediated caveat, got %q", exclusions[0])
	}
	if exclusions[1] != standingExclusionWallClock {
		t.Errorf("second exclusion should be wall-clock caveat, got %q", exclusions[1])
	}
}
