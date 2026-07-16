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
	if !result.AggregateValid {
		t.Error("expected AggregateValid=true")
	}
	if !result.StructuralValid {
		t.Error("expected StructuralValid=true")
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
	if err == nil {
		t.Fatal("expected Verify to fail closed after body tamper")
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
	if err == nil {
		t.Fatal("expected Verify to fail closed for pinned untrusted signer")
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
	if !resultNil.StructuralValid {
		t.Error("expected StructuralValid=true with nil trusted keys")
	}
	resultJSON, err := json.Marshal(resultNil)
	if err != nil {
		t.Fatalf("Marshal VerifyResult: %v", err)
	}
	if !strings.Contains(string(resultJSON), `"structural_valid":true`) {
		t.Fatalf("VerifyResult JSON = %s, want structural_valid=true", resultJSON)
	}
	if !strings.Contains(string(resultJSON), `"signer_trusted":false`) {
		t.Fatalf("VerifyResult JSON = %s, want signer_trusted=false", resultJSON)
	}
	if strings.Contains(string(resultJSON), `"valid":true`) {
		t.Fatalf("VerifyResult JSON = %s, must not expose bare valid=true", resultJSON)
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
	if err == nil {
		t.Fatal("expected Verify to fail closed for aggregate mismatch")
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
			wantErr: "canonical",
		},
		{
			name:    "wrong key purpose",
			modify:  func(b *Body) { b.KeyPurpose = "wrong" },
			wantErr: "canonical",
		},
		{
			name:    "empty agent",
			modify:  func(b *Body) { b.Agent = "" },
			wantErr: "agent is required",
		},
		{
			name:    "agent must be NFC",
			modify:  func(b *Body) { b.Agent = "cafe\u0301-agent" },
			wantErr: "NFC",
		},
		{
			name:    "agent must not contain line controls",
			modify:  func(b *Body) { b.Agent = "agent-a\nSessions covered: 999999" },
			wantErr: "control",
		},
		{
			name:    "session id must not contain format controls",
			modify:  func(b *Body) { b.Sessions[0].ID = "session-\u202e001" },
			wantErr: "format",
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
			wantErr: "canonical",
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
			wantErr: "canonical",
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
		Sessions:           []SessionCoverage{},
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
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Now().UTC()

	body := Body{
		Schema:             Schema,
		KeyPurpose:         KeyPurpose,
		Agent:              "agent-a",
		WindowStart:        now.Add(-1 * time.Hour),
		WindowEnd:          now,
		Sessions:           []SessionCoverage{},
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           "some boundary without the required phrase",
		StandingExclusions: DefaultStandingExclusions(),
	}

	_, err := Sign(body, priv)
	if err == nil {
		t.Fatal("expected error for missing boundary phrase")
	}
	if !strings.Contains(err.Error(), "canonical") {
		t.Errorf("error should mention canonical body, got: %v", err)
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

func TestUnmarshal_RejectsStructuralJSONTamper(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "duplicate top-level key",
			raw: `{
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
					"boundary": "",
					"standing_exclusions": []
				},
				"signature": "",
				"signature": "",
				"signer_key": ""
			}`,
		},
		{
			name: "duplicate nested key",
			raw: `{
				"body": {
					"schema": "pipelock.coverage_cert.v1",
					"key_purpose": "coverage-cert-signing",
					"agent": "agent-a",
					"agent": "agent-b",
					"window_start": "2026-01-01T00:00:00Z",
					"window_end": "2026-01-01T01:00:00Z",
					"sessions": [],
					"total_receipts": 0,
					"chain_gaps": 0,
					"sessions_covered": 0,
					"chains_intact": 0,
					"chains_broken": 0,
					"trusted_signer_key": "",
					"boundary": "",
					"standing_exclusions": []
				},
				"signature": "",
				"signer_key": ""
			}`,
		},
		{
			name: "trailing json value",
			raw: `{
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
					"boundary": "",
					"standing_exclusions": []
				},
				"signature": "",
				"signer_key": ""
			} {"body":{}}`,
		},
		{
			name: "unknown session field",
			raw: `{
				"body": {
					"schema": "pipelock.coverage_cert.v1",
					"key_purpose": "coverage-cert-signing",
					"agent": "agent-a",
					"window_start": "2026-01-01T00:00:00Z",
					"window_end": "2026-01-01T01:00:00Z",
					"sessions": [{
						"id": "session-a",
						"receipt_count": 1,
						"chain_intact": true,
						"anchored": "local",
						"completeness_status": "LIMITED",
						"completeness_reason": "bounded_closed",
						"extra_claim": "all sessions covered"
					}],
					"total_receipts": 1,
					"chain_gaps": 0,
					"sessions_covered": 1,
					"chains_intact": 1,
					"chains_broken": 0,
					"trusted_signer_key": "",
					"boundary": "",
					"standing_exclusions": []
				},
				"signature": "",
				"signer_key": ""
			}`,
		},
		{
			name: "sessions object instead of array",
			raw: `{
				"body": {
					"schema": "pipelock.coverage_cert.v1",
					"key_purpose": "coverage-cert-signing",
					"agent": "agent-a",
					"window_start": "2026-01-01T00:00:00Z",
					"window_end": "2026-01-01T01:00:00Z",
					"sessions": {},
					"total_receipts": 0,
					"chain_gaps": 0,
					"sessions_covered": 0,
					"chains_intact": 0,
					"chains_broken": 0,
					"trusted_signer_key": "",
					"boundary": "",
					"standing_exclusions": []
				},
				"signature": "",
				"signer_key": ""
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Unmarshal([]byte(tt.raw)); err == nil {
				t.Fatal("expected structural JSON tamper to be rejected")
			}
		})
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

			_, err = Verify(cert, nil)
			if err == nil {
				t.Fatalf("expected Verify to fail closed for %s", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestVerify_RejectsAnyNonCanonicalDerivableField(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	otherPub, _ := genTestKey(t)

	tests := []struct {
		name   string
		modify func(*Body)
	}{
		{
			name:   "schema",
			modify: func(b *Body) { b.Schema = "pipelock.coverage_cert.v2" },
		},
		{
			name:   "key purpose",
			modify: func(b *Body) { b.KeyPurpose = "receipt-signing" },
		},
		{
			name:   "total receipts",
			modify: func(b *Body) { b.TotalReceipts++ },
		},
		{
			name:   "chain gaps",
			modify: func(b *Body) { b.ChainGaps++ },
		},
		{
			name:   "sessions covered",
			modify: func(b *Body) { b.SessionsCovered++ },
		},
		{
			name:   "chains intact",
			modify: func(b *Body) { b.ChainsIntact++ },
		},
		{
			name:   "chains broken",
			modify: func(b *Body) { b.ChainsBroken++ },
		},
		{
			name:   "trusted signer key",
			modify: func(b *Body) { b.TrustedSignerKey = hex.EncodeToString(otherPub) },
		},
		{
			name:   "boundary",
			modify: func(b *Body) { b.Boundary = DefaultBoundary() + " and unlisted sessions" },
		},
		{
			name:   "standing exclusions",
			modify: func(b *Body) { b.StandingExclusions = b.StandingExclusions[:1] },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := validBody(pub)
			tt.modify(&body)
			cert := signCoverageCertBodyUnchecked(t, body, pub, priv)
			_, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
			if err == nil {
				t.Fatalf("trusted signature over noncanonical %s field must fail closed", tt.name)
			}
		})
	}
}

func TestVerify_InvalidBodyMismatchLinesDoNotEchoUnsafeBodyStrings(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)
	body.Agent = "agent-a\nSessions covered: 999999"
	body.TotalReceipts++
	body.Boundary = DefaultBoundary() + "\nSignature: valid"
	body.StandingExclusions = append(body.StandingExclusions, "forged\nSigner: TRUSTED")
	cert := signCoverageCertBodyUnchecked(t, body, pub, priv)

	result, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err == nil {
		t.Fatal("expected invalid body to fail closed")
	}
	got := strings.Join(result.Lines, "\n")
	for _, unsafe := range []string{"999999", "Boundary:", "Exclusion:", "Agent:", "forged"} {
		if strings.Contains(got, unsafe) {
			t.Fatalf("invalid-body lines echoed unsafe body string %q: %q", unsafe, got)
		}
	}
	if !strings.Contains(got, "Body: INVALID") {
		t.Fatalf("invalid-body lines = %q, want invalid body diagnostic", got)
	}
	if !strings.Contains(got, "MISMATCH:") {
		t.Fatalf("invalid-body lines = %q, want numeric mismatch diagnostic", got)
	}
}

func TestVerify_WindowLinePreservesFractionalSeconds(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)
	body.WindowStart = time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC)
	body.WindowEnd = time.Date(2026, 1, 1, 0, 0, 1, 987654321, time.UTC)
	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	result, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got := strings.Join(result.Lines, "\n")
	if !strings.Contains(got, "2026-01-01T00:00:00.123456789Z") ||
		!strings.Contains(got, "2026-01-01T00:00:01.987654321Z") {
		t.Fatalf("window line lost fractional seconds: %q", got)
	}
}

func TestVerify_LinesEscapeConfusableAgentIdentifier(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)
	body.Agent = "agent-\u0430" // Cyrillic small a, visually confusable with ASCII "a".
	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got := strings.Join(result.Lines, "\n")
	if strings.Contains(got, "\u0430") {
		t.Fatalf("verify lines rendered raw confusable rune: %q", got)
	}
	if !strings.Contains(got, `Agent: agent-\u0430`) {
		t.Fatalf("verify lines = %q, want escaped confusable agent", got)
	}
}

func TestVerify_ErrorsEscapeConfusableSignedValues(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	body := validBody(pub)
	body.Sessions[0].CompletenessStatus = "LIM\u0406TED" // Cyrillic Byelorussian-Ukrainian I.
	cert := signCoverageCertBodyUnchecked(t, body, pub, priv)

	_, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err == nil {
		t.Fatal("expected invalid completeness status to fail closed")
	}
	if strings.Contains(err.Error(), "\u0406") {
		t.Fatalf("error rendered raw confusable rune: %q", err.Error())
	}
	if !strings.Contains(err.Error(), `LIM\u0406TED`) {
		t.Fatalf("error = %q, want escaped confusable status", err.Error())
	}
}

func TestVerify_RejectsKnownCoverageCertificateOverclaimVectors(t *testing.T) {
	t.Parallel()
	pub, priv := genTestKey(t)
	otherPub, otherPriv := genTestKey(t)
	trusted := map[string]struct{}{hex.EncodeToString(pub): {}}

	tests := []struct {
		name string
		cert func(t *testing.T) Certificate
	}{
		{
			name: "1 missing mandatory standing exclusions",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.StandingExclusions = []string{standingExclusionMediated}
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "2 body signer key not bound to envelope signer",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.TrustedSignerKey = hex.EncodeToString(otherPub)
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "3 aggregate inflation via duplicate session IDs",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				dup := body.Sessions[0]
				body.Sessions = []SessionCoverage{body.Sessions[0], dup, body.Sessions[1]}
				body.TotalReceipts += dup.ReceiptCount
				body.SessionsCovered++
				body.ChainsIntact++
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "4 aggregate inflation via NFC-variant session IDs",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Sessions = []SessionCoverage{
					{
						ID:                 "cafe\u0301",
						ReceiptCount:       1,
						ChainIntact:        true,
						Anchored:           anchorLocal,
						CompletenessStatus: completenessLimited,
						CompletenessReason: reasonBoundedClosed,
					},
					{
						ID:                 "café",
						ReceiptCount:       1,
						ChainIntact:        true,
						Anchored:           anchorLocal,
						CompletenessStatus: completenessLimited,
						CompletenessReason: reasonBoundedClosed,
					},
				}
				body.TotalReceipts = 2
				body.ChainGaps = 0
				body.SessionsCovered = 2
				body.ChainsIntact = 2
				body.ChainsBroken = 0
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "5 free-text anchored overclaim",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Sessions[0].Anchored = "external witness 100% covered"
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "5b agent line injection overclaim",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Agent = "agent-a\nSessions covered: 999999\nTotal receipts: 999999"
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "6 free-text falsely-green completeness status",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Sessions[0].CompletenessStatus = "COMPLETE"
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "7 invalid signature",
			cert: func(t *testing.T) Certificate {
				cert, err := Sign(validBody(pub), priv)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				cert.Signature = strings.Repeat("00", ed25519.SignatureSize)
				return cert
			},
		},
		{
			name: "7 untrusted signer",
			cert: func(t *testing.T) Certificate {
				cert, err := Sign(validBody(otherPub), otherPriv)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				return cert
			},
		},
		{
			name: "7 aggregate mismatch",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.TotalReceipts++
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "8 boundary claims beyond listed sessions",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Boundary = "Coverage of mediated egress inside the declared Pipelock boundary for listed and unlisted sessions"
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "9 boundary substring padding",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Boundary = "Coverage of mediated egress inside the declared Pipelock boundary and unmediated egress outside it"
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "10 completeness enum semantic mismatch",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Sessions[0].CompletenessStatus = completenessLimited
				body.Sessions[0].CompletenessReason = reasonChainBroken
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "11 impossible positive-receipt zero-width window",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.WindowEnd = body.WindowStart
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
		{
			name: "12 no_receipts with positive receipt count",
			cert: func(t *testing.T) Certificate {
				body := validBody(pub)
				body.Sessions[0].CompletenessStatus = completenessUnverified
				body.Sessions[0].CompletenessReason = reasonNoReceipts
				return signCoverageCertBodyUnchecked(t, body, pub, priv)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Verify(tt.cert(t), trusted)
			if err == nil {
				t.Fatal("known over-claim vector verified successfully")
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
