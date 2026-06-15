// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// signedCRLWire signs a CRL payload and returns its on-disk {payload,signature}
// wire bytes — the exact form ParseAndVerifyCRLSignatureOnly consumes.
func signedCRLWire(t *testing.T, priv ed25519.PrivateKey, payload CRLPayload) []byte {
	t.Helper()
	crl, err := SignCRL(payload, priv)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("marshal CRL: %v", err)
	}
	return data
}

func TestParseAndVerifyCRLSignatureOnly(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now()

	t.Run("accepts_valid_unexpired_crl", func(t *testing.T) {
		data := signedCRLWire(t, priv, CRLPayload{
			Version:    CRLVersion,
			Generation: 7,
			IssuedAt:   now.Add(-time.Hour).Unix(),
			ExpiresAt:  now.Add(time.Hour).Unix(),
		})
		crl, err := ParseAndVerifyCRLSignatureOnly(data, pub)
		if err != nil {
			t.Fatalf("valid CRL must parse: %v", err)
		}
		if crl.Payload.Generation != 7 {
			t.Fatalf("generation = %d, want 7", crl.Payload.Generation)
		}
	})

	t.Run("accepts_EXPIRED_crl (the whole point — recovery on a historical CRL)", func(t *testing.T) {
		// Sign with a future expiry so SignCRL accepts it, then re-issue the wire
		// bytes with an expiry already in the past by editing the payload before
		// signing manually. Simpler: sign a CRL whose expiry is in the past is
		// rejected by SignCRL's own validation, so craft the wire blob directly.
		past := now.Add(-48 * time.Hour)
		payload := CRLPayload{
			Version:    CRLVersion,
			Generation: 3,
			IssuedAt:   past.Add(-time.Hour).Unix(),
			ExpiresAt:  past.Unix(), // already expired
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		sig := ed25519.Sign(priv, payloadBytes)
		wire := struct {
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		}{
			Payload:   base64.RawURLEncoding.EncodeToString(payloadBytes),
			Signature: base64.RawURLEncoding.EncodeToString(sig),
		}
		data, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("marshal wire: %v", err)
		}

		// ParseAndVerifyCRL (the trust path) MUST reject the expired CRL...
		if _, err := ParseAndVerifyCRL(data, pub, now); err == nil {
			t.Fatal("ParseAndVerifyCRL must reject an expired CRL")
		}
		// ...but the signature-only path accepts it: its job is to read the
		// generation off a historical, possibly-expired published CRL.
		crl, err := ParseAndVerifyCRLSignatureOnly(data, pub)
		if err != nil {
			t.Fatalf("signature-only path must accept an expired CRL: %v", err)
		}
		if crl.Payload.Generation != 3 {
			t.Fatalf("generation = %d, want 3", crl.Payload.Generation)
		}
	})

	t.Run("rejects_wrong_key", func(t *testing.T) {
		otherPub, _ := testKeyPair(t)
		data := signedCRLWire(t, priv, CRLPayload{
			Version: CRLVersion, Generation: 1,
			IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		})
		if _, err := ParseAndVerifyCRLSignatureOnly(data, otherPub); err == nil {
			t.Fatal("a CRL signed by a different key must be rejected")
		}
	})

	t.Run("rejects_invalid_public_key_size", func(t *testing.T) {
		data := signedCRLWire(t, priv, CRLPayload{
			Version: CRLVersion, Generation: 1,
			IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		})
		if _, err := ParseAndVerifyCRLSignatureOnly(data, ed25519.PublicKey{1, 2, 3}); err == nil {
			t.Fatal("a wrong-size public key must be rejected")
		}
	})

	t.Run("rejects_oversized_input", func(t *testing.T) {
		huge := make([]byte, maxCRLFileSize+1)
		if _, err := ParseAndVerifyCRLSignatureOnly(huge, pub); err == nil {
			t.Fatal("oversized input must be rejected")
		}
	})

	t.Run("rejects_malformed_json", func(t *testing.T) {
		if _, err := ParseAndVerifyCRLSignatureOnly([]byte("{not json"), pub); err == nil {
			t.Fatal("malformed JSON must be rejected")
		}
	})

	t.Run("rejects_bad_base64_payload", func(t *testing.T) {
		data := []byte(`{"payload":"!!!notbase64!!!","signature":"AAAA"}`)
		if _, err := ParseAndVerifyCRLSignatureOnly(data, pub); err == nil {
			t.Fatal("bad base64 payload must be rejected")
		}
	})

	t.Run("rejects_bad_base64_signature", func(t *testing.T) {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"version":1}`))
		data := []byte(`{"payload":"` + payload + `","signature":"!!!notbase64!!!"}`)
		if _, err := ParseAndVerifyCRLSignatureOnly(data, pub); err == nil {
			t.Fatal("bad base64 signature must be rejected")
		}
	})

	t.Run("rejects_wrong_signature_size", func(t *testing.T) {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"version":1}`))
		shortSig := base64.RawURLEncoding.EncodeToString([]byte("tooshort"))
		data := []byte(`{"payload":"` + payload + `","signature":"` + shortSig + `"}`)
		if _, err := ParseAndVerifyCRLSignatureOnly(data, pub); err == nil {
			t.Fatal("a wrong-size signature must be rejected")
		}
	})

	t.Run("rejects_unsupported_version", func(t *testing.T) {
		// Sign a payload whose version is not CRLVersion. SignCRL would normalize
		// version 0 -> CRLVersion, so craft and sign the wire blob directly.
		payloadBytes, err := json.Marshal(CRLPayload{
			Version:    99,
			Generation: 1,
			IssuedAt:   now.Add(-time.Hour).Unix(),
			ExpiresAt:  now.Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		sig := ed25519.Sign(priv, payloadBytes)
		data, err := json.Marshal(struct {
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		}{
			Payload:   base64.RawURLEncoding.EncodeToString(payloadBytes),
			Signature: base64.RawURLEncoding.EncodeToString(sig),
		})
		if err != nil {
			t.Fatalf("marshal wire: %v", err)
		}
		_, err = ParseAndVerifyCRLSignatureOnly(data, pub)
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("unsupported version must be rejected with a version error, got %v", err)
		}
	})
}
