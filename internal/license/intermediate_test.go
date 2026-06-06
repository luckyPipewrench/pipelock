// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const (
	testSerial    = "int-2026-001"
	testWrongAlg  = "rsa"
	testWrongPurp = "code-signing"
)

// testIntermediate signs a well-formed intermediate certificate with rootPriv
// certifying intPub, valid over [notBefore, notAfter], and returns both the
// parsed cert and its wire bytes.
func testIntermediate(t *testing.T, rootPriv ed25519.PrivateKey, intPub ed25519.PublicKey, notBefore, notAfter time.Time) (Intermediate, []byte) {
	t.Helper()
	cert, err := SignIntermediate(IntermediatePayload{
		Serial:    testSerial,
		Purpose:   PurposeLicenseSigning,
		Algorithm: AlgorithmEd25519,
		PublicKey: hex.EncodeToString(intPub),
		NotBefore: notBefore.Unix(),
		NotAfter:  notAfter.Unix(),
		IssuedAt:  notBefore.Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}
	data, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal intermediate: %v", err)
	}
	return cert, data
}

// rawIntermediateWire builds a root-signed intermediate wire blob WITHOUT going
// through SignIntermediate's validation, so negative tests can construct certs
// with pinned-field violations and confirm ParseAndVerifyIntermediate enforces
// them independently (defense in depth: the verifier never trusts that the
// signer validated).
func rawIntermediateWire(t *testing.T, rootPriv ed25519.PrivateKey, payload IntermediatePayload) []byte {
	t.Helper()
	if payload.Version == 0 {
		payload.Version = IntermediateVersion
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := ed25519.Sign(rootPriv, pb)
	data, err := json.Marshal(intermediateWire{
		Payload:   base64.RawURLEncoding.EncodeToString(pb),
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	return data
}

// testIntermediateCRL signs a CRL revoking one intermediate serial.
func testIntermediateCRL(t *testing.T, priv ed25519.PrivateKey, now time.Time, revokedSerial string) CRL {
	t.Helper()
	crl, err := SignCRL(CRLPayload{
		Version:   CRLVersion,
		IssuedAt:  now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(),
		RevokedIntermediates: []RevokedIntermediate{{
			Serial:    revokedSerial,
			Reason:    "key_rotation",
			RevokedAt: now.Add(-time.Hour).Unix(),
		}},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func validIntermediatePayload(intPub ed25519.PublicKey, now time.Time) IntermediatePayload {
	return IntermediatePayload{
		Serial:    testSerial,
		Purpose:   PurposeLicenseSigning,
		Algorithm: AlgorithmEd25519,
		PublicKey: hex.EncodeToString(intPub),
		NotBefore: now.Add(-time.Hour).Unix(),
		NotAfter:  now.Add(90 * 24 * time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Hour).Unix(),
	}
}

func testLicenseToken(t *testing.T, signer ed25519.PrivateKey, id string, now time.Time) string {
	t.Helper()
	token, err := Issue(License{
		ID:        id,
		Email:     "customer@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Features:  []string{FeatureFleet},
	}, signer)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

func TestSignAndParseIntermediate_RoundTrip(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	cert, data := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if cert.Serial() != testSerial {
		t.Fatalf("Serial() = %q, want %q", cert.Serial(), testSerial)
	}

	got, err := ParseAndVerifyIntermediate(data, rootPub, now)
	if err != nil {
		t.Fatalf("ParseAndVerifyIntermediate: %v", err)
	}
	if !got.PublicKey().Equal(intPub) {
		t.Fatal("parsed intermediate public key does not match signed key")
	}
	exposed := got.PublicKey()
	exposed[0] ^= 0xff
	if !got.PublicKey().Equal(intPub) {
		t.Fatal("PublicKey() returned mutable internal key storage")
	}
	if got.Serial() != testSerial {
		t.Fatalf("parsed Serial() = %q, want %q", got.Serial(), testSerial)
	}
}

func TestParseAndVerifyIntermediate_WrongRootRejected(t *testing.T) {
	_, rootPriv := testKeyPair(t)
	wrongPub, _ := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	_, data := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	if _, err := ParseAndVerifyIntermediate(data, wrongPub, now); err == nil {
		t.Fatal("expected error verifying intermediate against wrong root key")
	}
}

func TestParseAndVerifyIntermediate_TamperedRejected(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	_, data := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	// Flip the payload by re-encoding a different serial under the same signature.
	var wire intermediateWire
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(wire.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var p IntermediatePayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		t.Fatal(err)
	}
	p.Serial = "int-tampered"
	tamperedPayload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	wire.Payload = base64.RawURLEncoding.EncodeToString(tamperedPayload)
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseAndVerifyIntermediate(tampered, rootPub, now); err == nil {
		t.Fatal("expected error verifying tampered intermediate")
	}
}

func TestParseAndVerifyIntermediate_ValidityWindow(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantErr   error
	}{
		{"expired", now.Add(-48 * time.Hour), now.Add(-time.Hour), ErrIntermediateExpired},
		{"not-yet-valid", now.Add(time.Hour), now.Add(48 * time.Hour), ErrIntermediateNotYetValid},
		{"current", now.Add(-time.Hour), now.Add(48 * time.Hour), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, data := testIntermediate(t, rootPriv, intPub, tc.notBefore, tc.notAfter)
			_, err := ParseAndVerifyIntermediate(data, rootPub, now)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ParseAndVerifyIntermediate: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseAndVerifyIntermediate_PinnedFields(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	tests := []struct {
		name    string
		mutate  func(p *IntermediatePayload)
		wantErr error
	}{
		{
			name:    "wrong-purpose",
			mutate:  func(p *IntermediatePayload) { p.Purpose = testWrongPurp },
			wantErr: ErrIntermediatePurpose,
		},
		{
			name:    "wrong-algorithm",
			mutate:  func(p *IntermediatePayload) { p.Algorithm = testWrongAlg },
			wantErr: ErrIntermediateAlgorithm,
		},
		{
			name:    "empty-serial",
			mutate:  func(p *IntermediatePayload) { p.Serial = "" },
			wantErr: ErrIntermediateMalformed,
		},
		{
			name:    "missing-issued-at",
			mutate:  func(p *IntermediatePayload) { p.IssuedAt = 0 },
			wantErr: ErrIntermediateMalformed,
		},
		{
			name:    "missing-not-before",
			mutate:  func(p *IntermediatePayload) { p.NotBefore = 0 },
			wantErr: ErrIntermediateMalformed,
		},
		{
			name:    "missing-not-after",
			mutate:  func(p *IntermediatePayload) { p.NotAfter = 0 },
			wantErr: ErrIntermediateMalformed,
		},
		{
			name:    "not-after-before-not-before",
			mutate:  func(p *IntermediatePayload) { p.NotAfter = p.NotBefore - 1 },
			wantErr: ErrIntermediateMalformed,
		},
		{
			name: "issued-at-after-not-after",
			mutate: func(p *IntermediatePayload) {
				p.IssuedAt = p.NotAfter + 1
			},
			wantErr: ErrIntermediateMalformed,
		},
		{
			name: "validity-window-too-long",
			mutate: func(p *IntermediatePayload) {
				p.NotAfter = p.NotBefore + int64((500 * 24 * time.Hour).Seconds())
			},
			wantErr: ErrIntermediateMalformed,
		},
		{
			name:    "bad-pubkey-hex",
			mutate:  func(p *IntermediatePayload) { p.PublicKey = "nothex!!" },
			wantErr: ErrIntermediateMalformed,
		},
		{
			name:    "wrong-pubkey-size",
			mutate:  func(p *IntermediatePayload) { p.PublicKey = hex.EncodeToString([]byte("short")) },
			wantErr: ErrIntermediateMalformed,
		},
		{
			name:    "unsupported-version",
			mutate:  func(p *IntermediatePayload) { p.Version = 99 },
			wantErr: ErrIntermediateMalformed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validIntermediatePayload(intPub, now)
			tc.mutate(&p)
			data := rawIntermediateWire(t, rootPriv, p)
			_, err := ParseAndVerifyIntermediate(data, rootPub, now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestSignIntermediate_RejectsBadPayload(t *testing.T) {
	_, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	base := validIntermediatePayload(intPub, now)

	tests := []struct {
		name   string
		mutate func(p *IntermediatePayload)
	}{
		{"wrong-purpose", func(p *IntermediatePayload) { p.Purpose = testWrongPurp }},
		{"wrong-algorithm", func(p *IntermediatePayload) { p.Algorithm = testWrongAlg }},
		{"empty-serial", func(p *IntermediatePayload) { p.Serial = "" }},
		{"naf-before-nbf", func(p *IntermediatePayload) { p.NotAfter = p.NotBefore - 1 }},
		{"validity-too-long", func(p *IntermediatePayload) { p.NotAfter = p.NotBefore + int64((500 * 24 * time.Hour).Seconds()) }},
		{"bad-pubkey", func(p *IntermediatePayload) { p.PublicKey = "nothex" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			if _, err := SignIntermediate(p, rootPriv); err == nil {
				t.Fatal("expected SignIntermediate to reject invalid payload")
			}
		})
	}

	t.Run("bad-root-key-size", func(t *testing.T) {
		if _, err := SignIntermediate(base, ed25519.PrivateKey("short")); err == nil {
			t.Fatal("expected error for invalid root private key size")
		}
	})
}

func TestVerifyChain_IntermediateSignedToken(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	now := time.Now().UTC()

	cert, _ := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	token := testLicenseToken(t, intPriv, "lic_int_signed", now)

	lic, err := VerifyChain(token, &cert, rootPub, nil, now)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if lic.ID != "lic_int_signed" {
		t.Fatalf("lic.ID = %q, want lic_int_signed", lic.ID)
	}
	if !lic.HasFeature(FeatureFleet) {
		t.Fatal("expected fleet feature on chain-verified license")
	}
}

func TestVerifyChain_LegacyRootTokenFallback(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	// Token signed directly by ROOT (legacy), verified with a valid intermediate
	// configured: the chain must fall back to direct-root verification.
	cert, _ := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	token := testLicenseToken(t, rootPriv, "lic_legacy_root", now)

	lic, err := VerifyChain(token, &cert, rootPub, nil, now)
	if err != nil {
		t.Fatalf("VerifyChain legacy fallback: %v", err)
	}
	if lic.ID != "lic_legacy_root" {
		t.Fatalf("lic.ID = %q, want lic_legacy_root", lic.ID)
	}
}

func TestVerifyChain_NilIntermediateIsDirectRoot(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	now := time.Now().UTC()

	token := testLicenseToken(t, rootPriv, "lic_direct", now)
	lic, err := VerifyChain(token, nil, rootPub, nil, now)
	if err != nil {
		t.Fatalf("VerifyChain nil intermediate: %v", err)
	}
	if lic.ID != "lic_direct" {
		t.Fatalf("lic.ID = %q, want lic_direct", lic.ID)
	}

	// A token signed by some other key must NOT verify under direct-root.
	_, otherPriv := testKeyPair(t)
	bad := testLicenseToken(t, otherPriv, "lic_forged", now)
	if _, err := VerifyChain(bad, nil, rootPub, nil, now); err == nil {
		t.Fatal("expected forged token to fail direct-root verification")
	}
}

func TestVerifyChain_RevokedIntermediateFailsClosed(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	now := time.Now().UTC()

	cert, _ := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	token := testLicenseToken(t, intPriv, "lic_after_revoke", now)
	crl := testIntermediateCRL(t, rootPriv, now, testSerial)

	_, err := VerifyChain(token, &cert, rootPub, &crl, now)
	if !errors.Is(err, ErrIntermediateRevoked) {
		t.Fatalf("error = %v, want ErrIntermediateRevoked", err)
	}
}

func TestVerifyChain_ExpiredIntermediateFailsClosed(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	now := time.Now().UTC()

	// Cert was valid when parsed but the verification `now` is past NotAfter.
	cert, _ := testIntermediate(t, rootPriv, intPub, now.Add(-90*24*time.Hour), now.Add(-time.Hour))
	token := testLicenseToken(t, intPriv, "lic_expired_chain", now)

	_, err := VerifyChain(token, &cert, rootPub, nil, now)
	if !errors.Is(err, ErrIntermediateExpired) {
		t.Fatalf("error = %v, want ErrIntermediateExpired", err)
	}
}

func TestVerifyChain_ReverifiesIntermediateObject(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()

	validCert, _ := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	legacyToken := testLicenseToken(t, rootPriv, "lic_legacy_root", now)

	t.Run("missing-signature-fails-closed-before-legacy-fallback", func(t *testing.T) {
		handBuilt := Intermediate{Payload: validCert.Payload}
		if _, err := VerifyChain(legacyToken, &handBuilt, rootPub, nil, now); !errors.Is(err, ErrIntermediateMalformed) {
			t.Fatalf("error = %v, want ErrIntermediateMalformed", err)
		}
	})

	t.Run("tampered-payload-cache-fails-closed-before-legacy-fallback", func(t *testing.T) {
		tampered := validCert
		tampered.Payload.Serial = "tampered-public-field"
		tampered.payload = []byte(`{"version":1,"serial":"tampered-signed-bytes"}`)
		if _, err := VerifyChain(legacyToken, &tampered, rootPub, nil, now); !errors.Is(err, ErrIntermediateSignature) {
			t.Fatalf("error = %v, want ErrIntermediateSignature", err)
		}
	})
}

func TestVerifyTokenWithOptionalIntermediate(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	now := time.Now().UTC()

	_, validCert := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	_, expiredCert := testIntermediate(t, rootPriv, intPub, now.Add(-90*24*time.Hour), now.Add(-time.Hour))
	intToken := testLicenseToken(t, intPriv, "lic_int", now)
	rootToken := testLicenseToken(t, rootPriv, "lic_root", now)

	t.Run("not-configured-legacy-only", func(t *testing.T) {
		lic, err := VerifyTokenWithOptionalIntermediate(rootToken, nil, rootPub, nil, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lic.ID != "lic_root" {
			t.Fatalf("lic.ID = %q, want lic_root", lic.ID)
		}
		// Intermediate-signed token has no valid path without a configured cert.
		if _, err := VerifyTokenWithOptionalIntermediate(intToken, nil, rootPub, nil, now); err == nil {
			t.Fatal("expected intermediate-signed token to fail with no cert configured")
		}
	})

	t.Run("valid-cert-intermediate-token", func(t *testing.T) {
		lic, err := VerifyTokenWithOptionalIntermediate(intToken, validCert, rootPub, nil, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lic.ID != "lic_int" {
			t.Fatalf("lic.ID = %q, want lic_int", lic.ID)
		}
	})

	t.Run("valid-cert-legacy-token-still-verifies", func(t *testing.T) {
		lic, err := VerifyTokenWithOptionalIntermediate(rootToken, validCert, rootPub, nil, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lic.ID != "lic_root" {
			t.Fatalf("lic.ID = %q, want lic_root", lic.ID)
		}
	})

	t.Run("configured-but-expired-fails-closed-even-for-legacy", func(t *testing.T) {
		// Doctrine: a configured-but-invalid cert blocks ALL verification,
		// including legacy root-signed tokens. Operator reverts by removing the
		// cert config, never by silently falling through to root.
		if _, err := VerifyTokenWithOptionalIntermediate(rootToken, expiredCert, rootPub, nil, now); err == nil {
			t.Fatal("expected fail-closed on configured-but-expired cert")
		}
		if _, err := VerifyTokenWithOptionalIntermediate(intToken, expiredCert, rootPub, nil, now); err == nil {
			t.Fatal("expected fail-closed on configured-but-expired cert for intermediate token")
		}
	})

	t.Run("configured-but-revoked-fails-closed", func(t *testing.T) {
		crl := testIntermediateCRL(t, rootPriv, now, testSerial)
		if _, err := VerifyTokenWithOptionalIntermediate(intToken, validCert, rootPub, &crl, now); !errors.Is(err, ErrIntermediateRevoked) {
			t.Fatalf("error = %v, want ErrIntermediateRevoked", err)
		}
		// Even a legacy root token is blocked while a revoked cert is configured.
		if _, err := VerifyTokenWithOptionalIntermediate(rootToken, validCert, rootPub, &crl, now); !errors.Is(err, ErrIntermediateRevoked) {
			t.Fatalf("legacy error = %v, want ErrIntermediateRevoked", err)
		}
	})

	t.Run("configured-but-garbage-fails-closed", func(t *testing.T) {
		if _, err := VerifyTokenWithOptionalIntermediate(rootToken, []byte("{not a cert}"), rootPub, nil, now); err == nil {
			t.Fatal("expected fail-closed on garbage cert bytes")
		}
	})
}

func TestParseAndVerifyIntermediate_MalformedInputs(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()
	_, good := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(48*time.Hour))

	goodSig := func() string {
		var w intermediateWire
		_ = json.Unmarshal(good, &w)
		return w.Signature
	}()
	goodPayload := func() string {
		var w intermediateWire
		_ = json.Unmarshal(good, &w)
		return w.Payload
	}()

	tests := []struct {
		name   string
		rootPK ed25519.PublicKey
		data   []byte
	}{
		{"wrong-root-pubkey-size", ed25519.PublicKey("short"), good},
		{"oversized", rootPub, make([]byte, maxIntermediateBytes+1)},
		{"not-json", rootPub, []byte("not json")},
		{"bad-base64-payload", rootPub, mustWire(t, "!!notb64", goodSig)},
		{"bad-base64-signature", rootPub, mustWire(t, goodPayload, "!!notb64")},
		{"wrong-signature-size", rootPub, mustWire(t, goodPayload, base64.RawURLEncoding.EncodeToString([]byte("short")))},
		{"payload-not-json", rootPub, mustWire(t, base64.RawURLEncoding.EncodeToString([]byte("xx")), goodSig)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAndVerifyIntermediate(tc.data, tc.rootPK, now); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func mustWire(t *testing.T, payload, sig string) []byte {
	t.Helper()
	data, err := json.Marshal(intermediateWire{Payload: payload, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestIntermediate_MarshalJSONFallback(t *testing.T) {
	intPub, _ := testKeyPair(t)
	now := time.Now().UTC()
	// An Intermediate with no cached canonical bytes (e.g. hand-built) must
	// re-marshal Payload on the fly.
	im := Intermediate{
		Payload:   validIntermediatePayload(intPub, now),
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	data, err := json.Marshal(im)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var w intermediateWire
	if err := json.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	if w.Payload == "" {
		t.Fatal("expected payload to be re-marshaled from Payload struct")
	}
}

func TestVerifyChain_SurfacesDefinitiveErrors(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	now := time.Now().UTC()
	cert, _ := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	t.Run("intermediate-signed-but-license-expired", func(t *testing.T) {
		expiredTok, err := Issue(License{
			ID:        "lic_exp",
			Email:     "customer@example.com",
			IssuedAt:  now.Add(-48 * time.Hour).Unix(),
			ExpiresAt: now.Add(-time.Hour).Unix(),
			Features:  []string{FeatureFleet},
		}, intPriv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyChain(expiredTok, &cert, rootPub, nil, now); !errors.Is(err, ErrLicenseExpired) {
			t.Fatalf("error = %v, want ErrLicenseExpired", err)
		}
	})

	t.Run("legacy-root-token-expired-surfaced-via-fallback", func(t *testing.T) {
		expiredRoot, err := Issue(License{
			ID:        "lic_root_exp",
			Email:     "customer@example.com",
			IssuedAt:  now.Add(-48 * time.Hour).Unix(),
			ExpiresAt: now.Add(-time.Hour).Unix(),
			Features:  []string{FeatureFleet},
		}, rootPriv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyChain(expiredRoot, &cert, rootPub, nil, now); !errors.Is(err, ErrLicenseExpired) {
			t.Fatalf("error = %v, want ErrLicenseExpired", err)
		}
	})

	t.Run("forged-token-fails-both-paths", func(t *testing.T) {
		_, otherPriv := testKeyPair(t)
		forged := testLicenseToken(t, otherPriv, "lic_forged", now)
		if _, err := VerifyChain(forged, &cert, rootPub, nil, now); err == nil {
			t.Fatal("expected forged token to fail")
		}
	})
}

func TestCheckIntermediate(t *testing.T) {
	_, rootPriv := testKeyPair(t)
	now := time.Now().UTC()

	withReason := testIntermediateCRL(t, rootPriv, now, testSerial)
	if err := withReason.CheckIntermediate(testSerial); !errors.Is(err, ErrIntermediateRevoked) {
		t.Fatalf("revoked-with-reason: %v", err)
	}
	if err := withReason.CheckIntermediate("other-serial"); err != nil {
		t.Fatalf("unrevoked serial should pass: %v", err)
	}
	if err := withReason.CheckIntermediate(""); !errors.Is(err, ErrIntermediateRevoked) {
		t.Fatalf("empty serial must fail closed: %v", err)
	}

	// Revoked with empty reason hits the no-reason branch.
	noReason, err := SignCRL(CRLPayload{
		Version:   CRLVersion,
		IssuedAt:  now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(),
		RevokedIntermediates: []RevokedIntermediate{{
			Serial:    testSerial,
			RevokedAt: now.Add(-time.Hour).Unix(),
		}},
	}, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := noReason.CheckIntermediate(testSerial); !errors.Is(err, ErrIntermediateRevoked) {
		t.Fatalf("revoked-no-reason: %v", err)
	}

	// Linear-scan fallback when the index is absent (defensive parity path).
	noIndex := CRL{Payload: CRLPayload{RevokedIntermediates: []RevokedIntermediate{{Serial: testSerial, RevokedAt: 1}}}}
	if _, ok := noIndex.RevocationForIntermediate(testSerial); !ok {
		t.Fatal("expected linear-scan hit without index")
	}
	if _, ok := noIndex.RevocationForIntermediate("missing"); ok {
		t.Fatal("expected linear-scan miss without index")
	}
}

func TestSignCRL_RejectsBadIntermediateList(t *testing.T) {
	_, rootPriv := testKeyPair(t)
	now := time.Now().UTC()
	base := CRLPayload{
		Version:   CRLVersion,
		IssuedAt:  now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(),
	}
	tests := []struct {
		name string
		ints []RevokedIntermediate
	}{
		{"empty-serial", []RevokedIntermediate{{Serial: "", RevokedAt: 1}}},
		{"missing-revoked-at", []RevokedIntermediate{{Serial: "s1"}}},
		{"duplicate-serial", []RevokedIntermediate{{Serial: "s1", RevokedAt: 1}, {Serial: "s1", RevokedAt: 2}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.RevokedIntermediates = tc.ints
			if _, err := SignCRL(p, rootPriv); err == nil {
				t.Fatal("expected SignCRL to reject invalid intermediate list")
			}
		})
	}
}

func TestVerifyChain_HandBuiltIntermediateRevalidated(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	now := time.Now().UTC()
	p := validIntermediatePayload(intPub, now)
	p.Version = IntermediateVersion
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(rootPriv, pb)
	token := testLicenseToken(t, intPriv, "lic_handbuilt", now)

	// Hand-built Intermediate with NO cached canonical bytes: VerifyChain must
	// re-marshal Payload, re-verify against root, and accept it.
	im := Intermediate{
		Payload:   p,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	lic, err := VerifyChain(token, &im, rootPub, nil, now)
	if err != nil {
		t.Fatalf("VerifyChain hand-built: %v", err)
	}
	if lic.ID != "lic_handbuilt" {
		t.Fatalf("lic.ID = %q, want lic_handbuilt", lic.ID)
	}

	// A hand-built Intermediate whose Payload was mutated after signing must
	// fail closed: the re-marshal no longer matches the root signature.
	tampered := Intermediate{Payload: p, Signature: im.Signature}
	tampered.Payload.Serial = "int-tampered"
	if _, err := VerifyChain(token, &tampered, rootPub, nil, now); !errors.Is(err, ErrIntermediateSignature) {
		t.Fatalf("tampered hand-built error = %v, want ErrIntermediateSignature", err)
	}
}

func TestParseAndVerifyIntermediate_ValidSigNonJSONPayload(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	now := time.Now().UTC()
	// A payload the root genuinely signed but that is not valid JSON: the
	// signature passes, then the structural parse must fail closed.
	raw := []byte("root-signed but not json")
	sig := ed25519.Sign(rootPriv, raw)
	data, err := json.Marshal(intermediateWire{
		Payload:   base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndVerifyIntermediate(data, rootPub, now); !errors.Is(err, ErrIntermediateMalformed) {
		t.Fatalf("error = %v, want ErrIntermediateMalformed", err)
	}
}

func TestVerifyTokenWithOptionalIntermediate_LicenseRevocationStillApplies(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	now := time.Now().UTC()

	_, validCert := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	token := testLicenseToken(t, intPriv, "lic_revoked_id", now)
	// CRL revokes the LICENSE id (not the intermediate). Chain must still reject.
	crl := testCRL(t, rootPriv, now, "lic_revoked_id")

	if _, err := VerifyTokenWithOptionalIntermediate(token, validCert, rootPub, &crl, now); !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("error = %v, want ErrLicenseRevoked", err)
	}
}
