// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignParseAndVerifyCRL(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	crl := testCRL(t, priv, now, "lic_revoked")

	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAndVerifyCRL(data, pub, now)
	if err != nil {
		t.Fatalf("ParseAndVerifyCRL: %v", err)
	}
	if _, ok := got.RevocationFor("lic_revoked"); !ok {
		t.Fatal("expected revoked license in CRL")
	}
}

func TestVerifyWithCRLRejectsRevokedLicense(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	lic := License{
		ID:        "lic_revoked",
		Email:     "customer@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Features:  []string{FeatureAgents},
	}
	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	crl := testCRL(t, priv, now, lic.ID)

	_, err = VerifyWithCRL(token, pub, &crl)
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("VerifyWithCRL error = %v, want ErrLicenseRevoked", err)
	}
}

func TestVerifyWithCRLAllowsUnrevokedLicense(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	lic := License{
		ID:        "lic_active",
		Email:     "customer@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Features:  []string{FeatureAgents},
	}
	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	crl := testCRL(t, priv, now, "lic_other")

	got, err := VerifyWithCRL(token, pub, &crl)
	if err != nil {
		t.Fatalf("VerifyWithCRL: %v", err)
	}
	if got.ID != lic.ID {
		t.Errorf("ID = %q, want %q", got.ID, lic.ID)
	}
}

func TestParseAndVerifyCRLRejectsTampering(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	crl := testCRL(t, priv, now, "lic_revoked")
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	var wire crlWire
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(wire.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), "lic_revoked", "lic_active", 1))
	wire.Payload = base64.RawURLEncoding.EncodeToString(payload)
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseAndVerifyCRL(tampered, pub, now)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error, got %v", err)
	}
}

func TestCRLWirePayloadIsBase64AndDigestIsSet(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	crl := testCRL(t, priv, now, "lic_digest")
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "lic_digest") {
		t.Fatalf("wire CRL should carry base64 payload, got %s", string(data))
	}
	verified, err := ParseAndVerifyCRL(data, pub, now)
	if err != nil {
		t.Fatalf("ParseAndVerifyCRL: %v", err)
	}
	if verified.SHA256 == "" {
		t.Fatal("expected CRL SHA256 digest")
	}
}

func TestCRLMarshalPreservesVerifiedPayloadBytes(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	issuedAt := now.Add(-time.Hour).Unix()
	expiresAt := now.Add(24 * time.Hour).Unix()
	payload := []byte(`{"revoked":[{"revoked_at":` +
		strconv.FormatInt(issuedAt, 10) +
		`,"id":"lic_preserve"}],"expires_at":` +
		strconv.FormatInt(expiresAt, 10) +
		`,"issued_at":` +
		strconv.FormatInt(issuedAt, 10) +
		`,"version":1}`)
	sig := ed25519.Sign(priv, payload)
	wire := crlWire{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseAndVerifyCRL(data, pub, now)
	if err != nil {
		t.Fatalf("ParseAndVerifyCRL: %v", err)
	}
	remarshaled, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	var got crlWire
	if err := json.Unmarshal(remarshaled, &got); err != nil {
		t.Fatal(err)
	}
	if got.Payload != wire.Payload {
		t.Fatalf("MarshalJSON changed signed payload bytes\ngot  %s\nwant %s", got.Payload, wire.Payload)
	}
}

func TestParseAndVerifyCRLVerifiesBeforePayloadValidation(t *testing.T) {
	pub, _ := testKeyPair(t)
	now := time.Now().UTC()
	issuedAt := now.Add(-time.Hour).Unix()
	expiresAt := now.Add(24 * time.Hour).Unix()
	payload := []byte(`{"version":1,"issued_at":` +
		strconv.FormatInt(issuedAt, 10) +
		`,"expires_at":` +
		strconv.FormatInt(expiresAt, 10) +
		`,"revoked":[{"id":"lic_dup","revoked_at":` +
		strconv.FormatInt(issuedAt, 10) +
		`},{"id":"lic_dup","revoked_at":` +
		strconv.FormatInt(issuedAt, 10) +
		`}]}`)
	wire := crlWire{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseAndVerifyCRL(data, pub, now)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error before payload validation, got %v", err)
	}
}

func TestSignCRLRejectsInvertedTimestamps(t *testing.T) {
	_, priv := testKeyPair(t)
	now := time.Now().UTC()
	_, err := SignCRL(CRLPayload{
		Version:   CRLVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(-time.Hour).Unix(),
	}, priv)
	if err == nil || !strings.Contains(err.Error(), "expires_at") {
		t.Fatalf("expected expires_at validation error, got %v", err)
	}
}

func TestParseAndVerifyCRLRejectsExpiredList(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	payload := CRLPayload{
		Version:   CRLVersion,
		IssuedAt:  now.Add(-48 * time.Hour).Unix(),
		ExpiresAt: now.Add(-24 * time.Hour).Unix(),
		Revoked: []RevokedLicense{{
			ID:        "lic_revoked",
			RevokedAt: now.Add(-48 * time.Hour).Unix(),
		}},
	}
	payloadData, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	crl := CRL{
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payloadData)),
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseAndVerifyCRL(data, pub, now)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired CRL error, got %v", err)
	}
}

func TestLoadAndVerifyCRL(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	crl := testCRL(t, priv, now, "lic_revoked")
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "crl.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAndVerifyCRL(path, pub, now); err != nil {
		t.Fatalf("LoadAndVerifyCRL: %v", err)
	}
}

func testCRL(t *testing.T, priv ed25519.PrivateKey, now time.Time, revokedID string) CRL {
	t.Helper()
	crl, err := SignCRL(CRLPayload{
		Version:   CRLVersion,
		IssuedAt:  now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(),
		Revoked: []RevokedLicense{{
			ID:        revokedID,
			Reason:    "subscription_ended",
			RevokedAt: now.Add(-time.Hour).Unix(),
		}},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}
