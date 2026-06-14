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
	// Use real time, not a fixed date: testCRL signs via SignCRL, which validates
	// the payload's expiry against time.Now(). A hard-coded date makes the 7-day
	// CRL expire in wall-clock time and time-bombs the test (the sibling CRL tests
	// all use time.Now() for this reason).
	now := time.Now().UTC()
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

func TestCRLUnmarshalJSONBuildsIndex(t *testing.T) {
	_, priv := testKeyPair(t)
	now := time.Now().UTC()
	crl := testCRL(t, priv, now, "lic_unmarshal")
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	var got CRL
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if got.SHA256 == "" {
		t.Fatal("expected digest after unmarshal")
	}
	if revoked, ok := got.RevocationFor("lic_unmarshal"); !ok || revoked.ID != "lic_unmarshal" {
		t.Fatalf("revocation lookup failed: %+v ok=%v", revoked, ok)
	}
}

func TestCRLRevocationForFallbackAndReasonlessError(t *testing.T) {
	crl := CRL{Payload: CRLPayload{Revoked: []RevokedLicense{{
		ID:        "lic_reasonless",
		RevokedAt: time.Now().UTC().Unix(),
	}}}}
	revoked, ok := crl.RevocationFor("lic_reasonless")
	if !ok || revoked.ID != "lic_reasonless" {
		t.Fatalf("RevocationFor = %+v, %v; want fallback match", revoked, ok)
	}
	if _, ok := crl.RevocationFor("lic_missing"); ok {
		t.Fatal("missing license should not be revoked")
	}
	err := crl.CheckLicense(License{ID: "lic_reasonless"})
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("CheckLicense error = %v, want ErrLicenseRevoked", err)
	}
	if strings.Contains(err.Error(), "()") {
		t.Fatalf("reasonless revocation should not render empty reason: %v", err)
	}
}

func TestCRLRejectsMalformedInputs(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()
	valid := testCRL(t, priv, now, "lic_valid")
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var validWire crlWire
	if err := json.Unmarshal(validData, &validWire); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		data []byte
		key  ed25519.PublicKey
	}{
		{name: "bad public key", data: validData, key: ed25519.PublicKey("short")},
		{name: "too large", data: []byte(strings.Repeat("x", maxCRLFileSize+1)), key: pub},
		{name: "bad json", data: []byte("{"), key: pub},
		{name: "bad payload base64", data: []byte(`{"payload":"%%","signature":"` + validWire.Signature + `"}`), key: pub},
		{name: "bad signature base64", data: []byte(`{"payload":"` + validWire.Payload + `","signature":"%%"}`), key: pub},
		{name: "bad signature size", data: []byte(`{"payload":"` + validWire.Payload + `","signature":"` + base64.RawURLEncoding.EncodeToString([]byte("short")) + `"}`), key: pub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseAndVerifyCRL(tt.data, tt.key, now); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateCRLPayloadRejectsInvalidRecords(t *testing.T) {
	now := time.Now().UTC()
	base := CRLPayload{
		Version:   CRLVersion,
		IssuedAt:  now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Revoked: []RevokedLicense{{
			ID:        "lic_ok",
			RevokedAt: now.Add(-time.Hour).Unix(),
		}},
	}
	tests := []struct {
		name   string
		mutate func(*CRLPayload)
	}{
		{name: "version", mutate: func(p *CRLPayload) { p.Version = 99 }},
		{name: "issued", mutate: func(p *CRLPayload) { p.IssuedAt = 0 }},
		{name: "expires", mutate: func(p *CRLPayload) { p.ExpiresAt = 0 }},
		{name: "empty id", mutate: func(p *CRLPayload) { p.Revoked[0].ID = "" }},
		{name: "missing revoked_at", mutate: func(p *CRLPayload) { p.Revoked[0].RevokedAt = 0 }},
		{name: "duplicate", mutate: func(p *CRLPayload) { p.Revoked = append(p.Revoked, p.Revoked[0]) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := base
			payload.Revoked = append([]RevokedLicense(nil), base.Revoked...)
			tt.mutate(&payload)
			if err := validateCRLPayload(payload, now); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadAndVerifyCRLRejectsBadPaths(t *testing.T) {
	pub, _ := testKeyPair(t)
	now := time.Now().UTC()
	dir := t.TempDir()
	large := filepath.Join(dir, "large.json")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxCRLFileSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing.json"), dir, large} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := LoadAndVerifyCRL(path, pub, now); err == nil {
				t.Fatal("expected load error")
			}
		})
	}
}

func TestCRLGenerationRoundTrip(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()

	t.Run("legacy-no-generation-field-is-gen-0", func(t *testing.T) {
		// A CRL signed without a Generation field round-trips as generation 0
		// and verifies (back-compat: legacy CRLs predate the field).
		crl, err := SignCRL(CRLPayload{
			Version:   CRLVersion,
			IssuedAt:  now.Add(-time.Hour).Unix(),
			ExpiresAt: now.Add(24 * time.Hour).Unix(),
		}, priv)
		if err != nil {
			t.Fatalf("SignCRL: %v", err)
		}
		// omitempty: a 0 generation must NOT appear in the signed payload, so a
		// legacy verifier that never knew the field sees byte-identical output.
		if strings.Contains(string(crl.payload), "generation") {
			t.Fatalf("gen-0 payload should omit the generation field: %s", crl.payload)
		}
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseAndVerifyCRL(data, pub, now)
		if err != nil {
			t.Fatalf("ParseAndVerifyCRL: %v", err)
		}
		if got.Payload.Generation != 0 {
			t.Fatalf("generation = %d, want 0", got.Payload.Generation)
		}
	})

	t.Run("generation-survives-sign-verify", func(t *testing.T) {
		const wantGen = 123
		crl, err := SignCRL(CRLPayload{
			Version:    CRLVersion,
			Generation: wantGen,
			IssuedAt:   now.Add(-time.Hour).Unix(),
			ExpiresAt:  now.Add(24 * time.Hour).Unix(),
		}, priv)
		if err != nil {
			t.Fatalf("SignCRL: %v", err)
		}
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseAndVerifyCRL(data, pub, now)
		if err != nil {
			t.Fatalf("ParseAndVerifyCRL: %v", err)
		}
		if got.Payload.Generation != wantGen {
			t.Fatalf("generation = %d, want %d", got.Payload.Generation, wantGen)
		}
	})
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
