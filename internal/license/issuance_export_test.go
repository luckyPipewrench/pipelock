// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mustToken(t *testing.T, priv ed25519.PrivateKey, lic License) string {
	t.Helper()
	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return token
}

func TestSignAndParseIssuanceExport_RoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	now := time.Now()
	lic := License{
		ID:             "lic_abc123",
		Email:          "buyer@vendor.example",
		Org:            "Vendor Example",
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(365 * 24 * time.Hour).Unix(),
		Features:       []string{FeatureAgents},
		Tier:           "pro",
		SubscriptionID: "sub_xyz",
	}
	token := mustToken(t, priv, lic)

	payload := BuildIssuanceExportFromToken(token, lic, `["agents"]`, now)
	export, err := SignIssuanceExport(payload, priv)
	if err != nil {
		t.Fatalf("sign export: %v", err)
	}

	if export.Payload.IssuerKeyID != hex.EncodeToString(pub) {
		t.Errorf("issuer key id = %q, want %q", export.Payload.IssuerKeyID, hex.EncodeToString(pub))
	}
	if export.Payload.TokenSHA256 != TokenSHA256Hex(token) {
		t.Error("token hash mismatch")
	}

	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	got, err := ParseAndVerifyIssuanceExport(data, pub)
	if err != nil {
		t.Fatalf("parse export: %v", err)
	}
	if got.Payload.LicenseID != lic.ID {
		t.Errorf("license id = %q, want %q", got.Payload.LicenseID, lic.ID)
	}
	if got.Payload.SubscriptionID != lic.SubscriptionID {
		t.Errorf("subscription id = %q", got.Payload.SubscriptionID)
	}
	if got.Payload.TokenSHA256 != TokenSHA256Hex(token) {
		t.Error("parsed token hash mismatch")
	}
}

func TestParseIssuanceExport_WrongKeyRejected(t *testing.T) {
	_, priv := mustKeypair(t)
	otherPub, _ := mustKeypair(t)
	now := time.Now()
	lic := License{ID: "lic_1", Email: "a@vendor.example", IssuedAt: now.Unix()}
	token := mustToken(t, priv, lic)
	export, err := SignIssuanceExport(BuildIssuanceExportFromToken(token, lic, "", now), priv)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(export)

	if _, err := ParseAndVerifyIssuanceExport(data, otherPub); err == nil {
		t.Fatal("expected wrong-key verification to fail closed")
	}
}

func TestParseIssuanceExport_TamperedPayloadRejected(t *testing.T) {
	pub, priv := mustKeypair(t)
	now := time.Now()
	lic := License{ID: "lic_1", Email: "a@vendor.example", IssuedAt: now.Unix()}
	token := mustToken(t, priv, lic)
	export, err := SignIssuanceExport(BuildIssuanceExportFromToken(token, lic, "", now), priv)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper: re-encode the wire with a different payload (a swapped license id)
	// but keep the original signature.
	var wire issuanceExportWire
	data, _ := json.Marshal(export)
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	tampered := export.Payload
	tampered.LicenseID = "lic_attacker"
	tamperedBytes, _ := json.Marshal(tampered)
	wire.Payload = base64.RawURLEncoding.EncodeToString(tamperedBytes)
	bad, _ := json.Marshal(wire)

	if _, err := ParseAndVerifyIssuanceExport(bad, pub); err == nil {
		t.Fatal("expected tampered payload to fail closed")
	}
}

func TestParseIssuanceExport_IssuerKeyIDMismatchRejected(t *testing.T) {
	// An export signed by a trusted key but carrying a FORGED issuer_key_id that
	// names a different key must be rejected even though the signature is valid:
	// display/reality divergence.
	pub, priv := mustKeypair(t)
	otherPub, _ := mustKeypair(t)
	now := time.Now()
	lic := License{ID: "lic_1", Email: "a@vendor.example", IssuedAt: now.Unix()}
	token := mustToken(t, priv, lic)

	payload := BuildIssuanceExportFromToken(token, lic, "", now)
	payload.IssuerKeyID = hex.EncodeToString(otherPub) // forge a different signer
	// Sign with priv but keep the forged id (SignIssuanceExport keeps a non-empty id).
	export, err := SignIssuanceExport(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(export)

	if _, err := ParseAndVerifyIssuanceExport(data, pub); err == nil {
		t.Fatal("expected issuer_key_id mismatch to fail closed")
	}
}

func TestSignIssuanceExport_RejectsBadInputs(t *testing.T) {
	_, priv := mustKeypair(t)
	now := time.Now()
	tests := []struct {
		name    string
		payload IssuanceExportPayload
	}{
		{"missing license id", IssuanceExportPayload{Version: 1, TokenSHA256: strings.Repeat("a", 64), IssuedAt: now.Unix()}},
		{"missing issued at", IssuanceExportPayload{Version: 1, LicenseID: "lic_1", TokenSHA256: strings.Repeat("a", 64)}},
		{"short token hash", IssuanceExportPayload{Version: 1, LicenseID: "lic_1", TokenSHA256: "deadbeef", IssuedAt: now.Unix()}},
		{"non-hex token hash", IssuanceExportPayload{Version: 1, LicenseID: "lic_1", TokenSHA256: strings.Repeat("z", 64), IssuedAt: now.Unix()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SignIssuanceExport(tc.payload, priv); err == nil {
				t.Fatalf("expected sign to reject %s", tc.name)
			}
		})
	}
}

func TestSignIssuanceExport_RejectsBadKey(t *testing.T) {
	now := time.Now()
	p := IssuanceExportPayload{Version: 1, LicenseID: "lic_1", TokenSHA256: strings.Repeat("a", 64), IssuedAt: now.Unix(), IssuerKeyID: "x"}
	if _, err := SignIssuanceExport(p, ed25519.PrivateKey("short")); err == nil {
		t.Fatal("expected bad key to be rejected")
	}
}

func TestParseIssuanceExport_OversizeRejected(t *testing.T) {
	pub, _ := mustKeypair(t)
	big := make([]byte, maxIssuanceExportSize+1)
	if _, err := ParseAndVerifyIssuanceExport(big, pub); err == nil {
		t.Fatal("expected oversize export to be rejected")
	}
}

func TestParseIssuanceExport_MalformedInputsRejected(t *testing.T) {
	pub, _ := mustKeypair(t)
	tests := []struct {
		name string
		data []byte
	}{
		{"not json", []byte("{not json")},
		{"bad base64 payload", mustExportWire(t, "!!!notb64!!!", base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))},
		{"bad base64 sig", mustExportWire(t, base64.RawURLEncoding.EncodeToString([]byte(`{"version":1}`)), "!!!")},
		{"wrong sig size", mustExportWire(t, base64.RawURLEncoding.EncodeToString([]byte(`{"version":1}`)), base64.RawURLEncoding.EncodeToString([]byte("short")))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAndVerifyIssuanceExport(tc.data, pub); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestParseIssuanceExport_BadVerifyKeySize(t *testing.T) {
	if _, err := ParseAndVerifyIssuanceExport([]byte("{}"), ed25519.PublicKey("short")); err == nil {
		t.Fatal("expected bad public key size to be rejected")
	}
}

func TestMarshalIssuanceExport_FallbackPath(t *testing.T) {
	// An export built by hand (no cached signed bytes) must still marshal via the
	// fallback that re-marshals the payload.
	x := IssuanceExport{
		Payload:   IssuanceExportPayload{Version: 1, LicenseID: "lic_1", TokenSHA256: strings.Repeat("a", 64), IssuedAt: 1, IssuerKeyID: "k"},
		Signature: "sig",
	}
	data, err := x.MarshalJSON()
	if err != nil {
		t.Fatalf("fallback marshal: %v", err)
	}
	var wire issuanceExportWire
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Payload == "" || wire.Signature != "sig" {
		t.Fatal("fallback marshal produced wrong wire")
	}
}

func TestBuildIssuanceExportFromToken_DefaultsIssuedAt(t *testing.T) {
	now := time.Now()
	p := BuildIssuanceExportFromToken("pipelock_lic_"+"v1_x", License{ID: "lic_1"}, "", now)
	if p.IssuedAt != now.Unix() {
		t.Fatalf("IssuedAt = %d, want %d (defaulted from now)", p.IssuedAt, now.Unix())
	}
	if p.ExpiresAt != 0 {
		t.Fatal("expected no expiry to map to 0")
	}
}

func mustExportWire(t *testing.T, payloadB64, sigB64 string) []byte {
	t.Helper()
	data, err := json.Marshal(issuanceExportWire{Payload: payloadB64, Signature: sigB64})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTokenSHA256Hex_MatchesFullSha(t *testing.T) {
	token := "pipelock_lic_" + "v1_xyz"
	sum := sha256.Sum256([]byte(token))
	if TokenSHA256Hex(token) != hex.EncodeToString(sum[:]) {
		t.Fatal("TokenSHA256Hex does not match full sha256")
	}
	if len(TokenSHA256Hex(token)) != sha256.Size*2 {
		t.Fatal("hash not full length (truncated like the ledger hash)")
	}
}
