// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestIssueAndVerify(t *testing.T) {
	pub, priv := testKeyPair(t)

	lic := License{
		ID:        "lic_test_001",
		Email:     "customer@example.com",
		Org:       "Acme Corp",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  []string{FeatureAgents},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(token, tokenPrefix) {
		t.Errorf("token missing prefix, got %q", token[:20])
	}

	got, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if got.ID != lic.ID {
		t.Errorf("ID = %q, want %q", got.ID, lic.ID)
	}
	if got.Email != lic.Email {
		t.Errorf("Email = %q, want %q", got.Email, lic.Email)
	}
	if got.Org != lic.Org {
		t.Errorf("Org = %q, want %q", got.Org, lic.Org)
	}
	if !got.HasFeature(FeatureAgents) {
		t.Error("expected agents feature")
	}
}

func TestVerifyExpired(t *testing.T) {
	pub, priv := testKeyPair(t)

	lic := License{
		ID:        "lic_expired",
		Email:     "old@example.com",
		IssuedAt:  time.Now().Add(-730 * 24 * time.Hour).Unix(), // 2 years ago
		ExpiresAt: time.Now().Add(-24 * time.Hour).Unix(),       // yesterday
		Features:  []string{FeatureAgents},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Verify(token, pub)
	if err == nil {
		t.Fatal("expected error for expired license")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %q, want 'expired'", err.Error())
	}
}

func TestVerifyNoExpiration(t *testing.T) {
	pub, priv := testKeyPair(t)

	lic := License{
		ID:        "lic_perpetual",
		Email:     "forever@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: 0, // no expiration
		Features:  []string{FeatureAgents},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("perpetual license should verify: %v", err)
	}
	if got.ExpiresAt != 0 {
		t.Errorf("ExpiresAt = %d, want 0", got.ExpiresAt)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv := testKeyPair(t)
	otherPub, _ := testKeyPair(t)

	lic := License{
		ID:       "lic_wrong_key",
		Email:    "test@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{FeatureAgents},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Verify(token, otherPub)
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error = %q, want 'signature'", err.Error())
	}
}

func TestVerifyTamperedToken(t *testing.T) {
	pub, priv := testKeyPair(t)

	lic := License{
		ID:       "lic_tampered",
		Email:    "test@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{FeatureAgents},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a character in the base64 payload (after the prefix).
	tampered := token[:len(tokenPrefix)+5] + "X" + token[len(tokenPrefix)+6:]

	_, err = Verify(tampered, pub)
	if err == nil {
		t.Fatal("expected verification failure for tampered token")
	}
}

func TestVerifyBadFormat(t *testing.T) {
	pub, _ := testKeyPair(t)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no prefix", "not_a_license_token"},
		{"bad base64", tokenPrefix + "!!!invalid!!!"},
		{"too short", tokenPrefix + "YQ"}, // just "a"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.token, pub)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestHasFeature(t *testing.T) {
	l := License{Features: []string{"agents", "reports"}}
	if !l.HasFeature("agents") {
		t.Error("expected agents feature")
	}
	if !l.HasFeature("reports") {
		t.Error("expected reports feature")
	}
	if l.HasFeature("nonexistent") {
		t.Error("unexpected feature match")
	}
}

func TestEmbeddedPublicKey_Empty(t *testing.T) {
	// PublicKeyHex is empty by default in tests (no ldflags).
	key := EmbeddedPublicKey()
	if key != nil {
		t.Error("expected nil when PublicKeyHex is empty")
	}
}

func TestEmbeddedPublicKey_Valid(t *testing.T) {
	pub, _ := testKeyPair(t)
	original := PublicKeyHex
	PublicKeyHex = hex.EncodeToString(pub)
	defer func() { PublicKeyHex = original }()

	key := EmbeddedPublicKey()
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if !key.Equal(pub) {
		t.Error("embedded key doesn't match")
	}
}

func TestEmbeddedPublicKey_InvalidHex(t *testing.T) {
	original := PublicKeyHex
	PublicKeyHex = "not-valid-hex"
	defer func() { PublicKeyHex = original }()

	key := EmbeddedPublicKey()
	if key != nil {
		t.Error("expected nil for invalid hex")
	}
}

func TestVerifyRequiresID(t *testing.T) {
	pub, priv := testKeyPair(t)
	lic := License{
		ID:       "", // empty
		Email:    "test@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{FeatureAgents},
	}
	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(token, pub)
	if err == nil {
		t.Fatal("expected error for empty id")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("error = %q, want mention of 'id'", err.Error())
	}
}

func TestVerifyRequiresEmail(t *testing.T) {
	pub, priv := testKeyPair(t)
	lic := License{
		ID:       "lic_test",
		Email:    "", // empty
		IssuedAt: time.Now().Unix(),
		Features: []string{FeatureAgents},
	}
	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(token, pub)
	if err == nil {
		t.Fatal("expected error for empty sub")
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Errorf("error = %q, want mention of 'sub'", err.Error())
	}
}

func TestVerifyRejectsOversizedToken(t *testing.T) {
	pub, _ := testKeyPair(t)
	// Build a token that exceeds maxTokenBytes.
	huge := tokenPrefix + strings.Repeat("A", maxTokenBytes+1)
	_, err := Verify(huge, pub)
	if err == nil {
		t.Fatal("expected error for oversized token")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Errorf("error = %q, want 'maximum size'", err.Error())
	}
}

func TestDecodeRejectsOversizedToken(t *testing.T) {
	huge := tokenPrefix + strings.Repeat("A", maxTokenBytes+1)
	_, err := Decode(huge)
	if err == nil {
		t.Fatal("expected error for oversized token")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Errorf("error = %q, want 'maximum size'", err.Error())
	}
}
