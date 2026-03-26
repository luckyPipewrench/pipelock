// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// --- Issue coverage tests (81.2% -> higher) ---

func TestIssue_ValidLicense(t *testing.T) {
	pub, priv := testKeyPair(t)

	lic := License{
		ID:             "lic_valid",
		Email:          "valid@example.com",
		Org:            "Test Org",
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(30 * 24 * time.Hour).Unix(),
		Features:       []string{FeatureAgents},
		Tier:           "pro",
		SubscriptionID: "sub_test",
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if !strings.HasPrefix(token, tokenPrefix) {
		t.Errorf("token should have prefix %q", tokenPrefix)
	}

	// Verify the token.
	verified, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.ID != lic.ID {
		t.Errorf("ID = %q, want %q", verified.ID, lic.ID)
	}
	if verified.Tier != lic.Tier {
		t.Errorf("Tier = %q, want %q", verified.Tier, lic.Tier)
	}
	if verified.SubscriptionID != lic.SubscriptionID {
		t.Errorf("SubscriptionID = %q, want %q", verified.SubscriptionID, lic.SubscriptionID)
	}
}

func TestIssue_NoExpiration(t *testing.T) {
	_, priv := testKeyPair(t)

	lic := License{
		ID:       "lic_no_expiry",
		Email:    "noexp@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{FeatureAgents},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	decoded, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.ExpiresAt != 0 {
		t.Errorf("ExpiresAt = %d, want 0 for perpetual", decoded.ExpiresAt)
	}
}

func TestIssue_EmptyFeatures(t *testing.T) {
	_, priv := testKeyPair(t)

	lic := License{
		ID:       "lic_empty_feat",
		Email:    "empty@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	decoded, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(decoded.Features) != 0 {
		t.Errorf("Features length = %d, want 0", len(decoded.Features))
	}
}

func TestIssue_MultipleFeatures(t *testing.T) {
	pub, priv := testKeyPair(t)

	lic := License{
		ID:       "lic_multi_feat",
		Email:    "multi@example.com",
		IssuedAt: time.Now().Unix(),
		Features: []string{FeatureAgents, "fleet", "sso"},
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	verified, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verified.Features) != 3 {
		t.Errorf("Features length = %d, want 3", len(verified.Features))
	}
	if !verified.HasFeature("fleet") {
		t.Error("expected fleet feature")
	}
	if !verified.HasFeature("sso") {
		t.Error("expected sso feature")
	}
}

func TestIssue_MinimalLicense(t *testing.T) {
	// Minimal valid license: just ID and Email.
	_, priv := testKeyPair(t)

	lic := License{
		ID:    "lic_min",
		Email: "min@example.com",
	}

	token, err := Issue(lic, priv)
	if err != nil {
		t.Fatalf("Issue minimal: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

// --- EmbeddedPublicKey edge cases ---

func TestEmbeddedPublicKey_WrongLengthHex(t *testing.T) {
	original := PublicKeyHex
	// Valid hex but wrong length (16 bytes instead of 32).
	PublicKeyHex = hex.EncodeToString(make([]byte, 16))
	defer func() { PublicKeyHex = original }()

	key := EmbeddedPublicKey()
	if key != nil {
		t.Error("expected nil for wrong key length")
	}
}

func TestEmbeddedPublicKey_ValidHex(t *testing.T) {
	original := PublicKeyHex
	pub, _ := testKeyPair(t)
	PublicKeyHex = hex.EncodeToString(pub)
	defer func() { PublicKeyHex = original }()

	key := EmbeddedPublicKey()
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if len(key) != ed25519.PublicKeySize {
		t.Errorf("key size = %d, want %d", len(key), ed25519.PublicKeySize)
	}
}

// --- HasFeature edge cases ---

func TestHasFeature_EmptyFeatures(t *testing.T) {
	l := License{Features: nil}
	if l.HasFeature(FeatureAgents) {
		t.Error("nil features should not contain any feature")
	}
}

func TestHasFeature_EmptySlice(t *testing.T) {
	l := License{Features: []string{}}
	if l.HasFeature(FeatureAgents) {
		t.Error("empty features should not contain any feature")
	}
}

func TestHasFeature_EmptyString(t *testing.T) {
	l := License{Features: []string{FeatureAgents}}
	if l.HasFeature("") {
		t.Error("should not match empty feature name")
	}
}
