// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestMintSessionDelegation_RoundTrip(t *testing.T) {
	t.Parallel()
	rootPub, rootPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("ab", 32)
	minted, err := MintSessionDelegation(rootPriv, "run-nonce-1", image, time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}
	if err := VerifyOrchestratorDelegation(rootPub, minted.Delegation, DelegationExpectations{
		RunNonce:    "run-nonce-1",
		ImageDigest: image,
		MaxLifetime: time.Hour,
	}); err != nil {
		t.Fatalf("verify minted delegation: %v", err)
	}
	sessionPub := minted.PrivateKey.Public().(ed25519.PublicKey)
	if hex.EncodeToString(sessionPub) != minted.Delegation.SessionPublicKey {
		t.Fatal("session public key does not match delegation")
	}
	if hex.EncodeToString(sessionPub) == hex.EncodeToString(rootPub) {
		t.Fatal("session key must not be the durable root")
	}
}

func TestMintSessionDelegation_RejectsBadRoot(t *testing.T) {
	t.Parallel()
	_, err := MintSessionDelegation(ed25519.PrivateKey("short"), "run", "sha256:"+strings.Repeat("cd", 32), time.Now(), time.Hour)
	if err == nil {
		t.Fatal("expected bad root to fail")
	}
}

func TestParseOrchestratorPrivateKeyHex(t *testing.T) {
	t.Parallel()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseOrchestratorPrivateKeyHex(hex.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(priv) != hex.EncodeToString(got) {
		t.Fatal("parsed key does not match")
	}
	if _, err := ParseOrchestratorPrivateKeyHex("not-hex"); err == nil {
		t.Fatal("expected malformed hex to fail")
	}
	if _, err := ParseOrchestratorPrivateKeyHex("aa"); err == nil {
		t.Fatal("expected short key to fail")
	}
}
