// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// DefaultSessionDelegationLifetime is the maximum playground session
// authorization window. Live sessions are 30 minutes; this leaves room for
// seal and verify after expiry.
const DefaultSessionDelegationLifetime = 2 * time.Hour

// MintedSession is one short-lived signing key plus the root-signed
// delegation that authorizes it for a single run and image.
type MintedSession struct {
	PrivateKey ed25519.PrivateKey
	Delegation OrchestratorDelegation
}

// MintSessionDelegation creates a session keypair and a root-signed
// delegation. The durable root private key never needs to leave the broker.
func MintSessionDelegation(root ed25519.PrivateKey, runNonce, imageDigest string, now time.Time, lifetime time.Duration) (MintedSession, error) {
	if err := signing.ValidatePrivateKeyConsistency(root); err != nil {
		return MintedSession{}, fmt.Errorf("delegation root key: %w", err)
	}
	if lifetime <= 0 {
		lifetime = DefaultSessionDelegationLifetime
	}
	sessionPub, sessionPriv, err := signing.GenerateKeyPair()
	if err != nil {
		return MintedSession{}, fmt.Errorf("session keygen: %w", err)
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return MintedSession{}, fmt.Errorf("delegation id: %w", err)
	}
	issued := now.UTC().Unix()
	d := OrchestratorDelegation{
		Format:           OrchestratorDelegationFormat,
		RootKeyID:        RootKeyID(root.Public().(ed25519.PublicKey)),
		DelegationID:     hex.EncodeToString(id[:]),
		RunNonce:         runNonce,
		SessionPublicKey: hex.EncodeToString(sessionPub),
		ImageDigest:      imageDigest,
		IssuedAtUnix:     issued,
		NotBeforeUnix:    issued,
		ExpiresAtUnix:    issued + int64(lifetime/time.Second),
	}
	signed, err := SignOrchestratorDelegation(root, d)
	if err != nil {
		return MintedSession{}, err
	}
	return MintedSession{PrivateKey: sessionPriv, Delegation: signed}, nil
}

// ParseOrchestratorPrivateKeyHex decodes a hex Ed25519 private key. It fails
// closed on malformed hex, wrong length, or a seed/public mismatch.
func ParseOrchestratorPrivateKeyHex(hexKey string) (ed25519.PrivateKey, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("decode orchestrator key hex: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("orchestrator key wrong size: got %d bytes, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(decoded)
	if err := signing.ValidatePrivateKeyConsistency(priv); err != nil {
		return nil, fmt.Errorf("orchestrator key: %w", err)
	}
	return priv, nil
}
