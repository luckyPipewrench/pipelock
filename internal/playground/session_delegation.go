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

// trustedDelegationRoot resolves the only root a delegation may be signed by.
// It is a package variable solely so this package's own tests can mint under a
// generated root; nothing outside this package can reach it, so no deployment
// can be configured to trust a different identity.
var trustedDelegationRoot = PublishedOrchestratorPublicKey

// VerifySessionDelegation checks a delegation against the published root and
// confirms it authorizes exactly this session key for this run. Parsing alone
// proves only that a delegation is well formed; without this a caller could
// present a structurally valid delegation it signed itself.
func VerifySessionDelegation(priv ed25519.PrivateKey, d OrchestratorDelegation, runNonce string) error {
	if runNonce == "" {
		return fmt.Errorf("delegated session requires a run nonce")
	}
	root, err := trustedDelegationRoot()
	if err != nil {
		return err
	}
	if err := VerifyOrchestratorDelegation(root, d, DelegationExpectations{RunNonce: runNonce}); err != nil {
		return err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("session signing key has no ed25519 public half")
	}
	if hex.EncodeToString(pub) != d.SessionPublicKey {
		return fmt.Errorf("delegation does not authorize this session signing key")
	}
	return nil
}

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
	// The delegation format carries second precision, so a sub-second lifetime
	// truncates to zero and mints a delegation that expires the instant it is
	// issued. Refuse rather than emit one nothing can use.
	if lifetime < time.Second {
		return MintedSession{}, fmt.Errorf("delegation lifetime %s is below the one-second format precision", lifetime)
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
