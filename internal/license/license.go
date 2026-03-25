// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package license provides Ed25519-signed license tokens for gating
// premium features (multi-agent profiles). Tokens are self-contained
// and verified offline; no server infrastructure is required.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// maxTokenBytes caps the decoded token size to prevent memory exhaustion
// from maliciously large tokens. 64 KiB is generous for any realistic
// license payload (~200 bytes JSON + 64 bytes signature).
const maxTokenBytes = 64 * 1024

// tokenPrefix identifies the license token format version.
const tokenPrefix = "pipelock_lic_" + "v1_" //nolint:gosec // G101: not a credential, license format prefix

// Feature names for gating.
const FeatureAgents = "agents"
const FeatureAssess = "assess"

// License represents the claims in a signed license token.
type License struct {
	ID             string   `json:"id"`
	Email          string   `json:"sub"`
	Org            string   `json:"org,omitempty"`
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
	Features       []string `json:"features"`
	Tier           string   `json:"tier,omitempty"`            // e.g. "pro", "founding_pro"
	SubscriptionID string   `json:"subscription_id,omitempty"` // external billing reference
}

// Issue creates a signed license token string from the license data.
func Issue(l License, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid private key size")
	}
	payload, err := json.Marshal(l)
	if err != nil {
		return "", fmt.Errorf("marshal license: %w", err)
	}
	// Cap payload size to prevent overflow in the allocation below.
	// License JSON is a small struct; 64KB is generous.
	const maxPayload = 64 * 1024
	if len(payload) > maxPayload {
		return "", fmt.Errorf("license payload too large: %d bytes", len(payload))
	}
	sig := ed25519.Sign(privateKey, payload)
	size := len(payload) + ed25519.SignatureSize
	if size < len(payload) { // integer overflow guard
		return "", errors.New("token size overflow")
	}
	token := make([]byte, size)
	copy(token, payload)
	copy(token[len(payload):], sig)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(token), nil
}

// Verify decodes a license token, checks the Ed25519 signature against
// the provided public key, and validates expiration. Returns the license
// data on success.
func Verify(token string, publicKey ed25519.PublicKey) (License, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return License{}, errors.New("invalid public key")
	}
	if !strings.HasPrefix(token, tokenPrefix) {
		return License{}, errors.New("invalid license format: missing prefix")
	}
	encoded := strings.TrimPrefix(token, tokenPrefix)
	// Reject oversized tokens before allocating memory for base64 decode.
	if len(encoded) > maxTokenBytes {
		return License{}, errors.New("license token exceeds maximum size")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return License{}, fmt.Errorf("decode license: %w", err)
	}
	// Minimum: 2 bytes of JSON + 64 bytes of signature.
	if len(raw) <= ed25519.SignatureSize {
		return License{}, errors.New("license token too short")
	}
	payload := raw[:len(raw)-ed25519.SignatureSize]
	sig := raw[len(raw)-ed25519.SignatureSize:]

	if !ed25519.Verify(publicKey, payload, sig) {
		return License{}, errors.New("invalid license signature")
	}

	var l License
	if err := json.Unmarshal(payload, &l); err != nil {
		return License{}, fmt.Errorf("parse license payload: %w", err)
	}

	// Validate required claims.
	if l.ID == "" {
		return License{}, errors.New("license missing required field: id")
	}
	if l.Email == "" {
		return License{}, errors.New("license missing required field: sub")
	}

	if l.ExpiresAt > 0 && time.Now().Unix() > l.ExpiresAt {
		return l, fmt.Errorf("license expired on %s", time.Unix(l.ExpiresAt, 0).UTC().Format(time.DateOnly))
	}

	return l, nil
}

// HasFeature checks whether the license includes a named feature.
func (l License) HasFeature(feature string) bool {
	for _, f := range l.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// Decode extracts the license payload from a token WITHOUT verifying the
// signature. Use for inspection only, never for authorization decisions.
func Decode(token string) (License, error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return License{}, errors.New("invalid license format: missing prefix")
	}
	encoded := strings.TrimPrefix(token, tokenPrefix)
	if len(encoded) > maxTokenBytes {
		return License{}, errors.New("license token exceeds maximum size")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return License{}, fmt.Errorf("decode license: %w", err)
	}
	if len(raw) <= ed25519.SignatureSize {
		return License{}, errors.New("license token too short")
	}
	payload := raw[:len(raw)-ed25519.SignatureSize]

	var l License
	if err := json.Unmarshal(payload, &l); err != nil {
		return License{}, fmt.Errorf("parse license payload: %w", err)
	}
	return l, nil
}

// PublicKeyHex is set at build time via ldflags:
//
//	-X github.com/luckyPipewrench/pipelock/internal/license.PublicKeyHex=<hex>
//
// Official releases embed the production public key. Dev builds leave it
// empty, which means license verification always fails and agents require
// a license_public_key_file in the config.
var PublicKeyHex string

// EmbeddedPublicKey returns the build-time public key, or nil if not set.
func EmbeddedPublicKey() ed25519.PublicKey {
	if PublicKeyHex == "" {
		return nil
	}
	key, err := hex.DecodeString(PublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(key)
}
