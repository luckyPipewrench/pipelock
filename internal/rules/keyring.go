// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
)

// KeyringHex is set at build time via ldflags:
//
//	-X github.com/luckyPipewrench/pipelock/internal/rules.KeyringHex=<hex>[,<hex>...]
//
// It contains comma-separated hex-encoded Ed25519 public keys that form
// the embedded trust root for verifying official rule bundles.
var KeyringHex string

// EmbeddedKeyring parses KeyringHex into a list of Ed25519 public keys.
// Invalid entries (bad hex, wrong length) are silently skipped.
// Returns nil if KeyringHex is empty or contains no valid keys.
func EmbeddedKeyring() []ed25519.PublicKey {
	if KeyringHex == "" {
		return nil
	}

	parts := strings.Split(KeyringHex, ",")
	var keys []ed25519.PublicKey

	for _, part := range parts {
		h := strings.TrimSpace(part)
		if h == "" {
			continue
		}

		raw, err := hex.DecodeString(h)
		if err != nil {
			continue
		}

		if len(raw) != ed25519.PublicKeySize {
			continue
		}

		keys = append(keys, ed25519.PublicKey(raw))
	}

	return keys
}

// IsOfficialKey returns true if key matches any key in the embedded keyring.
func IsOfficialKey(key ed25519.PublicKey) bool {
	for _, k := range EmbeddedKeyring() {
		if k.Equal(key) {
			return true
		}
	}
	return false
}

// KeyFingerprint returns the lowercase hex encoding of an Ed25519 public key.
func KeyFingerprint(key ed25519.PublicKey) string {
	return hex.EncodeToString(key)
}
