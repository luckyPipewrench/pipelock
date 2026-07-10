// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
)

// DefaultKeyringHex is the published official rules signing public key
// (pipelock-official-rules). It also ships embedded in every release binary;
// this is public information, not a secret.
var DefaultKeyringHex = "7051d8082f3a369886d25e847e3827b4b4263f9d28cb070104b606c9fb07ae82"

// KeyringHex is set at build time via ldflags:
//
//	-X github.com/luckyPipewrench/pipelock/internal/rules.KeyringHex=<hex>[,<hex>...]
//
// It contains comma-separated hex-encoded Ed25519 public keys that form
// the embedded trust root for verifying official rule bundles.
var KeyringHex string

// EmbeddedKeyring parses DefaultKeyringHex and KeyringHex into a deduplicated
// list of Ed25519 public keys.
// Invalid entries (bad hex, wrong length) are silently skipped.
// Returns nil if both inputs are empty or contain no valid keys.
func EmbeddedKeyring() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	seen := make(map[string]struct{})

	for _, keyringHex := range []string{DefaultKeyringHex, KeyringHex} {
		for _, part := range strings.Split(keyringHex, ",") {
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

			dedupeKey := string(raw)
			if _, ok := seen[dedupeKey]; ok {
				continue
			}
			seen[dedupeKey] = struct{}{}
			keys = append(keys, ed25519.PublicKey(raw))
		}
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
