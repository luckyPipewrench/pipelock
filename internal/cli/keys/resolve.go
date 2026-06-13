// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// rosterRef captures the two ways a deployment pins its trust roots: a roster
// file path and/or a pinned root fingerprint. Either, both, or neither may be
// set depending on conductor configuration.
type rosterRef struct {
	path        string
	fingerprint string
}

// rosterReference reads the follower-side roster path and pinned fingerprint
// from the conductor config block. Empty fields mean "not configured".
func rosterReference(cfg *config.Config) rosterRef {
	return rosterRef{
		path:        strings.TrimSpace(cfg.Conductor.TrustRosterPath),
		fingerprint: strings.TrimSpace(cfg.Conductor.TrustRosterRootFingerprint),
	}
}

// rulesTrustedPublicKeys decodes the configured rules.trusted_keys entries into
// parsed Ed25519 public keys. Entries that fail to decode are skipped (the
// caller treats an empty result as "none configured"); validation of the
// trusted-key shape happens at config load, so a malformed entry here is
// already a load-time error and will not reach this command on a loaded config.
func rulesTrustedPublicKeys(cfg *config.Config) []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, tk := range cfg.Rules.TrustedKeys {
		pub, err := parsePublicKeyHex(strings.TrimSpace(tk.PublicKey))
		if err != nil {
			continue
		}
		keys = append(keys, pub)
	}
	return keys
}

// parsePublicKeyHex decodes a 64-char lowercase-hex Ed25519 public key. It
// accepts only the hex form used by config fields; it deliberately does not
// touch private material.
func parsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decode ed25519 public key hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decode ed25519 public key hex: %w", errInvalidPublicKeyLen)
	}
	return ed25519.PublicKey(raw), nil
}

// pathReadable reports whether the calling user can open the path for reading.
// It mirrors doctor's openReadable: under root, DAC is bypassed, which the
// report's root banner caveats.
func pathReadable(path string) bool {
	// os.ReadFile(filepath.Clean(...)) is the repo's gosec-clean idiom for
	// reading an operator-supplied local path (no lint suppression needed,
	// unlike a bare open). These are small key/config files; bytes are discarded.
	_, err := os.ReadFile(filepath.Clean(path))
	return err == nil
}

// conductorPurposeNote adds purpose-specific context for Conductor purposes:
// reserved (no shipped workflow consumes them) and threshold (catastrophic
// actions that must not be single-signer). Mirrors the labels emitted by
// `pipelock signing key generate`.
func conductorPurposeNote(purpose domsigning.KeyPurpose) string {
	parts := []string{}
	switch purpose {
	case domsigning.PurposeTrustRootRotation, domsigning.PurposeEnrollmentTokenSigning:
		parts = append(parts, "reserved purpose; no shipped operator workflow consumes this key yet")
	}
	if purpose.RequiresConductorThreshold() {
		parts = append(parts, "threshold key; deploy independent approver keys, not a single signer")
	}
	return strings.Join(parts, "; ")
}

// appendNote joins two note fragments with "; ", tolerating empty inputs so
// callers can build notes incrementally.
func appendNote(existing, add string) string {
	switch {
	case existing == "":
		return add
	case add == "":
		return existing
	default:
		return existing + "; " + add
	}
}
