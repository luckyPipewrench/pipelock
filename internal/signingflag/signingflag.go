// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package signingflag provides shared parsing for --trusted-signer CLI flag
// values. Both the Free evidence viewer and the Pro/Enterprise dashboard
// consume this parser so the flag semantics are identical across tiers.
package signingflag

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// DefaultSource is the label applied when a --trusted-signer value does not
// carry an explicit source= reason.
const DefaultSource = "--trusted-signer flag"

// ParseTrustedSigners parses repeated --trusted-signer values into the
// operator trusted-key set. An empty flag list returns nil: callers then
// honestly render every signer as Unverified (never trust-on-first-use).
func ParseTrustedSigners(values []string) (map[string]evidenceview.TrustedKey, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]evidenceview.TrustedKey, len(values))
	for _, raw := range values {
		keyHex, source, err := ParseTrustedSignerSpec(raw)
		if err != nil {
			return nil, fmt.Errorf("--trusted-signer %q: %w", raw, err)
		}
		if _, dup := out[keyHex]; dup {
			return nil, fmt.Errorf("--trusted-signer %q: duplicate key %s", raw, keyHex)
		}
		out[keyHex] = evidenceview.TrustedKey{Source: source}
	}
	return out, nil
}

// ParseTrustedSignerSpec parses one --trusted-signer value: comma-separated
// kv pairs with exactly one key source, '(inline=<hex-or-versioned>|file=/path)',
// plus an optional 'source=LABEL' shown in the UI as the reason the key is
// trusted.
func ParseTrustedSignerSpec(raw string) (keyHex, source string, err error) {
	var inline, file string
	var hasInline, hasFile, hasSource bool
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return "", "", fmt.Errorf("expected key=value, got %q", part)
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "inline":
			if hasInline {
				return "", "", errors.New("inline= may appear only once")
			}
			if v == "" {
				return "", "", errors.New("inline= value is empty")
			}
			hasInline = true
			inline = v
		case "file":
			if hasFile {
				return "", "", errors.New("file= may appear only once")
			}
			if v == "" {
				return "", "", errors.New("file= value is empty")
			}
			hasFile = true
			file = v
		case "source":
			if hasSource {
				return "", "", errors.New("source= may appear only once")
			}
			hasSource = true
			source = v
		default:
			return "", "", fmt.Errorf("unknown key %q", k)
		}
	}
	switch {
	case inline != "" && file != "":
		return "", "", errors.New("inline= and file= are mutually exclusive")
	case inline == "" && file == "":
		return "", "", errors.New("one of inline= or file= is required")
	case file != "":
		data, readErr := os.ReadFile(filepath.Clean(file))
		if readErr != nil {
			return "", "", fmt.Errorf("read key file: %w", readErr)
		}
		inline = strings.TrimSpace(string(data))
	}
	// signing.ParsePublicKey enforces the Ed25519 key size on both the
	// versioned and raw-hex paths, so a parsed key is always well-formed.
	pub, err := signing.ParsePublicKey(inline)
	if err != nil {
		return "", "", fmt.Errorf("parse public key: %w", err)
	}
	if source == "" {
		source = DefaultSource
	}
	return hex.EncodeToString(pub), source, nil
}
