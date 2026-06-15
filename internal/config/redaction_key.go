// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// CanonicalRedactionKey returns a stable identity hash of the redaction policy
// that is invariant to nil-vs-empty collection representation. It returns
// ("", nil) when redaction is disabled.
//
// Why canonicalization is required: the per-agent config path deep-copies a
// Config through a YAML marshal/unmarshal round-trip (enterprise.deepCopyConfig)
// which rewrites nil slices/maps as empty ones. A plain json.Marshal then emits
// null for a pristine config but []/{} for the round-tripped copy, so the same
// logical policy hashes differently. The proxy keys its startup redaction
// runtime from the pristine config and every per-request lookup from the
// deep-copied config; without a canonical key those never match and every
// request body fails closed. Running the same round-trip here collapses nil and
// empty to one form on both key derivations so they converge. The round-tripped
// value is only an in-memory canonical form; the bytes hashed are json.Marshal
// output, never the YAML emitter's (whose formatting is not a stable hash input).
//
// The result is memoised per Config because the round-trip is allocation-heavy
// (~40us, hundreds of allocs) and the key is recomputed on the request-body hot
// path. Config values are treated as immutable after Load()/Clone(); a mutation
// after the first call returns a stale value, matching CanonicalPolicyHash.
func (c *Config) CanonicalRedactionKey() (string, error) {
	if c == nil || !c.Redaction.Enabled {
		return "", nil
	}
	if c.canonicalRedactionKeyCache != nil {
		if cached := c.canonicalRedactionKeyCache.Load(); cached != nil {
			if s, ok := cached.(string); ok {
				return s, nil
			}
		}
	}
	canonical, err := canonicalRedactionConfig(c.Redaction)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal canonical redaction config: %w", err)
	}
	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])
	if c.canonicalRedactionKeyCache != nil {
		c.canonicalRedactionKeyCache.Store(key)
	}
	return key, nil
}

// canonicalRedactionConfig normalizes a redaction config through the same YAML
// marshal/unmarshal round-trip that enterprise.deepCopyConfig applies to
// per-agent configs, collapsing nil-vs-empty divergence across the whole
// redact.Config tree (current and future fields) without enumerating individual
// fields.
func canonicalRedactionConfig(in redact.Config) (redact.Config, error) {
	data, err := yaml.Marshal(in)
	if err != nil {
		return redact.Config{}, fmt.Errorf("canonicalize redaction config (marshal): %w", err)
	}
	var out redact.Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		return redact.Config{}, fmt.Errorf("canonicalize redaction config (unmarshal): %w", err)
	}
	return out, nil
}
