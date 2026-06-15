// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func enabledRedactionConfig() *Config {
	c := Defaults()
	c.Redaction = redact.Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]redact.ProfileSpec{
			"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
		},
		Limits: redact.DefaultLimits(),
	}
	return c
}

func TestCanonicalRedactionKey_DisabledAndNil(t *testing.T) {
	// Disabled redaction yields the empty sentinel, not an error.
	if got, err := Defaults().CanonicalRedactionKey(); err != nil || got != "" {
		t.Fatalf("disabled: got (%q, %v), want (\"\", nil)", got, err)
	}
	// Nil receiver is safe and also yields the empty sentinel.
	var nilCfg *Config
	if got, err := nilCfg.CanonicalRedactionKey(); err != nil || got != "" {
		t.Fatalf("nil receiver: got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestCanonicalRedactionKey_StableAndCached(t *testing.T) {
	c := enabledRedactionConfig()

	k1, err := c.CanonicalRedactionKey()
	if err != nil || k1 == "" {
		t.Fatalf("first call: got (%q, %v), want a non-empty key", k1, err)
	}
	// Second call must hit the memo cache and return the same value.
	k2, err := c.CanonicalRedactionKey()
	if err != nil || k2 != k1 {
		t.Fatalf("cached call: got (%q, %v), want %q", k2, err, k1)
	}

	// Invariant: the key is stable across the deep-copy YAML round-trip. The
	// round-tripped config is a zero-value Config, so this also exercises the
	// uncached path (no cache holder installed).
	data, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("yaml marshal: %v", err)
	}
	var roundTripped Config
	if err := yaml.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	k3, err := roundTripped.CanonicalRedactionKey()
	if err != nil {
		t.Fatalf("round-tripped key: %v", err)
	}
	if k3 != k1 {
		t.Fatalf("round-tripped key %q != pristine key %q", k3, k1)
	}
}

func TestCanonicalRedactionKey_PolicyChangeChangesKey(t *testing.T) {
	a := enabledRedactionConfig()
	b := enabledRedactionConfig()
	b.Redaction.AllowlistUnparseable = []string{"api.vendor.example"}

	ka, err := a.CanonicalRedactionKey()
	if err != nil {
		t.Fatalf("key a: %v", err)
	}
	kb, err := b.CanonicalRedactionKey()
	if err != nil {
		t.Fatalf("key b: %v", err)
	}
	if ka == kb {
		t.Fatal("a genuinely different redaction policy produced the same key")
	}
}
