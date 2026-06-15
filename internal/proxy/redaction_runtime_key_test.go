// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// yamlRoundTripConfig mirrors enterprise.deepCopyConfig: the per-agent config
// path deep-copies a config via a YAML marshal/unmarshal round-trip, which
// rewrites nil slices/maps as empty ones. Tests use it to reproduce that exact
// transformation (the trigger for the redaction-runtime fail-closed) without
// importing the enterprise package. The returned config has no cache holder
// installed (zero-value Config), which also exercises CanonicalRedactionKey's
// uncached path.
func yamlRoundTripConfig(t *testing.T, cfg *config.Config) *config.Config {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml marshal: %v", err)
	}
	var out config.Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	return &out
}

func TestRedactionConfigKey_NilConfig(t *testing.T) {
	if got, err := redactionConfigKey(nil); err != nil || got != "" {
		t.Fatalf("redactionConfigKey(nil) = (%q, %v), want (\"\", nil)", got, err)
	}
}

func mustRedactionKey(t *testing.T, cfg *config.Config) string {
	t.Helper()
	k, err := redactionConfigKey(cfg)
	if err != nil {
		t.Fatalf("redactionConfigKey: %v", err)
	}
	return k
}

func mustRedactionKeyForScanner(t *testing.T, cfg *config.Config, sc *scanner.Scanner) string {
	t.Helper()
	k, err := redactionConfigKeyForScanner(cfg, sc)
	if err != nil {
		t.Fatalf("redactionConfigKeyForScanner: %v", err)
	}
	return k
}

// TestRedactionConfigKey_StableAcrossYAMLRoundTrip is the regression for the
// fail-closed bug: redactionConfigKey must produce the same value for a pristine
// config and for the same config after the per-agent deep-copy YAML round-trip.
// Before the canonicalization fix the startup runtime (keyed from the pristine
// config) and every per-request lookup (keyed from the deep-copied config)
// disagreed, so every request body returned the "redaction runtime unavailable"
// sentinel.
func TestRedactionConfigKey_StableAcrossYAMLRoundTrip(t *testing.T) {
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)

	roundTripped := yamlRoundTripConfig(t, cfg)

	// Guard: the RAW redaction json must actually drift across the round-trip
	// (nil -> empty), proving this test exercises the real failure condition.
	rawBefore, err := json.Marshal(cfg.Redaction)
	if err != nil {
		t.Fatalf("marshal pristine redaction: %v", err)
	}
	rawAfter, err := json.Marshal(roundTripped.Redaction)
	if err != nil {
		t.Fatalf("marshal round-tripped redaction: %v", err)
	}
	if string(rawBefore) == string(rawAfter) {
		t.Fatalf("expected raw redaction json to drift across yaml round-trip; got identical: %s", rawBefore)
	}

	if got, want := mustRedactionKey(t, roundTripped), mustRedactionKey(t, cfg); got != want {
		t.Fatalf("redactionConfigKey not stable across deep-copy round-trip:\n  pristine      = %s\n  round-tripped = %s", want, got)
	}
}

// TestRedactionConfigKey_StableAcrossDeepCopy_WholeTree proves the invariance
// holds for a fully-populated redact.Config (every collection field and nested
// slice), not just the minimal profile, and that the canonical key is
// idempotent under repeated round-trips. This guards the whole class, so a
// future nil/empty-prone field cannot silently reintroduce the drift.
func TestRedactionConfigKey_StableAcrossDeepCopy_WholeTree(t *testing.T) {
	cfg := config.Defaults()
	cfg.Redaction = redact.Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]redact.ProfileSpec{
			"code": {
				Classes:      []string{string(redact.ClassAWSAccessKey), string(redact.ClassJWT)},
				Dictionaries: []string{"vendor"},
			},
		},
		Dictionaries: map[string]redact.DictionarySpec{
			"vendor": {
				Class:           "known-secret",
				Entries:         []string{"placeholder-a", "placeholder-b"},
				CaseInsensitive: true,
				Priority:        10,
			},
		},
		AllowlistUnparseable: []string{"api.vendor.example"},
		AllowlistUnparseableRoutes: []redact.UnparseableRouteSpec{
			{Host: "oauth.vendor.example", Methods: []string{"POST"}, PathPrefixes: []string{"/token"}},
		},
		Limits: redact.DefaultLimits(),
		// Providers is json:",omitempty" so nil and empty marshal identically;
		// it is not a drift source and is intentionally left unset.
	}

	once := yamlRoundTripConfig(t, cfg)
	twice := yamlRoundTripConfig(t, once)

	k0 := mustRedactionKey(t, cfg)
	k1 := mustRedactionKey(t, once)
	k2 := mustRedactionKey(t, twice)
	if k0 == "" {
		t.Fatal("whole-tree redaction key is empty; redaction not enabled in setup")
	}
	if k0 != k1 || k1 != k2 {
		t.Fatalf("redactionConfigKey not stable/idempotent across deep-copy of a fully-populated config:\n  pristine      = %s\n  round-trip x1 = %s\n  round-trip x2 = %s", k0, k1, k2)
	}
}

// TestRedactionConfigKey_RealPolicyChangeStillChangesKey proves the
// canonicalization does not over-normalize: a genuinely different redaction
// policy must still produce a different key so a stale runtime still fails
// closed (the prior lockstep-fix invariant).
func TestRedactionConfigKey_RealPolicyChangeStillChangesKey(t *testing.T) {
	base := config.Defaults()
	applyRedactionTestProfile(base)
	baseKey := mustRedactionKey(t, base)
	if baseKey == "" {
		t.Fatal("base redaction key is empty; test setup did not enable redaction")
	}

	changed := config.Defaults()
	applyRedactionTestProfile(changed)
	// A real policy delta: narrowing which hosts may bypass non-JSON redaction.
	changed.Redaction.AllowlistUnparseable = []string{"api.vendor.example"}

	if mustRedactionKey(t, changed) == baseKey {
		t.Fatal("changed redaction policy produced the same configKey; fail-closed invariant broken")
	}

	// Disabled redaction yields the empty sentinel key (no runtime required).
	if got := mustRedactionKey(t, config.Defaults()); got != "" {
		t.Fatalf("disabled redaction key = %q, want empty", got)
	}
}
