// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func genPubHex(t *testing.T) string {
	t.Helper()
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return hex.EncodeToString(pub)
}

// a2aSigYAML builds a config enabling A2A scanning with one trusted key and an
// optional require_signed_agent_cards line.
func a2aSigYAML(pubHex, requireLine string) string {
	return "version: 1\n" +
		"a2a_scanning:\n" +
		"  enabled: true\n" +
		"  action: block\n" +
		requireLine +
		"  trusted_agent_card_keys:\n" +
		"    - key_id: k1\n" +
		"      public_key: " + pubHex + "\n" +
		"      allowed_origins:\n" +
		"        - https://agent.example.com\n"
}

func loadA2ASig(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// --- require_signed_agent_cards: the 6 mandated config-boolean states ---

// State 1: omitted -> false (unsigned cards keep existing behavior by default).
func TestRequireSignedCards_Omitted(t *testing.T) {
	cfg := loadA2ASig(t, a2aSigYAML(genPubHex(t), ""))
	if cfg.A2AScanning.RequireSignedAgentCards {
		t.Fatal("omitted require_signed_agent_cards must default to false")
	}
}

// State 2: YAML null/blank -> false.
func TestRequireSignedCards_YAMLNull(t *testing.T) {
	cfg := loadA2ASig(t, a2aSigYAML(genPubHex(t), "  require_signed_agent_cards:\n"))
	if cfg.A2AScanning.RequireSignedAgentCards {
		t.Fatal("YAML null require_signed_agent_cards must be false")
	}
}

// State 3: explicit false -> false.
func TestRequireSignedCards_ExplicitFalse(t *testing.T) {
	cfg := loadA2ASig(t, a2aSigYAML(genPubHex(t), "  require_signed_agent_cards: false\n"))
	if cfg.A2AScanning.RequireSignedAgentCards {
		t.Fatal("explicit false must be preserved")
	}
}

// State 4: explicit true -> true.
func TestRequireSignedCards_ExplicitTrue(t *testing.T) {
	cfg := loadA2ASig(t, a2aSigYAML(genPubHex(t), "  require_signed_agent_cards: true\n"))
	if !cfg.A2AScanning.RequireSignedAgentCards {
		t.Fatal("explicit true must be preserved")
	}
}

// State 5: reload with change (false -> true).
func TestRequireSignedCards_ReloadWithChange(t *testing.T) {
	pubHex := genPubHex(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(a2aSigYAML(pubHex, "  require_signed_agent_cards: false\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	if first.A2AScanning.RequireSignedAgentCards {
		t.Fatal("first load should be false")
	}
	if err := os.WriteFile(path, []byte(a2aSigYAML(pubHex, "  require_signed_agent_cards: true\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if !second.A2AScanning.RequireSignedAgentCards {
		t.Fatal("reload with change should observe true")
	}
}

// State 6: reload without change preserves the value.
func TestRequireSignedCards_ReloadWithoutChange(t *testing.T) {
	pubHex := genPubHex(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	body := a2aSigYAML(pubHex, "  require_signed_agent_cards: true\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if first.A2AScanning.RequireSignedAgentCards != second.A2AScanning.RequireSignedAgentCards {
		t.Fatal("reload without change must preserve value")
	}
	if !first.A2AScanning.RequireSignedAgentCards {
		t.Fatal("value should remain true across reloads")
	}
}

// --- Trusted key validation ---

func validateA2A(t *testing.T, require bool, keys []A2ATrustedCardKey) error {
	t.Helper()
	cfg := Defaults()
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = ActionBlock
	cfg.A2AScanning.RequireSignedAgentCards = require
	cfg.A2AScanning.TrustedAgentCardKeys = keys
	return cfg.Validate()
}

func TestValidateA2ATrustedCardKeys(t *testing.T) {
	pub1 := genPubHex(t)
	pub2 := genPubHex(t)
	origins := []string{"https://agent.example.com"}

	cases := []struct {
		name    string
		require bool
		keys    []A2ATrustedCardKey
		wantErr string
	}{
		{
			name: "valid",
			keys: []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: origins}},
		},
		{
			name:    "empty_key_id",
			keys:    []A2ATrustedCardKey{{KeyID: "", PublicKey: pub1, AllowedOrigins: origins}},
			wantErr: "key_id is required",
		},
		{
			name: "duplicate_key_id",
			keys: []A2ATrustedCardKey{
				{KeyID: "dup", PublicKey: pub1, AllowedOrigins: origins},
				{KeyID: "dup", PublicKey: pub2, AllowedOrigins: origins},
			},
			wantErr: "duplicate key_id",
		},
		{
			name:    "invalid_public_key",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: "not-a-key", AllowedOrigins: origins}},
			wantErr: "invalid public_key",
		},
		{
			name: "duplicate_fingerprint",
			keys: []A2ATrustedCardKey{
				{KeyID: "k1", PublicKey: pub1, AllowedOrigins: origins},
				{KeyID: "k2", PublicKey: pub1, AllowedOrigins: origins},
			},
			wantErr: "share the same public key",
		},
		{
			name:    "empty_origins",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: nil}},
			wantErr: "allowed_origins is required",
		},
		{
			name:    "origin_with_path",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://agent.example.com/path"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_no_scheme",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"agent.example.com"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_with_userinfo",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://user:pass@agent.example.com"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_with_query",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://agent.example.com?x=1"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_empty_string",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{""}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_empty_host",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://:443"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_bad_port",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://agent.example.com:99999"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_named_bad_port",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://agent.example.com:https"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_empty_port",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://agent.example.com:"}}},
			wantErr: "invalid origin",
		},
		{
			name:    "origin_with_trailing_slash_ok",
			keys:    []A2ATrustedCardKey{{KeyID: "k1", PublicKey: pub1, AllowedOrigins: []string{"https://agent.example.com/"}}},
			wantErr: "",
		},
		{
			name:    "require_signed_without_keys",
			require: true,
			keys:    nil,
			wantErr: "requires at least one trusted_agent_card_keys",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateA2A(t, tc.require, tc.keys)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateA2ATrustedCardKeysNormalizesAcceptedValues(t *testing.T) {
	pubHex := genPubHex(t)
	pub, err := signing.ParsePublicKey(pubHex)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	cfg := Defaults()
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = ActionBlock
	cfg.A2AScanning.TrustedAgentCardKeys = []A2ATrustedCardKey{{
		KeyID:     " k1 ",
		PublicKey: pubHex,
		AllowedOrigins: []string{
			"HTTPS://Agent.Example.Com:443/",
			"http://[2001:DB8::1]:80",
			"https://agent.example.com:8443",
		},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := cfg.A2AScanning.TrustedAgentCardKeys[0]
	if got.KeyID != "k1" {
		t.Fatalf("KeyID not normalized: %q", got.KeyID)
	}
	if want := signing.EncodePublicKey(pub); got.PublicKey != want {
		t.Fatalf("PublicKey not normalized:\n got %q\nwant %q", got.PublicKey, want)
	}
	wantOrigins := []string{
		"https://agent.example.com",
		"http://[2001:db8::1]",
		"https://agent.example.com:8443",
	}
	if strings.Join(got.AllowedOrigins, "\n") != strings.Join(wantOrigins, "\n") {
		t.Fatalf("AllowedOrigins not normalized:\n got %#v\nwant %#v", got.AllowedOrigins, wantOrigins)
	}
}

func TestCanonicalPolicyHash_A2ATrustedCardKeysCanonical(t *testing.T) {
	pub1 := genPubHex(t)
	pub2 := genPubHex(t)

	hashA := canonicalA2AHash(t, []A2ATrustedCardKey{
		{
			KeyID:     " beta ",
			PublicKey: pub2,
			AllowedOrigins: []string{
				"https://beta.example.com:8443",
				"https://beta.example.com:443/",
			},
		},
		{
			KeyID:     "alpha",
			PublicKey: pub1,
			AllowedOrigins: []string{
				"HTTPS://Agent.Example.Com:443/",
				"http://[2001:DB8::1]:80",
			},
		},
	})
	hashB := canonicalA2AHash(t, []A2ATrustedCardKey{
		{
			KeyID:     "alpha",
			PublicKey: encodedPublicKey(t, pub1),
			AllowedOrigins: []string{
				"http://[2001:db8::1]",
				"https://agent.example.com",
			},
		},
		{
			KeyID:     "beta",
			PublicKey: encodedPublicKey(t, pub2),
			AllowedOrigins: []string{
				"https://beta.example.com",
				"https://beta.example.com:8443",
			},
		},
	})
	if hashA != hashB {
		t.Fatalf("equivalent A2A trusted key policy should hash equally:\n  a = %s\n  b = %s", hashA, hashB)
	}
}

func canonicalA2AHash(t *testing.T, keys []A2ATrustedCardKey) string {
	t.Helper()
	cfg := Defaults()
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = ActionBlock
	cfg.A2AScanning.TrustedAgentCardKeys = keys
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return cfg.CanonicalPolicyHash()
}

func encodedPublicKey(t *testing.T, key string) string {
	t.Helper()
	pub, err := signing.ParsePublicKey(key)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return signing.EncodePublicKey(pub)
}

// --- Reload warnings ---

func TestReloadWarnings_A2ASignature(t *testing.T) {
	pub := genPubHex(t)
	mk := func(require bool, keyCount int) *Config {
		cfg := Defaults()
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = ActionBlock
		cfg.A2AScanning.RequireSignedAgentCards = require
		var keys []A2ATrustedCardKey
		for i := 0; i < keyCount; i++ {
			keys = append(keys, A2ATrustedCardKey{
				KeyID:          "k" + strings.Repeat("x", i+1),
				PublicKey:      pub, // same key bytes are fine here; reload warnings don't validate
				AllowedOrigins: []string{"https://agent.example.com"},
			})
		}
		cfg.A2AScanning.TrustedAgentCardKeys = keys
		return cfg
	}

	t.Run("require_disabled", func(t *testing.T) {
		warns := ValidateReload(mk(true, 1), mk(false, 1))
		if !hasWarning(warns, "a2a_scanning.require_signed_agent_cards") {
			t.Fatalf("expected require_signed downgrade warning, got %+v", warns)
		}
	})

	t.Run("keys_removed_to_zero_warns", func(t *testing.T) {
		// Verification turning off (non-empty -> empty) is the genuine downgrade.
		warns := ValidateReload(mk(false, 2), mk(false, 0))
		if !hasWarning(warns, "a2a_scanning.trusted_agent_card_keys") {
			t.Fatalf("expected trusted-keys-removed warning, got %+v", warns)
		}
	})

	t.Run("keys_reduced_revocation_no_warning", func(t *testing.T) {
		// Removing one of several keys is revocation (stricter), not a downgrade.
		// Flagging it would block emergency revocation under strict-mode reload.
		warns := ValidateReload(mk(false, 2), mk(false, 1))
		if hasWarning(warns, "a2a_scanning.trusted_agent_card_keys") {
			t.Fatalf("key revocation must NOT warn, got %+v", warns)
		}
	})

	t.Run("disabled_no_signature_warnings", func(t *testing.T) {
		// When A2A scanning is off in the new config, signature sub-warnings are
		// suppressed (the top-level "A2A scanning disabled" warning covers it) so
		// strict-mode reload is not rejected for an unrelated downgrade.
		oldCfg := mk(true, 2)
		newCfg := mk(false, 0)
		newCfg.A2AScanning.Enabled = false
		warns := ValidateReload(oldCfg, newCfg)
		if hasWarning(warns, "a2a_scanning.require_signed_agent_cards") || hasWarning(warns, "a2a_scanning.trusted_agent_card_keys") {
			t.Fatalf("disabled A2A must not emit signature sub-warnings, got %+v", warns)
		}
	})

	t.Run("no_change_no_warning", func(t *testing.T) {
		warns := ValidateReload(mk(true, 1), mk(true, 1))
		if hasWarning(warns, "a2a_scanning.require_signed_agent_cards") || hasWarning(warns, "a2a_scanning.trusted_agent_card_keys") {
			t.Fatalf("unexpected A2A signature warnings: %+v", warns)
		}
	})
}

// TestValidateA2ATrustedCardKeys_RunsWhenDisabled proves trusted-key validation
// is fail-fast at load even when a2a_scanning.enabled is false, so a bad key
// config does not slip through to only fail on a later enabling reload.
func TestValidateA2ATrustedCardKeys_RunsWhenDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.A2AScanning.Enabled = false
	cfg.A2AScanning.TrustedAgentCardKeys = []A2ATrustedCardKey{
		{KeyID: "k1", PublicKey: "not-a-key", AllowedOrigins: []string{"https://agent.example.com"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid public_key") {
		t.Fatalf("disabled A2A must still reject a malformed trusted key, got %v", err)
	}
}

func hasWarning(warns []ReloadWarning, field string) bool {
	for _, w := range warns {
		if w.Field == field {
			return true
		}
	}
	return false
}
