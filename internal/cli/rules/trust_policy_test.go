// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestRulesTrustPolicy_DefaultsPermissiveWhenNoConfig pins the fail-SAFE default.
//
// This helper resolves the rule-bundle signing trust policy for every rules
// subcommand. Its default matters more than it looks: because the permissive value of
// TrustEmbeddedKeys is `true`, the Go ZERO VALUE of the policy struct is the
// RESTRICTIVE one. A refactor that returned a bare TrustPolicy{} on the no-config path
// would silently put every rules command into private-root-only mode, refusing the
// official keyring and every unsigned local bundle, with no config change and no error
// naming the cause. That is an availability failure, and it would look like corruption.
func TestRulesTrustPolicy_DefaultsPermissiveWhenNoConfig(t *testing.T) {
	// Not parallel: mutates PIPELOCK_CONFIG and the working directory via t.Setenv/Chdir.
	t.Setenv("PIPELOCK_CONFIG", "")
	// An empty configFile with no env override and no discoverable config must still
	// yield the permissive policy, not a zero value.
	dir := t.TempDir()
	t.Chdir(dir)

	var stderr bytes.Buffer
	policy, err := rulesTrustPolicy("", &stderr)
	if err != nil {
		t.Fatalf("rulesTrustPolicy with no config: %v", err)
	}
	if !policy.TrustEmbeddedKeys {
		t.Fatal("no-config default must TRUST the embedded keyring: a zero-value policy " +
			"silently means private-root-only and refuses official and unsigned bundles")
	}
	if len(policy.TrustedKeys) != 0 {
		t.Fatalf("no-config default should carry no third-party keys, got %d", len(policy.TrustedKeys))
	}
}

// TestRulesTrustPolicy_CarriesConfiguredValues proves the helper actually reads config
// rather than always returning the default, which is what would make the test above
// vacuous on its own.
func TestRulesTrustPolicy_CarriesConfiguredValues(t *testing.T) {
	// Not parallel: mutates PIPELOCK_CONFIG.
	t.Setenv("PIPELOCK_CONFIG", "")

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyHex := hex.EncodeToString(pub)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	body := "mode: balanced\n" +
		"rules:\n" +
		"  trust_embedded_keys: false\n" +
		"  trusted_keys:\n" +
		"    - name: private-root\n" +
		"      public_key: \"" + keyHex + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stderr bytes.Buffer
	policy, err := rulesTrustPolicy(cfgPath, &stderr)
	if err != nil {
		t.Fatalf("rulesTrustPolicy with explicit config: %v", err)
	}
	if policy.TrustEmbeddedKeys {
		t.Fatal("explicit trust_embedded_keys: false must be carried through, or an operator " +
			"who de-trusted the vendor key still gets it trusted")
	}
	if len(policy.TrustedKeys) != 1 || policy.TrustedKeys[0].Name != "private-root" {
		t.Fatalf("configured trusted_keys not carried: %+v", policy.TrustedKeys)
	}
}
