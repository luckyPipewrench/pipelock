// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// writeEnvelopeSigningKey generates a throwaway Ed25519 key and saves it
// to a temp file with 0o600 permissions, returning the path. Used by the
// RFC 9421 mediation envelope validation tests so they can exercise the
// real signing.LoadPrivateKeyFile path without reusing a committed key.
func writeEnvelopeSigningKey(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "envelope-ed25519.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("saving ed25519 key: %v", err)
	}
	return path
}

func TestValidateMediationEnvelope_DisabledSignOK(t *testing.T) {
	t.Parallel()

	c := Defaults()
	// Default shape: Enabled:false, Sign:false — must validate cleanly.
	if err := c.validateMediationEnvelope(); err != nil {
		t.Errorf("default mediation_envelope should validate: %v", err)
	}
}

func TestValidateMediationEnvelope_SignRequiresEnabled(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.Enabled = false
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)

	err := c.validateMediationEnvelope()
	if err == nil {
		t.Fatal("expected error when sign:true with enabled:false, got nil")
	}
	if want := "mediation_envelope.sign requires mediation_envelope.enabled"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestValidateMediationEnvelope_SignRequiresKeyPath(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = ""

	err := c.validateMediationEnvelope()
	if err == nil {
		t.Fatal("expected error when sign:true without signing_key_path, got nil")
	}
	if got, want := err.Error(), "mediation_envelope.signing_key_path is required when mediation_envelope.sign is true"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestValidateMediationEnvelope_WhitespaceKeyPathRejected(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = "   "

	if err := c.validateMediationEnvelope(); err == nil {
		t.Error("expected error when signing_key_path is whitespace-only")
	}
}

func TestValidateMediationEnvelope_UnreadableKeyFails(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = filepath.Join(t.TempDir(), "does-not-exist.key")

	if err := c.validateMediationEnvelope(); err == nil {
		t.Error("expected error when signing_key_path points at a missing file")
	}
}

func TestValidateMediationEnvelope_GoodKeyPopulatesDefaults(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)

	if err := c.validateMediationEnvelope(); err != nil {
		t.Fatalf("good key validation failed: %v", err)
	}

	me := c.MediationEnvelope
	if me.KeyID != DefaultEnvelopeSignKeyID {
		t.Errorf("KeyID default = %q, want %q", me.KeyID, DefaultEnvelopeSignKeyID)
	}
	if me.CreatedSkewSeconds != DefaultEnvelopeSignCreatedSkewSecs {
		t.Errorf("CreatedSkewSeconds default = %d, want %d",
			me.CreatedSkewSeconds, DefaultEnvelopeSignCreatedSkewSecs)
	}
	if me.MaxBodyBytes != DefaultEnvelopeSignMaxBodyBytes {
		t.Errorf("MaxBodyBytes default = %d, want %d", me.MaxBodyBytes, DefaultEnvelopeSignMaxBodyBytes)
	}

	want := DefaultEnvelopeSignedComponents()
	if len(me.SignedComponents) != len(want) {
		t.Fatalf("SignedComponents length = %d, want %d (%v)", len(me.SignedComponents), len(want), want)
	}
	for i := range want {
		if me.SignedComponents[i] != want[i] {
			t.Errorf("SignedComponents[%d] = %q, want %q", i, me.SignedComponents[i], want[i])
		}
	}
}

func TestValidateMediationEnvelope_CustomValuesPreserved(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
	c.MediationEnvelope.KeyID = testEnvelopeKeyIDV2
	c.MediationEnvelope.SignedComponents = []string{" @Method ", "@AUTHORITY"}
	c.MediationEnvelope.CreatedSkewSeconds = 120
	c.MediationEnvelope.MaxBodyBytes = 512 * 1024

	if err := c.validateMediationEnvelope(); err != nil {
		t.Fatalf("validation with custom values failed: %v", err)
	}

	me := c.MediationEnvelope
	if me.KeyID != testEnvelopeKeyIDV2 {
		t.Errorf("KeyID overridden: %q", me.KeyID)
	}
	if me.CreatedSkewSeconds != 120 || me.MaxBodyBytes != 512*1024 {
		t.Errorf("custom skew/max not preserved: %+v", me)
	}
	if len(me.SignedComponents) != 2 || me.SignedComponents[0] != "@method" || me.SignedComponents[1] != "@authority" {
		t.Errorf("custom SignedComponents not preserved: %v", me.SignedComponents)
	}
}

func TestValidateMediationEnvelope_NegativeSkewRejected(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
	c.MediationEnvelope.CreatedSkewSeconds = -1

	if err := c.validateMediationEnvelope(); err == nil {
		t.Error("expected error for negative created_skew_seconds")
	}
}

func TestValidateMediationEnvelope_NegativeMaxBodyBytesRejected(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
	c.MediationEnvelope.MaxBodyBytes = -1

	if err := c.validateMediationEnvelope(); err == nil {
		t.Error("expected error for negative max_body_bytes")
	}
}

func TestValidateMediationEnvelope_EmptyComponentRejected(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
	c.MediationEnvelope.SignedComponents = []string{"@method", "   ", "@authority"}

	if err := c.validateMediationEnvelope(); err == nil {
		t.Error("expected error for whitespace-only signed_components entry")
	}
}

func TestValidateMediationEnvelope_UnsupportedComponentRejected(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
	c.MediationEnvelope.SignedComponents = []string{"@method", "host"}

	if err := c.validateMediationEnvelope(); err == nil {
		t.Error("expected error for unsupported signed_components entry")
	}
}

func TestValidateMediationEnvelope_DuplicateComponentRejected(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
	c.MediationEnvelope.SignedComponents = []string{"@method", "@method"}

	if err := c.validateMediationEnvelope(); err == nil {
		t.Error("expected error for duplicate signed_components entry")
	}
}

func TestValidateReload_MediationEnvelopeSignDowngrade(t *testing.T) {
	t.Parallel()

	keyPath := writeEnvelopeSigningKey(t)

	old := Defaults()
	old.MediationEnvelope.Enabled = true
	old.MediationEnvelope.Sign = true
	old.MediationEnvelope.SigningKeyPath = keyPath
	if err := old.validateMediationEnvelope(); err != nil {
		t.Fatalf("old validate: %v", err)
	}

	updated := Defaults()
	updated.MediationEnvelope.Enabled = true
	updated.MediationEnvelope.Sign = false // downgrade to unsigned envelope
	if err := updated.validateMediationEnvelope(); err != nil {
		t.Fatalf("updated validate: %v", err)
	}

	warnings := ValidateReload(old, updated)
	if !reloadWarningHasField(warnings, "mediation_envelope.sign") {
		t.Errorf("expected mediation_envelope.sign downgrade warning, got %v", warnings)
	}
	if reloadWarningHasField(warnings, "mediation_envelope.enabled") {
		t.Errorf("did not expect mediation_envelope.enabled warning, got %v", warnings)
	}
}

func TestValidateReload_MediationEnvelopeDisabled(t *testing.T) {
	t.Parallel()

	old := Defaults()
	old.MediationEnvelope.Enabled = true
	updated := Defaults()
	updated.MediationEnvelope.Enabled = false

	warnings := ValidateReload(old, updated)
	if !reloadWarningHasField(warnings, "mediation_envelope.enabled") {
		t.Errorf("expected mediation_envelope.enabled disabled warning, got %v", warnings)
	}
}

func TestValidateReload_MediationEnvelopeKeyIDChange(t *testing.T) {
	t.Parallel()

	keyPath := writeEnvelopeSigningKey(t)

	old := Defaults()
	old.MediationEnvelope.Enabled = true
	old.MediationEnvelope.Sign = true
	old.MediationEnvelope.SigningKeyPath = keyPath
	old.MediationEnvelope.KeyID = testEnvelopeKeyIDV1
	if err := old.validateMediationEnvelope(); err != nil {
		t.Fatalf("old validate: %v", err)
	}

	updated := Defaults()
	updated.MediationEnvelope.Enabled = true
	updated.MediationEnvelope.Sign = true
	updated.MediationEnvelope.SigningKeyPath = keyPath
	updated.MediationEnvelope.KeyID = testEnvelopeKeyIDV2
	if err := updated.validateMediationEnvelope(); err != nil {
		t.Fatalf("updated validate: %v", err)
	}

	warnings := ValidateReload(old, updated)
	if !reloadWarningHasField(warnings, "mediation_envelope.key_id") {
		t.Errorf("expected mediation_envelope.key_id change warning, got %v", warnings)
	}
}

func TestValidateReload_MediationEnvelopeSignedComponentsNarrowed(t *testing.T) {
	t.Parallel()

	keyPath := writeEnvelopeSigningKey(t)

	old := Defaults()
	old.MediationEnvelope.Enabled = true
	old.MediationEnvelope.Sign = true
	old.MediationEnvelope.SigningKeyPath = keyPath
	if err := old.validateMediationEnvelope(); err != nil {
		t.Fatalf("old validate: %v", err)
	}

	updated := Defaults()
	updated.MediationEnvelope.Enabled = true
	updated.MediationEnvelope.Sign = true
	updated.MediationEnvelope.SigningKeyPath = keyPath
	updated.MediationEnvelope.SignedComponents = []string{"@method", "@target-uri"}
	if err := updated.validateMediationEnvelope(); err != nil {
		t.Fatalf("updated validate: %v", err)
	}

	warnings := ValidateReload(old, updated)
	if !reloadWarningHasField(warnings, "mediation_envelope.signed_components") {
		t.Errorf("expected mediation_envelope.signed_components warning, got %v", warnings)
	}
}

func TestValidateReload_MediationEnvelopeMaxBodyBytesReduced(t *testing.T) {
	t.Parallel()

	keyPath := writeEnvelopeSigningKey(t)

	old := Defaults()
	old.MediationEnvelope.Enabled = true
	old.MediationEnvelope.Sign = true
	old.MediationEnvelope.SigningKeyPath = keyPath
	if err := old.validateMediationEnvelope(); err != nil {
		t.Fatalf("old validate: %v", err)
	}

	updated := Defaults()
	updated.MediationEnvelope.Enabled = true
	updated.MediationEnvelope.Sign = true
	updated.MediationEnvelope.SigningKeyPath = keyPath
	updated.MediationEnvelope.MaxBodyBytes = old.MediationEnvelope.MaxBodyBytes / 2
	if err := updated.validateMediationEnvelope(); err != nil {
		t.Fatalf("updated validate: %v", err)
	}

	warnings := ValidateReload(old, updated)
	if !reloadWarningHasField(warnings, "mediation_envelope.max_body_bytes") {
		t.Errorf("expected mediation_envelope.max_body_bytes warning, got %v", warnings)
	}
}

func reloadWarningHasField(warnings []ReloadWarning, field string) bool {
	for _, w := range warnings {
		if w.Field == field {
			return true
		}
	}
	return false
}
