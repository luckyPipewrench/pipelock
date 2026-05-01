// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/hex"
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
	if me.ActorFormat != DefaultEnvelopeActorFormat {
		t.Errorf("ActorFormat default = %q, want %q", me.ActorFormat, DefaultEnvelopeActorFormat)
	}
	if me.TrustDomain != DefaultEnvelopeTrustDomain {
		t.Errorf("TrustDomain default = %q, want %q", me.TrustDomain, DefaultEnvelopeTrustDomain)
	}
	if me.VerifyInbound.ReplayCache.Window != DefaultEnvelopeReplayWindow.String() {
		t.Errorf("ReplayCache.Window default = %q, want %q",
			me.VerifyInbound.ReplayCache.Window, DefaultEnvelopeReplayWindow)
	}
	if me.VerifyInbound.ReplayCache.MaxEntries != DefaultEnvelopeReplayMaxEntries {
		t.Errorf("ReplayCache.MaxEntries default = %d, want %d",
			me.VerifyInbound.ReplayCache.MaxEntries, DefaultEnvelopeReplayMaxEntries)
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

func TestValidateMediationEnvelope_VerifyInboundTrustList(t *testing.T) {
	t.Parallel()

	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	c := Defaults()
	c.MediationEnvelope.VerifyInbound.Enabled = true
	if err := c.validateMediationEnvelope(); err == nil {
		t.Fatal("expected enabled verify_inbound without trust_list to fail")
	}

	c = Defaults()
	c.MediationEnvelope.VerifyInbound.Enabled = true
	c.MediationEnvelope.VerifyInbound.TrustList = []MediationEnvelopeTrustedKey{{
		KeyID:        "partner-key",
		PublicKey:    pubHex,
		WellKnownURL: "https://partner.example/.well-known/http-message-signatures-directory",
	}}
	c.MediationEnvelope.VerifyInbound.ReplayCache.Window = "2m"
	c.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries = 16
	if err := c.validateMediationEnvelope(); err != nil {
		t.Fatalf("valid verify_inbound trust_list failed: %v", err)
	}
	if got := c.MediationEnvelope.VerifyInbound.ReplayCache.Window; got != "2m" {
		t.Fatalf("ReplayCache.Window = %q", got)
	}

	c.MediationEnvelope.VerifyInbound.TrustList[0].WellKnownURL = "http://partner.example/keys"
	if err := c.validateMediationEnvelope(); err == nil {
		t.Fatal("expected non-https well_known_url to fail")
	}
}

func TestValidateMediationEnvelope_ReplayCacheMaxEntriesDefaulted(t *testing.T) {
	t.Parallel()

	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	c := Defaults()
	c.MediationEnvelope.VerifyInbound.Enabled = true
	c.MediationEnvelope.VerifyInbound.TrustList = []MediationEnvelopeTrustedKey{{
		KeyID:     "partner-key",
		PublicKey: hex.EncodeToString(pub),
	}}
	c.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries = 0

	if err := c.validateMediationEnvelope(); err != nil {
		t.Fatalf("validateMediationEnvelope: %v", err)
	}
	if got := c.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries; got != DefaultEnvelopeReplayMaxEntries {
		t.Fatalf("ReplayCache.MaxEntries = %d, want %d", got, DefaultEnvelopeReplayMaxEntries)
	}
}

func TestValidateMediationEnvelope_TrimsFederationFields(t *testing.T) {
	t.Parallel()

	c := Defaults()
	c.MediationEnvelope.Enabled = true
	c.MediationEnvelope.Sign = true
	c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
	c.MediationEnvelope.ActorFormat = " SPIFFE "
	c.MediationEnvelope.TrustDomain = " Example.Test "
	c.MediationEnvelope.SignatureExpires = " 1m "
	c.MediationEnvelope.VerifyInbound.ReplayCache.Window = " 2m "

	if err := c.validateMediationEnvelope(); err != nil {
		t.Fatalf("validateMediationEnvelope: %v", err)
	}
	if got := c.MediationEnvelope.ActorFormat; got != "spiffe" {
		t.Fatalf("ActorFormat = %q", got)
	}
	if got := c.MediationEnvelope.TrustDomain; got != "example.test" {
		t.Fatalf("TrustDomain = %q", got)
	}
	if got := c.MediationEnvelope.SignatureExpires; got != "1m" {
		t.Fatalf("SignatureExpires = %q", got)
	}
	if got := c.MediationEnvelope.VerifyInbound.ReplayCache.Window; got != "2m" {
		t.Fatalf("ReplayCache.Window = %q", got)
	}
}

func TestValidateMediationEnvelope_SignatureExpiresValidatedWhenVerifyInboundOff(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"0s", "-1s", "not-a-duration"} {
		t.Run(raw, func(t *testing.T) {
			c := Defaults()
			c.MediationEnvelope.Enabled = true
			c.MediationEnvelope.Sign = true
			c.MediationEnvelope.SigningKeyPath = writeEnvelopeSigningKey(t)
			c.MediationEnvelope.VerifyInbound.Enabled = false
			c.MediationEnvelope.SignatureExpires = raw

			if err := c.validateMediationEnvelope(); err == nil {
				t.Fatalf("expected signature_expires %q to fail", raw)
			}
		})
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
