// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// writeEnvelopeKey generates a temporary Ed25519 private key and saves
// it to a file in a directory the test owns. Returns the path. The
// file is cleaned up automatically when the test's TempDir is
// cleaned.
func writeEnvelopeKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "envelope-ed25519.key")
	if err := signing.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	return path
}

// envelopeReloadProxy builds a minimal Proxy suitable for exercising
// the envelope reload path. No recorder, no receipt emitter — the
// envelope reload lane is independent of flight recorder state.
func envelopeReloadProxy(t *testing.T) *Proxy {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}

	sc := scanner.New(cfg)
	m := metrics.New()
	logger := audit.NewNop()

	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return p
}

// enableEnvelopeSigning mutates cfg in place to turn on mediation
// envelope signing against a freshly-written key and walks it through
// validation so the defaults (key_id, signed_components, etc.) are
// populated the way Load() would populate them at startup.
func enableEnvelopeSigning(t *testing.T, cfg *config.Config, keyPath string) {
	t.Helper()
	cfg.MediationEnvelope.Enabled = true
	cfg.MediationEnvelope.Sign = true
	cfg.MediationEnvelope.SigningKeyPath = keyPath
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}
}

// TestProxy_ReloadEnvelopeEmitter_EnablesSigning reloads a proxy from
// mediation_envelope.enabled=false to enabled=true with sign=true, and
// verifies the installed emitter carries a working signer.
func TestProxy_ReloadEnvelopeEmitter_EnablesSigning(t *testing.T) {
	t.Parallel()

	p := envelopeReloadProxy(t)

	// Baseline: no envelope, no signer.
	if em := p.envelopeEmitterPtr.Load(); em != nil && em.HasSigner() {
		t.Fatal("baseline proxy should not have a signing envelope emitter")
	}

	keyPath := writeEnvelopeKey(t)
	reloadCfg := config.Defaults()
	reloadCfg.Internal = nil
	reloadCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	enableEnvelopeSigning(t, reloadCfg, keyPath)
	reloadSc := scanner.New(reloadCfg)

	p.Reload(reloadCfg, reloadSc)

	em := p.envelopeEmitterPtr.Load()
	if em == nil {
		t.Fatal("envelope emitter should be installed after reload with enabled+sign")
	}
	if !em.HasSigner() {
		t.Fatal("emitter should carry a signer after reload with sign:true")
	}
	if got := em.Signer().KeyID(); got != config.DefaultEnvelopeSignKeyID {
		t.Errorf("signer KeyID = %q, want %q", got, config.DefaultEnvelopeSignKeyID)
	}
}

// TestProxy_ReloadEnvelopeEmitter_DisablesSigning reloads a proxy that
// was signing back to sign:false and verifies the signer is dropped.
func TestProxy_ReloadEnvelopeEmitter_DisablesSigning(t *testing.T) {
	t.Parallel()

	p := envelopeReloadProxy(t)
	keyPath := writeEnvelopeKey(t)

	// First reload: enable signing.
	onCfg := config.Defaults()
	onCfg.Internal = nil
	onCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	enableEnvelopeSigning(t, onCfg, keyPath)
	p.Reload(onCfg, scanner.New(onCfg))
	if em := p.envelopeEmitterPtr.Load(); em == nil || !em.HasSigner() {
		t.Fatal("envelope emitter should be signing after first reload")
	}

	// Second reload: disable signing but keep envelope enabled.
	offCfg := config.Defaults()
	offCfg.Internal = nil
	offCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	offCfg.MediationEnvelope.Enabled = true
	offCfg.MediationEnvelope.Sign = false
	if err := offCfg.Validate(); err != nil {
		t.Fatalf("offCfg.Validate: %v", err)
	}
	p.Reload(offCfg, scanner.New(offCfg))

	em := p.envelopeEmitterPtr.Load()
	if em == nil {
		t.Fatal("envelope emitter should still be installed (enabled=true, sign=false)")
	}
	if em.HasSigner() {
		t.Error("emitter should NOT have a signer after sign:true → sign:false reload")
	}
}

// TestProxy_ReloadEnvelopeEmitter_AbortsOnMissingKey is the fail-closed
// reload test: when sign:true and the key file has been deleted
// between reloads, the whole Reload aborts, leaving the previous
// emitter (and its signer) unchanged. The caller-supplied new scanner
// is closed. The config pointer is also unchanged.
func TestProxy_ReloadEnvelopeEmitter_AbortsOnMissingKey(t *testing.T) {
	t.Parallel()

	p := envelopeReloadProxy(t)

	// First reload: enable signing with a real key.
	keyPath := writeEnvelopeKey(t)
	onCfg := config.Defaults()
	onCfg.Internal = nil
	onCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	enableEnvelopeSigning(t, onCfg, keyPath)
	p.Reload(onCfg, scanner.New(onCfg))

	beforeEmitter := p.envelopeEmitterPtr.Load()
	beforeCfg := p.cfgPtr.Load()
	if beforeEmitter == nil || !beforeEmitter.HasSigner() {
		t.Fatal("first reload should have installed a signing emitter")
	}

	// Delete the key file so the second reload cannot load it.
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("removing key: %v", err)
	}

	// Build a second reload that still points at the (now missing) key.
	brokenCfg := config.Defaults()
	brokenCfg.Internal = nil
	brokenCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	// Skip cfg.Validate() here — we want to exercise the reload-time
	// key read path, not startup validation. Load() would reject the
	// missing file earlier.
	brokenCfg.MediationEnvelope.Enabled = true
	brokenCfg.MediationEnvelope.Sign = true
	brokenCfg.MediationEnvelope.SigningKeyPath = keyPath
	brokenCfg.MediationEnvelope.KeyID = config.DefaultEnvelopeSignKeyID
	brokenCfg.MediationEnvelope.SignedComponents = config.DefaultEnvelopeSignedComponents()
	brokenCfg.MediationEnvelope.CreatedSkewSeconds = config.DefaultEnvelopeSignCreatedSkewSecs
	brokenCfg.MediationEnvelope.MaxBodyBytes = config.DefaultEnvelopeSignMaxBodyBytes

	brokenSc := scanner.New(brokenCfg)
	p.Reload(brokenCfg, brokenSc)

	// The envelope emitter pointer must be unchanged — same *Emitter
	// value, same signer key id. If reloadEnvelopeEmitter did install
	// a fresh emitter without a signer, or Reload swapped config with
	// the old signer still on the emitter, this assertion fails.
	afterEmitter := p.envelopeEmitterPtr.Load()
	if afterEmitter != beforeEmitter {
		t.Error("envelope emitter pointer changed after failed reload — old signer must be preserved")
	}
	if afterEmitter == nil || !afterEmitter.HasSigner() {
		t.Fatal("post-abort emitter lost its signer")
	}

	// The config pointer must also be unchanged — the fail-closed
	// contract is that a broken envelope signer aborts the WHOLE
	// reload, not just the envelope slot.
	if p.cfgPtr.Load() != beforeCfg {
		t.Error("cfgPtr swapped after failed reload — reload abort should preserve old cfg")
	}
}

// TestProxy_ReloadEnvelopeEmitter_DisabledNilsEmitter reloads from
// signing enabled to enabled=false and verifies the emitter pointer is
// nil, so transport inject sites see HasSigner()==false and no
// envelope header at all.
func TestProxy_ReloadEnvelopeEmitter_DisabledNilsEmitter(t *testing.T) {
	t.Parallel()

	p := envelopeReloadProxy(t)
	keyPath := writeEnvelopeKey(t)

	onCfg := config.Defaults()
	onCfg.Internal = nil
	onCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	enableEnvelopeSigning(t, onCfg, keyPath)
	p.Reload(onCfg, scanner.New(onCfg))

	offCfg := config.Defaults()
	offCfg.Internal = nil
	offCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	offCfg.MediationEnvelope.Enabled = false
	if err := offCfg.Validate(); err != nil {
		t.Fatalf("offCfg.Validate: %v", err)
	}
	p.Reload(offCfg, scanner.New(offCfg))

	// Atomic pointers to structs return a nil *Emitter as a typed nil.
	// Compare via the typed Load so a stale generic any interface does
	// not mask the assertion.
	if em := p.envelopeEmitterPtr.Load(); em != nil {
		t.Errorf("envelope emitter pointer should be nil after enabled=false reload, got %p", em)
	}
}

// compile-time check: the envelope package is actually imported (lint
// would otherwise prune the envelope.NewEmitter reference that only
// shows up inside reload lane wiring).
var _ = envelope.HeaderName
