// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
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
	t.Cleanup(p.Close)
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

// TestProxy_NewInitializesSigningEmitterAtStartup exercises the startup lane
// that previously left sign:true configs with a header-only emitter until the
// first reload. The first outbound request after New must already be signed.
func TestProxy_NewInitializesSigningEmitterAtStartup(t *testing.T) {
	t.Parallel()

	var gotSigInput string
	var gotSig string
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSigInput = r.Header.Get("Signature-Input")
		gotSig = r.Header.Get("Signature")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	enableEnvelopeSigning(t, cfg, writeEnvelopeKey(t))

	// Mimic the pre-fix startup path: runtime hands proxy.New a header-only
	// emitter. proxy.New must upgrade it to a signer-backed emitter before
	// serving the first request.
	startupEmitter := envelope.NewEmitter(envelope.EmitterConfig{
		ConfigHash: cfg.Hash(),
	})

	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New(), WithEnvelopeEmitter(startupEmitter))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	if em := p.envelopeEmitterPtr.Load(); em == nil || !em.HasSigner() {
		t.Fatal("startup proxy should install a signing emitter immediately")
	}

	handler := p.buildHandler(p.buildMux())
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL+"/signed", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if gotSigInput == "" || gotSig == "" {
		t.Fatalf("first startup request was unsigned: Signature-Input=%q Signature=%q", gotSigInput, gotSig)
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

// TestProxy_ReloadEnvelopeFailurePreservesReceiptEmitter verifies that a
// fail-closed envelope reload does not partially advance the receipt emitter.
// The config swap aborts, so the signed-receipt state must remain on the old
// emitter rather than moving to a config that never became active.
func TestProxy_ReloadEnvelopeFailurePreservesReceiptEmitter(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	_, receiptPrivA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey receipt A: %v", err)
	}
	_, receiptPrivB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey receipt B: %v", err)
	}

	receiptKeyA := filepath.Join(keyDir, "receiptA.key")
	if err := signing.SavePrivateKey(receiptPrivA, receiptKeyA); err != nil {
		t.Fatalf("SavePrivateKey receipt A: %v", err)
	}
	receiptKeyB := filepath.Join(keyDir, "receiptB.key")
	if err := signing.SavePrivateKey(receiptPrivB, receiptKeyB); err != nil {
		t.Fatalf("SavePrivateKey receipt B: %v", err)
	}

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                t.TempDir(),
		CheckpointInterval: 1000,
	}, nil, receiptPrivA)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	initialReceiptEmitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    receiptPrivA,
		ConfigHash: "hash-a",
		Principal:  "local",
		Actor:      "pipelock",
	})

	startCfg := config.Defaults()
	startCfg.Internal = nil
	startCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	startCfg.FlightRecorder.SigningKeyPath = receiptKeyA
	enableEnvelopeSigning(t, startCfg, writeEnvelopeKey(t))

	p, err := New(startCfg, audit.NewNop(), scanner.New(startCfg), metrics.New(),
		WithRecorder(rec),
		WithReceiptEmitter(initialReceiptEmitter),
		WithReceiptKeyPath(receiptKeyA),
	)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	beforeReceiptEmitter := p.receiptEmitterPtr.Load()
	if beforeReceiptEmitter == nil {
		t.Fatal("expected initial receipt emitter")
	}

	brokenEnvelopeKey := writeEnvelopeKey(t)
	if err := os.Remove(brokenEnvelopeKey); err != nil {
		t.Fatalf("removing broken envelope key: %v", err)
	}

	brokenCfg := config.Defaults()
	brokenCfg.Internal = nil
	brokenCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	brokenCfg.FlightRecorder.SigningKeyPath = receiptKeyB
	brokenCfg.MediationEnvelope.Enabled = true
	brokenCfg.MediationEnvelope.Sign = true
	brokenCfg.MediationEnvelope.SigningKeyPath = brokenEnvelopeKey
	brokenCfg.MediationEnvelope.KeyID = config.DefaultEnvelopeSignKeyID
	brokenCfg.MediationEnvelope.SignedComponents = config.DefaultEnvelopeSignedComponents()
	brokenCfg.MediationEnvelope.CreatedSkewSeconds = config.DefaultEnvelopeSignCreatedSkewSecs
	brokenCfg.MediationEnvelope.MaxBodyBytes = config.DefaultEnvelopeSignMaxBodyBytes

	p.Reload(brokenCfg, scanner.New(brokenCfg))

	if afterReceiptEmitter := p.receiptEmitterPtr.Load(); afterReceiptEmitter != beforeReceiptEmitter {
		t.Fatal("receipt emitter changed even though envelope reload aborted")
	}
}

// TestProxy_ReloadEnvelopeEmitter_InPlaceKeyRotation covers the
// file-content-rotation path that the other reload tests miss:
// ops overwrites the SAME signing_key_path with new key bytes and
// triggers a reload with an otherwise-identical config. The reload
// must install a fresh emitter with a fresh signer backed by the
// new key, and signatures produced afterwards must verify with the
// new public key and fail with the old one.
//
// This exercises the "Kubernetes Secret atomic symlink swap" style
// of key rotation where the path is stable across versions and
// only the bytes change.
func TestProxy_ReloadEnvelopeEmitter_InPlaceKeyRotation(t *testing.T) {
	t.Parallel()

	p := envelopeReloadProxy(t)

	// First key pair.
	pubV1, privV1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey v1: %v", err)
	}
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "envelope-ed25519.key")
	if err := signing.SavePrivateKey(privV1, keyPath); err != nil {
		t.Fatalf("SavePrivateKey v1: %v", err)
	}

	onCfg := config.Defaults()
	onCfg.Internal = nil
	onCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	enableEnvelopeSigning(t, onCfg, keyPath)
	p.Reload(onCfg, scanner.New(onCfg))
	firstEmitter := p.envelopeEmitterPtr.Load()
	if firstEmitter == nil || !firstEmitter.HasSigner() {
		t.Fatal("first reload should have installed a signing emitter")
	}

	// Sanity: signature produced before rotation verifies with pubV1.
	firstSig := signAndCaptureForTest(t, firstEmitter, "/before-rotation")
	if !verifySigForTest(t, pubV1, firstSig.base, firstSig.sigBytes) {
		t.Fatal("pre-rotation signature does not verify with v1 public key")
	}

	// Rotate: overwrite the SAME path with new key bytes. Path is
	// identical; only the bytes change. SavePrivateKey uses atomic
	// temp+rename internally.
	pubV2, privV2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey v2: %v", err)
	}
	if err := signing.SavePrivateKey(privV2, keyPath); err != nil {
		t.Fatalf("SavePrivateKey v2: %v", err)
	}

	// Reload with the same config. reloadEnvelopeEmitter must re-read
	// the key file, install a fresh Signer over the new bytes, and
	// swap the outer Emitter pointer.
	rotatedCfg := config.Defaults()
	rotatedCfg.Internal = nil
	rotatedCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	enableEnvelopeSigning(t, rotatedCfg, keyPath)
	p.Reload(rotatedCfg, scanner.New(rotatedCfg))

	secondEmitter := p.envelopeEmitterPtr.Load()
	if secondEmitter == nil || !secondEmitter.HasSigner() {
		t.Fatal("second reload should have installed a signing emitter")
	}
	if secondEmitter == firstEmitter {
		t.Fatal("in-place key rotation should install a fresh *Emitter pointer")
	}

	// Post-rotation signature must verify with pubV2 and FAIL with pubV1.
	secondSig := signAndCaptureForTest(t, secondEmitter, "/after-rotation")
	if !verifySigForTest(t, pubV2, secondSig.base, secondSig.sigBytes) {
		t.Fatal("post-rotation signature does not verify with v2 public key")
	}
	if verifySigForTest(t, pubV1, secondSig.base, secondSig.sigBytes) {
		t.Fatal("post-rotation signature must NOT verify with the old v1 public key")
	}
}

// capturedSignature is a tiny record of a signature + the base
// string used to produce it, so tests can run ed25519.Verify
// without re-implementing the RFC 9421 base builder.
type capturedSignature struct {
	base     string
	sigBytes []byte
}

// signAndCaptureForTest signs a canned GET request through the
// given emitter and returns the resulting base + signature bytes
// so the caller can verify against arbitrary public keys.
func signAndCaptureForTest(t *testing.T, em *envelope.Emitter, path string) capturedSignature {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://upstream.example"+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := em.InjectAndSign(req, nil, envelope.BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000030",
		Action:    "read",
		Verdict:   config.ActionAllow,
		Actor:     "test-agent",
		ActorAuth: envelope.ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	sigInputDict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	if err != nil {
		t.Fatalf("parse Signature-Input: %v", err)
	}
	member, ok := sigInputDict.Get("pipelock1")
	if !ok {
		t.Fatal("pipelock1 missing from Signature-Input")
	}
	inner, ok := member.(httpsfv.InnerList)
	if !ok {
		t.Fatalf("pipelock1 is %T, not InnerList", member)
	}

	var b strings.Builder
	for _, item := range inner.Items {
		name, _ := item.Value.(string)
		switch name {
		case "@method":
			b.WriteString(`"@method": GET` + "\n")
		case "@target-uri":
			b.WriteString(`"@target-uri": ` + req.URL.String() + "\n")
		case "pipelock-mediation":
			b.WriteString(`"pipelock-mediation": ` + req.Header.Get(envelope.HeaderName) + "\n")
		default:
			t.Fatalf("unsupported component in test helper: %q", name)
		}
	}
	serialized, err := httpsfv.Marshal(inner)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	b.WriteString(`"@signature-params": ` + serialized)

	sigDict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature"))
	if err != nil {
		t.Fatalf("parse Signature: %v", err)
	}
	sigMember, _ := sigDict.Get("pipelock1")
	sigBytes, _ := sigMember.(httpsfv.Item).Value.([]byte)
	return capturedSignature{base: b.String(), sigBytes: sigBytes}
}

// verifySigForTest runs ed25519.Verify without failing the test —
// tests that want success call it and assert the return value.
func verifySigForTest(t *testing.T, pub ed25519.PublicKey, base string, sig []byte) bool {
	t.Helper()
	return ed25519.Verify(pub, []byte(base), sig)
}

// TestProxy_ReloadEnvelopeEmitter_ConcurrentWithTraffic is a race-
// detector-focused soak test: hammers the fetch handler with
// concurrent requests while repeatedly reloading the config with a
// freshly-rotated signing key. Every response must carry a valid
// pipelock1 signature under either the old or the new key (no
// unsigned responses, no stale-signer crashes, no data races).
//
// This exercises the atomic.Pointer swap on envelopeEmitterPtr under
// load. The structural guarantee is that in-flight requests hold the
// old *Emitter pointer and finish against the old signer, while new
// requests pick up the new one. The soak verifies that empirically
// against a real handler with real redirect / signing paths.
func TestProxy_ReloadEnvelopeEmitter_ConcurrentWithTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test; skipped under -short")
	}
	t.Parallel()

	// The upstream records the Signature / Signature-Input /
	// Pipelock-Mediation headers it actually saw into a shared sync.Map
	// keyed by request URL. The fetch handler strips upstream response
	// headers before writing its own JSON response body back to the
	// client, so an in-process observation map is the only way for the
	// soak workers to see what pipelock sent on the wire.
	var observations sync.Map
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed := soakObservedHeaders{
			Signature:      r.Header.Get("Signature"),
			SignatureInput: r.Header.Get("Signature-Input"),
			Mediation:      r.Header.Get(envelope.HeaderName),
		}
		observations.Store(r.URL.RequestURI(), observed)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	// Pre-generate 4 key files so reloads can rotate between them.
	// The public halves stay in memory so the soak can verify each
	// response signature against the full rotation set and accept a
	// match from any one of them.
	keyDir := t.TempDir()
	keyPaths := make([]string, 4)
	pubKeys := make([]ed25519.PublicKey, 4)
	for i := range keyPaths {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey %d: %v", i, err)
		}
		keyPaths[i] = filepath.Join(keyDir, "env-"+string(rune('a'+i))+".key")
		if err := signing.SavePrivateKey(priv, keyPaths[i]); err != nil {
			t.Fatalf("SavePrivateKey %d: %v", i, err)
		}
		pubKeys[i] = pub
	}

	// Shared-path key file — each reload overwrites this from one
	// of the pre-generated sources.
	sharedPath := filepath.Join(keyDir, "shared.key")
	if err := copyFileForTest(keyPaths[0], sharedPath); err != nil {
		t.Fatalf("initial copy: %v", err)
	}

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	// Disable the per-source-IP rate limit — the soak intentionally
	// fires 200 hits from a single test client so we would otherwise
	// collide with the default 20/minute cap and see 429s that have
	// nothing to do with signing correctness.
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	enableEnvelopeSigning(t, cfg, sharedPath)

	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	handler := p.buildHandler(mux)

	// Traffic goroutines: 8 workers × 25 requests = 200 total.
	const workers = 8
	const perWorker = 25
	var wg sync.WaitGroup
	// Buffer covers workers + the reload goroutine so neither blocks.
	errCh := make(chan string, workers*perWorker+20)
	stop := make(chan struct{})

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// Each request gets a unique path so the shared
				// observation map can key on it without collisions.
				hitPath := fmt.Sprintf("/hit/w%d/n%d", id, i)
				r := httptest.NewRequest(http.MethodGet,
					"/fetch?url="+upstream.URL+hitPath, nil)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, r)
				if rr.Code != http.StatusOK {
					errCh <- fmt.Sprintf("worker %d hit %d: status %d", id, i, rr.Code)
					continue
				}
				// Pull the upstream-observed envelope + signature
				// out of the shared observation map and verify it
				// against one of the rotated public keys. Any hit
				// without a signature, or with a signature that
				// fails under every rotated key, is a fail-closed
				// regression.
				raw, ok := observations.Load(hitPath)
				if !ok {
					errCh <- fmt.Sprintf("worker %d hit %d: upstream never logged %s", id, i, hitPath)
					continue
				}
				observed := raw.(soakObservedHeaders) //nolint:errcheck // type known by construction
				if observed.Signature == "" || observed.SignatureInput == "" || observed.Mediation == "" {
					errCh <- fmt.Sprintf("worker %d hit %d: upstream saw no pipelock envelope (sig=%q input=%q med=%q)",
						id, i, observed.Signature, observed.SignatureInput, observed.Mediation)
					continue
				}
				if !soakVerifyAgainstAnyKey(t, pubKeys, "GET", upstream.URL+hitPath,
					observed.Mediation, observed.SignatureInput, observed.Signature) {
					errCh <- fmt.Sprintf("worker %d hit %d: signature did not verify under any rotated key", id, i)
				}
			}
		}(w)
	}

	// Reload goroutine: rotates the key file between the 4 source
	// keys and triggers Reload() every few milliseconds.
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		for i := 1; i <= 20; i++ {
			src := keyPaths[i%len(keyPaths)]
			if err := copyFileForTest(src, sharedPath); err != nil {
				errCh <- fmt.Sprintf("rotate %d: %v", i, err)
				return
			}
			rotatedCfg := config.Defaults()
			rotatedCfg.Internal = nil
			rotatedCfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			rotatedCfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
			enableEnvelopeSigning(t, rotatedCfg, sharedPath)
			p.Reload(rotatedCfg, scanner.New(rotatedCfg))
			// Yield so traffic workers can make progress between
			// reload churn cycles. Using time.Sleep rather than
			// runtime.Gosched to give the scheduler a real chance.
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()
	close(stop)
	<-reloadDone
	close(errCh)

	var errs []string
	for e := range errCh {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		t.Fatalf("soak failures (%d):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}

	// After the soak, the emitter must still be signing.
	if em := p.envelopeEmitterPtr.Load(); em == nil || !em.HasSigner() {
		t.Fatal("envelope emitter lost its signer during soak")
	}
}

// soakObservedHeaders is the envelope + signature payload the soak
// upstream snapshots for each request. Workers look it up via a
// sync.Map keyed by the unique request URL path.
type soakObservedHeaders struct {
	Signature      string
	SignatureInput string
	Mediation      string
}

// soakVerifyAgainstAnyKey reconstructs the RFC 9421 signature base
// from the soak worker's captured outbound state (method, target-uri,
// observed Pipelock-Mediation header) and tries to verify against
// every public key in the rotation set. Returns true on the first
// match. The soak test accepts ANY match because in-flight requests
// can hold any of the rotated emitters during the key churn cycle.
func soakVerifyAgainstAnyKey(t *testing.T, pubKeys []ed25519.PublicKey, method, targetURI, mediationHeader, sigInputHeader, sigHeader string) bool {
	t.Helper()

	sigInputDict, err := httpsfv.UnmarshalDictionary([]string{sigInputHeader})
	if err != nil {
		t.Logf("soak parse Signature-Input: %v (value=%q)", err, sigInputHeader)
		return false
	}
	member, ok := sigInputDict.Get("pipelock1")
	if !ok {
		t.Logf("soak: pipelock1 missing from Signature-Input")
		return false
	}
	inner, ok := member.(httpsfv.InnerList)
	if !ok {
		t.Logf("soak: pipelock1 is %T, want InnerList", member)
		return false
	}

	const (
		compMethod    = "@method"
		compTargetURI = "@target-uri"
		compMediation = "pipelock-mediation"
	)
	var b strings.Builder
	for _, item := range inner.Items {
		name, _ := item.Value.(string)
		switch name {
		case compMethod:
			fmt.Fprintf(&b, `"%s": %s`+"\n", compMethod, strings.ToUpper(method))
		case compTargetURI:
			fmt.Fprintf(&b, `"%s": %s`+"\n", compTargetURI, targetURI)
		case compMediation:
			fmt.Fprintf(&b, `"%s": %s`+"\n", compMediation, mediationHeader)
		default:
			t.Logf("soak: unsupported component %q in Signature-Input", name)
			return false
		}
	}
	serialised, err := httpsfv.Marshal(inner)
	if err != nil {
		t.Logf("soak: marshal sig params: %v", err)
		return false
	}
	fmt.Fprintf(&b, `"@signature-params": %s`, serialised)
	base := b.String()

	sigDict, err := httpsfv.UnmarshalDictionary([]string{sigHeader})
	if err != nil {
		t.Logf("soak parse Signature: %v", err)
		return false
	}
	sigMember, ok := sigDict.Get("pipelock1")
	if !ok {
		t.Logf("soak: pipelock1 missing from Signature")
		return false
	}
	sigItem, ok := sigMember.(httpsfv.Item)
	if !ok {
		return false
	}
	sigBytes, ok := sigItem.Value.([]byte)
	if !ok {
		return false
	}

	for _, pub := range pubKeys {
		if ed25519.Verify(pub, []byte(base), sigBytes) {
			return true
		}
	}
	return false
}

// copyFileForTest writes the contents of src to dst using the same
// atomic temp+rename helper as signing.SavePrivateKey, so the dst
// path passes the 0o600 permissions check on reload. dst may or may
// not already exist; if it exists the contents are overwritten.
func copyFileForTest(src, dst string) error {
	priv, err := signing.LoadPrivateKeyFile(src)
	if err != nil {
		return err
	}
	return signing.SavePrivateKey(priv, dst)
}

// compile-time check: the envelope package is actually imported (lint
// would otherwise prune the envelope.NewEmitter reference that only
// shows up inside reload lane wiring).
var _ = envelope.HeaderName
