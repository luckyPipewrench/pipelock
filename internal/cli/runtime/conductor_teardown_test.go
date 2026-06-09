//go:build enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// countingCloser is a conductorCloser that records how many times Close ran so a
// test can assert teardown closes the audit producer exactly once.
type countingCloser struct{ closes atomic.Int32 }

func (c *countingCloser) Close() error {
	c.closes.Add(1)
	return nil
}

type orderedQueueCloser struct {
	closes           atomic.Int32
	waitDone         *atomic.Bool
	closedBeforeWait atomic.Bool
}

func (c *orderedQueueCloser) Close() error {
	c.closes.Add(1)
	if c.waitDone != nil && !c.waitDone.Load() {
		c.closedBeforeWait.Store(true)
	}
	return nil
}

// TestTeardownConductor_StopsRuntimeAndIsIdempotent locks in the core teardown
// contract: cancel the poller sub-context, close the audit producer, flip the
// conductorDown gate, and do all of it exactly once even under repeated calls
// (the CRL watcher, expiry timer, and reload path can all race to call it).
func TestTeardownConductor_StopsRuntimeAndIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closer := &countingCloser{}
	s := &Server{}
	s.conductorProducer = closer
	s.setConductorCancel(cancel)

	if s.conductorDown.Load() {
		t.Fatal("conductorDown must start false")
	}

	s.teardownConductor("test revoke")

	if !s.conductorDown.Load() {
		t.Fatal("conductorDown must be true after teardown")
	}
	if ctx.Err() == nil {
		t.Fatal("teardown must cancel the conductor sub-context")
	}
	if got := closer.closes.Load(); got != 1 {
		t.Fatalf("producer Close count = %d, want 1", got)
	}

	// Idempotent: a second teardown (e.g. CRL watcher after reload already tore
	// down) must not re-close the producer or panic.
	s.teardownConductor("test revoke again")
	if got := closer.closes.Load(); got != 1 {
		t.Fatalf("producer Close count after 2nd teardown = %d, want 1", got)
	}
}

func TestTeardownConductor_WaitsBeforeClosingAuditQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var waitDone atomic.Bool
	queue := &orderedQueueCloser{waitDone: &waitDone}
	s := &Server{conductorAuditQueue: queue}
	s.setConductorCancel(cancel)
	s.setConductorWait(func() {
		if ctx.Err() == nil {
			t.Fatal("conductor wait ran before teardown cancelled the context")
		}
		waitDone.Store(true)
	})

	s.teardownConductor("test revoke")

	if !waitDone.Load() {
		t.Fatal("teardown must wait for conductor goroutines before closing the queue")
	}
	if got := queue.closes.Load(); got != 1 {
		t.Fatalf("queue Close count = %d, want 1", got)
	}
	if queue.closedBeforeWait.Load() {
		t.Fatal("queue lock was released before conductor goroutines stopped")
	}
}

func TestCleanupClosesConductorAuditQueue(t *testing.T) {
	queue := &countingCloser{}
	s := &Server{conductorAuditQueue: queue}

	s.cleanup()
	s.cleanup()

	if got := queue.closes.Load(); got != 1 {
		t.Fatalf("queue Close count = %d, want 1", got)
	}
	if s.conductorAuditQueue != nil {
		t.Fatalf("conductorAuditQueue = %T, want nil after cleanup", s.conductorAuditQueue)
	}
}

// TestTeardownConductor_NoopWhenNotRunning ensures teardown is a safe no-op when
// the follower Conductor runtime never launched (conductorCancel nil), e.g. on a
// proxy-only or Apache-core process where the CRL watcher still calls it.
func TestTeardownConductor_NoopWhenNotRunning(t *testing.T) {
	s := &Server{}
	s.teardownConductor("nothing to do")
	if s.conductorDown.Load() {
		t.Fatal("teardown with no running conductor must not flip conductorDown")
	}
}

// TestTeardownConductor_BeforeCancelPublishedFailsClosed covers the narrow
// startup window where Conductor handles exist but Start has not yet published
// the dedicated cancel func. A revocation/downgrade signal in that window must
// not be lost: mark Conductor down, close/detach existing handles, and cancel
// the sub-context immediately if it is published later.
func TestTeardownConductor_BeforeCancelPublishedFailsClosed(t *testing.T) {
	closer := &countingCloser{}
	s := &Server{
		conductorApply:    struct{}{},
		conductorProducer: closer,
	}

	s.teardownConductor("early revoke")

	if !s.conductorDown.Load() {
		t.Fatal("teardown with built Conductor handles must mark conductorDown even before cancel is published")
	}
	if got := closer.closes.Load(); got != 1 {
		t.Fatalf("producer Close count = %d, want 1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)
	if ctx.Err() == nil {
		t.Fatal("setConductorCancel after early teardown must immediately cancel the conductor sub-context")
	}
}

// TestExpireLicensedRuntime_TearsDownConductor proves the expiry timer path
// (server_lifecycle) stops the Conductor runtime on license expiry, parity with
// the agent-listener shutdown it already performed.
func TestExpireLicensedRuntime_TearsDownConductor(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)

	s.expireLicensedRuntime()

	if !s.conductorDown.Load() {
		t.Fatal("license expiry must tear down the Conductor runtime")
	}
	// Detection survives: the proxy keeps serving config after expiry teardown.
	if s.proxy.CurrentConfig() == nil {
		t.Fatal("proxy/detection must keep running after expiry teardown")
	}
}

// TestReloadCompletedHook_FiresAndRestores covers the test-only reload-cycle
// signal seam used by the cli-package reload tests to wait on the reload EVENT
// instead of polling a wall-clock deadline (the fix for the reload-test flake
// family).
func TestReloadCompletedHook_FiresAndRestores(t *testing.T) {
	var calls atomic.Int32
	restore := SetReloadCompletedHookForTest(func() { calls.Add(1) })
	fireReloadCompletedHook()
	if calls.Load() != 1 {
		t.Fatalf("hook calls = %d, want 1", calls.Load())
	}
	restore()
	fireReloadCompletedHook()
	if calls.Load() != 1 {
		t.Fatalf("hook calls after restore = %d, want 1 (hook should be cleared)", calls.Load())
	}
	// Clearing with nil is a no-op-safe path.
	restoreNil := SetReloadCompletedHookForTest(nil)
	fireReloadCompletedHook()
	restoreNil()
}

// TestApplyConductorPolicyBundle_FailsAfterTeardown proves the runtime gate:
// once teardownConductor has fired, no further signed policy bundles may be
// applied even if the apply cache handle is still present.
func TestApplyConductorPolicyBundle_FailsAfterTeardown(t *testing.T) {
	cache, err := applycache.Open(applycache.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("applycache.Open: %v", err)
	}
	s := &Server{conductorApply: cache}
	s.conductorDown.Store(true)
	if _, err := s.ApplyConductorPolicyBundle(conductor.PolicyBundle{}, ConductorApplyOptions{}); !errors.Is(err, applycache.ErrCacheRequired) {
		t.Fatalf("ApplyConductorPolicyBundle after teardown = %v, want ErrCacheRequired", err)
	}
}

// TestApplyConductorPolicyBundle_TeardownMidApplyAborts closes the in-flight
// window the entry/under-lock conductorDown checks cannot: a bundle that passes
// both guards and then loses its fleet entitlement WHILE staging must not reach
// the live-config reload or activate. The signature resolver is the injection
// seam — it runs during staging, after both guards, so flipping conductorDown
// there reproduces "teardownConductor fired mid-apply" deterministically.
func TestApplyConductorPolicyBundle_TeardownMidApplyAborts(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	liveBefore := s.proxy.CurrentConfig()
	bundle := signedRuntimePolicyBundle(t, signer, "bundle-1", 1, "", strings.Join([]string{
		"mode: strict",
		"api_allowlist:",
		"  - api.example.com",
		"",
	}, "\n"))

	// Real resolver, wrapped to tear down the fleet entitlement the first time
	// it is consulted (i.e. during signature verification in staging).
	base := signer.resolver()
	teardownDuringStage := func(keyID string) (conductor.SignatureKey, error) {
		s.teardownConductor("revoked mid-apply")
		return base(keyID)
	}

	_, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: teardownDuringStage})
	if !errors.Is(err, applycache.ErrEntitlementLost) {
		t.Fatalf("ApplyConductorPolicyBundle with mid-apply teardown = %v, want ErrEntitlementLost", err)
	}
	// The live proxy config must be untouched: the bundle never reloaded.
	if live := s.proxy.CurrentConfig(); live == nil || live.Mode == config.ModeStrict {
		t.Fatalf("live mode = %v, want the pre-apply mode (bundle must not have reloaded)", live)
	}
	if liveBefore != nil && s.proxy.CurrentConfig().Mode != liveBefore.Mode {
		t.Fatal("live config changed despite aborted apply")
	}
	// Nothing activated in the durable cache.
	cache, _ := s.conductorApply.(*applycache.Cache)
	if cache == nil {
		t.Fatalf("conductorApply: want *applycache.Cache, got %T", s.conductorApply)
	}
	if _, activeErr := cache.Active(); !errors.Is(activeErr, applycache.ErrNoValidBundle) {
		t.Fatalf("Active() after aborted apply = %v, want ErrNoValidBundle", activeErr)
	}
}

// TestRefreshLicenseCRL_RevokedTearsDownConductor proves gap 2 is closed: the
// runtime CRL watcher tears down a running Conductor follower (not just agent
// listeners) when the license is revoked, including the conductor-only case
// where there are no agent listeners at all.
func TestRefreshLicenseCRL_RevokedTearsDownConductor(t *testing.T) {
	tok, pubHex, crlPath := revokedLicenseConfigFixture(t)
	cfgYAML := strings.Join([]string{
		"mode: balanced",
		"license_key: " + strconv.Quote(tok),
		"license_public_key: " + strconv.Quote(pubHex),
		"license_crl_file: " + strconv.Quote(crlPath),
	}, "\n")
	cfgPath := writeServerTestConfig(t, cfgYAML)
	s, _ := newTestServer(t, func(o *ServerOpts) { o.ConfigFile = cfgPath })

	// Simulate a running follower-side Conductor runtime.
	_, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)

	if !s.refreshLicenseCRLOnce() {
		t.Fatal("refreshLicenseCRLOnce: want failClosed=true for a revoked license")
	}
	if !s.conductorDown.Load() {
		t.Fatal("CRL revocation must tear down the Conductor runtime")
	}
	// Detection must survive: the proxy keeps serving its config.
	if s.proxy.CurrentConfig() == nil {
		t.Fatal("proxy/detection must keep running after a fleet revocation teardown")
	}
}

// TestReload_FleetDowngradeTearsDownConductor proves gap 1 is closed: a config
// reload whose new license inputs no longer carry the fleet entitlement tears
// down the running Conductor follower, matching how agents are stripped on a
// revocation reload.
func TestReload_FleetDowngradeTearsDownConductor(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)

	proTok, proPubHex := agentsOnlyLicenseFixture(t)
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.LicenseKey = proTok
	newCfg.LicensePublicKey = proPubHex

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !s.conductorDown.Load() {
		t.Fatal("reload with an agents-only (no fleet) license must tear down Conductor")
	}
	if s.proxy.CurrentConfig() == nil {
		t.Fatal("proxy/detection must keep running after a fleet-downgrade teardown")
	}
}

// TestReload_NoLicenseChangeKeepsConductor is the negative control: an unrelated
// reload that does not touch license inputs must NOT tear down a healthy
// Conductor runtime (no over-enforcement).
func TestReload_NoLicenseChangeKeepsConductor(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)

	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.Mode = config.ModeStrict

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if s.conductorDown.Load() {
		t.Fatal("a reload that does not change license inputs must not tear down Conductor")
	}
}

// TestReload_UnverifiableLicenseInputKeepsConductor proves the Item B fix on
// the Conductor surface: a reload that introduces an UNVERIFIABLE new license
// input (an unreadable CRL path) must NOT tear down a still-entitled follower.
// License inputs are restart-only, so the effective fleet entitlement (the env
// token installed by the fixture) is unchanged; tearing down on a typo would be
// a denial-of-service, not fail-closed security.
func TestReload_UnverifiableLicenseInputKeepsConductor(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)

	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.LicenseCRLFile = filepath.Join(t.TempDir(), "missing.crl.json")

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if s.conductorDown.Load() {
		t.Fatal("an unverifiable new CRL input must NOT tear down a still-entitled Conductor")
	}
	if s.proxy.CurrentConfig() == nil {
		t.Fatal("proxy/detection must keep running")
	}
}

// TestReload_RevokedLicenseTearsDownConductor proves the genuine-loss side of
// the Item B classification: a reload whose new license inputs PROVE revocation
// (a signed CRL revoking the token) tears the follower down fail-closed, exactly
// like the fleet-downgrade case.
func TestReload_RevokedLicenseTearsDownConductor(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	s.setConductorCancel(cancel)

	tok, pubHex, crlPath := revokedLicenseConfigFixture(t)
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.LicenseKey = tok
	newCfg.LicensePublicKey = pubHex
	newCfg.LicenseCRLFile = crlPath

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !s.conductorDown.Load() {
		t.Fatal("a reload with a revoked license must tear down Conductor")
	}
	if s.proxy.CurrentConfig() == nil {
		t.Fatal("proxy/detection must keep running after a revocation teardown")
	}
}

// revokedLicenseConfigFixture issues a license token and a signed CRL that
// revokes it, writes the CRL to disk, and returns the token, its public key
// (hex), and the CRL path for use in a config (not env).
func revokedLicenseConfigFixture(t *testing.T) (token, pubHex, crlPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	const licenseID = "revoked-config-license"
	tok, err := license.Issue(license.License{
		ID:        licenseID,
		Email:     "test@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  []string{license.FeatureAgents, license.FeatureFleet},
		Tier:      "enterprise",
	}, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	crl, err := license.SignCRL(license.CRLPayload{
		Version:   license.CRLVersion,
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Revoked: []license.RevokedLicense{{
			ID:        licenseID,
			Reason:    "test revocation",
			RevokedAt: now.Unix(),
		}},
	}, priv)
	if err != nil {
		t.Fatalf("license.SignCRL: %v", err)
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("Marshal CRL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "license.crl.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(CRL): %v", err)
	}
	return tok, hex.EncodeToString(pub), path
}

// agentsOnlyLicenseFixture issues a valid Pro-tier token that carries only the
// agents feature (no fleet), plus its public key hex, for testing fleet
// downgrade detection on reload.
func agentsOnlyLicenseFixture(t *testing.T) (token, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	tok, err := license.Issue(license.License{
		ID:        "agents-only-license",
		Email:     "test@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
		Tier:      "pro",
	}, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	return tok, hex.EncodeToString(pub)
}
