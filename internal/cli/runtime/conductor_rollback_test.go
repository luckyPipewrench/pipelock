//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// rollbackSigner is a single ed25519 rollback-purpose signer for runtime tests.
type rollbackSigner struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newRollbackSigner(t *testing.T, id string) rollbackSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return rollbackSigner{id: id, pub: pub, priv: priv}
}

// combinedResolver resolves the policy-bundle signer plus any rollback signers,
// mirroring how the real roster-backed resolver resolves every signer purpose.
func combinedResolver(policy runtimePolicySigner, rollbacks ...rollbackSigner) conductor.SignatureKeyResolver {
	return func(signerKeyID string) (conductor.SignatureKey, error) {
		if signerKeyID == policy.id {
			return conductor.SignatureKey{
				PublicKey:  policy.pub,
				KeyPurpose: signing.PurposePolicyBundleSigning,
				NotBefore:  time.Now().Add(-time.Hour),
				NotAfter:   time.Now().Add(time.Hour),
			}, nil
		}
		for _, rb := range rollbacks {
			if signerKeyID == rb.id {
				return conductor.SignatureKey{
					PublicKey:  rb.pub,
					KeyPurpose: signing.PurposePolicyBundleRollback,
					NotBefore:  time.Now().Add(-time.Hour),
					NotAfter:   time.Now().Add(time.Hour),
				}, nil
			}
		}
		return conductor.SignatureKey{}, conductor.ErrSignatureVerification
	}
}

func signedRuntimeRollbackAuth(t *testing.T, current, target conductor.PolicyBundle, signers ...rollbackSigner) conductor.RollbackAuthorization {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: "rollback-1",
		OrgID:           "org-main",
		FleetID:         "prod",
		CurrentBundleID: current.BundleID,
		CurrentVersion:  current.Version,
		TargetBundleID:  target.BundleID,
		TargetVersion:   target.Version,
		Counter:         1,
		Reason:          "operator rollback",
		CreatedAt:       time.Now().UTC().Add(-time.Minute),
		ExpiresAt:       time.Now().UTC().Add(time.Hour),
	}
	preimage, err := auth.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	for _, s := range signers {
		auth.Signatures = append(auth.Signatures, conductor.SignatureProof{
			SignerKeyID: s.id,
			KeyPurpose:  signing.PurposePolicyBundleRollback,
			Algorithm:   conductor.SignatureAlgorithmEd25519,
			Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(s.priv, preimage)),
		})
	}
	return auth
}

const (
	// Both bundles use strict mode so a rollback (bundle-2 -> bundle-1) is not a
	// security downgrade (the reload path independently rejects strict -> balanced).
	// They differ only in the allowlist entry, which is the observable difference
	// the rollback restores.
	rollbackTestBundle1YAML = "mode: strict\napi_allowlist:\n  - api1.example.com\n"
	rollbackTestBundle2YAML = "mode: strict\napi_allowlist:\n  - api2.example.com\n"
	rollbackBundle1Host     = "api1.example.com"
	rollbackBundle2Host     = "api2.example.com"
)

func liveAllowlistHas(t *testing.T, s *Server, host string) bool {
	t.Helper()
	live := s.proxy.CurrentConfig()
	if live == nil {
		t.Fatal("live config is nil")
	}
	for _, h := range live.APIAllowlist {
		if h == host {
			return true
		}
	}
	return false
}

// applyTwoBundles applies bundle-1 then bundle-2 (with bundle-1 as base) to the
// server's apply cache, returning the cache and the two bundles. After this the
// active bundle is bundle-2 and its on-disk BaseHash points at bundle-1.
func applyTwoBundles(t *testing.T, s *Server, policy runtimePolicySigner) (*applycache.Cache, conductor.PolicyBundle, conductor.PolicyBundle) {
	t.Helper()
	b1 := signedRuntimePolicyBundle(t, policy, "bundle-1", 1, "", rollbackTestBundle1YAML)
	if _, err := s.ApplyConductorPolicyBundle(b1, ConductorApplyOptions{Resolver: policy.resolver()}); err != nil {
		t.Fatalf("apply bundle-1: %v", err)
	}
	b1Hash, err := b1.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(bundle-1): %v", err)
	}
	b2 := signedRuntimePolicyBundle(t, policy, "bundle-2", 2, b1Hash, rollbackTestBundle2YAML)
	if _, err := s.ApplyConductorPolicyBundle(b2, ConductorApplyOptions{Resolver: policy.resolver()}); err != nil {
		t.Fatalf("apply bundle-2: %v", err)
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	if cache == nil {
		t.Fatalf("conductorApply: want *applycache.Cache, got %T", s.conductorApply)
	}
	return cache, b1, b2
}

func TestNewServer_WiresConductorRollbackPoller(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	if s.conductorRollback == nil {
		t.Fatal("conductor rollback poller should be wired when conductor.enabled")
	}
}

// TestConductorRollbackContextProvider proves the provider walks one step back
// through the on-disk bundle history: with only one bundle applied it reports
// ok=false (nothing to roll back to); with two it reports current=bundle-2,
// target=bundle-1.
func TestConductorRollbackContextProvider(t *testing.T) {
	s, policy := newConductorApplyTestServer(t)

	// No bundle applied yet: ok=false, no error.
	cache, _ := s.conductorApply.(*applycache.Cache)
	provider := conductorRollbackContextProvider{cache: cache}
	if _, _, ok, err := provider.RollbackContext(); err != nil || ok {
		t.Fatalf("RollbackContext() with no bundle = ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// One bundle applied: still nothing prior to roll back to.
	b1 := signedRuntimePolicyBundle(t, policy, "bundle-1", 1, "", rollbackTestBundle1YAML)
	if _, err := s.ApplyConductorPolicyBundle(b1, ConductorApplyOptions{Resolver: policy.resolver()}); err != nil {
		t.Fatalf("apply bundle-1: %v", err)
	}
	if _, _, ok, err := provider.RollbackContext(); err != nil || ok {
		t.Fatalf("RollbackContext() with one bundle = ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// Two bundles: current=bundle-2, target=bundle-1.
	b1Hash, err := b1.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(bundle-1): %v", err)
	}
	b2 := signedRuntimePolicyBundle(t, policy, "bundle-2", 2, b1Hash, rollbackTestBundle2YAML)
	if _, err := s.ApplyConductorPolicyBundle(b2, ConductorApplyOptions{Resolver: policy.resolver()}); err != nil {
		t.Fatalf("apply bundle-2: %v", err)
	}
	current, target, ok, err := provider.RollbackContext()
	if err != nil || !ok {
		t.Fatalf("RollbackContext() with two bundles = ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if current.BundleID != "bundle-2" || current.Version != 2 {
		t.Fatalf("current = %s/%d, want bundle-2/2", current.BundleID, current.Version)
	}
	if target.BundleID != "bundle-1" || target.Version != 1 {
		t.Fatalf("target = %s/%d, want bundle-1/1", target.BundleID, target.Version)
	}
}

// TestConductorRollbackApplierRestoresPriorBundle is the end-to-end happy path:
// after applying bundle-1 then bundle-2 (live allowlist = bundle-2's), a signed
// rollback authorization drives the applier through the real apply boundary and
// the live config reverts to bundle-1's allowlist.
func TestConductorRollbackApplierRestoresPriorBundle(t *testing.T) {
	s, policy := newConductorApplyTestServer(t)
	cache, b1, b2 := applyTwoBundles(t, s, policy)

	if !liveAllowlistHas(t, s, rollbackBundle2Host) {
		t.Fatalf("pre-rollback live allowlist missing %q (bundle-2)", rollbackBundle2Host)
	}

	rb1 := newRollbackSigner(t, "rollback-1")
	rb2 := newRollbackSigner(t, "rollback-2")
	auth := signedRuntimeRollbackAuth(t, b2, b1, rb1, rb2)

	applier := conductorRollbackApplier{
		server:   s,
		cache:    cache,
		resolver: combinedResolver(policy, rb1, rb2),
	}
	if err := applier.ApplyRollback(auth); err != nil {
		t.Fatalf("ApplyRollback() error = %v", err)
	}

	active, err := cache.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if active.Bundle.BundleID != "bundle-1" || active.Bundle.Version != 1 {
		t.Fatalf("post-rollback active = %s/%d, want bundle-1/1", active.Bundle.BundleID, active.Bundle.Version)
	}
	if !liveAllowlistHas(t, s, rollbackBundle1Host) {
		t.Fatalf("post-rollback live allowlist missing %q (bundle-1)", rollbackBundle1Host)
	}
	if liveAllowlistHas(t, s, rollbackBundle2Host) {
		t.Fatalf("post-rollback live allowlist still has %q (bundle-2)", rollbackBundle2Host)
	}

	provider := conductorRollbackContextProvider{cache: cache}
	if _, _, ok, err := provider.RollbackContext(); err != nil || ok {
		t.Fatalf("post-rollback RollbackContext() = ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

// TestConductorRollbackApplierUnderSignedThreshold proves the applier fails
// closed when the authorization lacks the required signature threshold: the
// existing authorizeVersionTransition path rejects it and the active bundle is
// unchanged.
func TestConductorRollbackApplierUnderSignedThreshold(t *testing.T) {
	s, policy := newConductorApplyTestServer(t)
	cache, b1, b2 := applyTwoBundles(t, s, policy)

	rb1 := newRollbackSigner(t, "rollback-1")
	// Only one signer: below RequiredCatastrophicSigners (2).
	auth := signedRuntimeRollbackAuth(t, b2, b1, rb1)
	applier := conductorRollbackApplier{server: s, cache: cache, resolver: combinedResolver(policy, rb1)}
	if err := applier.ApplyRollback(auth); err == nil {
		t.Fatal("ApplyRollback() with under-threshold signatures = nil, want error")
	}
	active, err := cache.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if active.Bundle.BundleID != "bundle-2" {
		t.Fatalf("active after rejected rollback = %s, want bundle-2 (unchanged)", active.Bundle.BundleID)
	}
}

// TestConductorRollbackApplierNoPriorFailsClosed proves that with only one
// bundle on disk (no prior to roll back to) the applier returns an error rather
// than silently succeeding.
func TestConductorRollbackApplierNoPriorFailsClosed(t *testing.T) {
	s, policy := newConductorApplyTestServer(t)
	b1 := signedRuntimePolicyBundle(t, policy, "bundle-1", 1, "", rollbackTestBundle1YAML)
	if _, err := s.ApplyConductorPolicyBundle(b1, ConductorApplyOptions{Resolver: policy.resolver()}); err != nil {
		t.Fatalf("apply bundle-1: %v", err)
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	rb1 := newRollbackSigner(t, "rollback-1")
	rb2 := newRollbackSigner(t, "rollback-2")
	auth := signedRuntimeRollbackAuth(t, b1, b1, rb1, rb2)
	applier := conductorRollbackApplier{server: s, cache: cache, resolver: combinedResolver(policy, rb1, rb2)}
	if err := applier.ApplyRollback(auth); !errors.Is(err, applycache.ErrNoValidBundle) {
		t.Fatalf("ApplyRollback() with no prior = %v, want ErrNoValidBundle", err)
	}
}

// TestBuildConductorRollbackPollerDisabled confirms a no-op (nil, nil) when
// conductor is not enabled.
func TestBuildConductorRollbackPollerDisabled(t *testing.T) {
	s := &Server{}
	poller, err := s.buildConductorRollbackPoller(&config.Config{Conductor: config.Conductor{Enabled: false}}, io.Discard)
	if err != nil {
		t.Fatalf("disabled buildConductorRollbackPoller() error = %v", err)
	}
	if poller != nil {
		t.Fatal("disabled buildConductorRollbackPoller() poller = non-nil, want nil")
	}
}

// TestBuildConductorRollbackPollerNoCacheFailsClosed proves the builder fails
// closed when conductor.enabled but the apply cache was never opened (a wiring
// error), rather than launching a poller that can never read a bundle.
func TestBuildConductorRollbackPollerNoCacheFailsClosed(t *testing.T) {
	s := &Server{} // conductorApply is nil
	_, err := s.buildConductorRollbackPoller(&config.Config{Conductor: config.Conductor{Enabled: true}}, io.Discard)
	if !errors.Is(err, applycache.ErrCacheRequired) {
		t.Fatalf("buildConductorRollbackPoller() no-cache err = %v, want ErrCacheRequired", err)
	}
}

// TestBuildConductorRollbackPollerErrorPaths covers the fail-closed branches
// after the cache check: bad mTLS client cert, bad trust roster (the rollback
// poller ALWAYS verifies signed authorizations, regardless of
// honor_remote_kill_switch), and an unparseable poll interval.
func TestBuildConductorRollbackPollerErrorPaths(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	rosterPath := filepath.Join(dir, "trust-roster.json")
	bundlePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rootFingerprint := writeRuntimeTrustRoster(t, rosterPath, bundlePub, "policy-signer-1", signing.PurposePolicyBundleSigning)
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	// A real opened cache so the builder gets past the cache check.
	cacheDir := filepath.Join(dir, "bundles")
	cache, err := applycache.Open(applycache.Config{Dir: cacheDir})
	if err != nil {
		t.Fatalf("Open(cache): %v", err)
	}

	base := config.Conductor{
		Enabled:                    true,
		ConductorURL:               "https://conductor.example",
		OrgID:                      "org-main",
		FleetID:                    "prod",
		InstanceID:                 "pl-prod-1",
		TrustRosterPath:            rosterPath,
		TrustRosterRootFingerprint: rootFingerprint,
		ServerCAFile:               caPath,
		ClientCertPath:             clientCertPath,
		ClientKeyPath:              clientKeyPath,
		BundleCacheDir:             cacheDir,
		PollInterval:               "30s",
		HonorRemoteKillSwitch:      false,
	}

	newServer := func() *Server { return &Server{conductorApply: cache} }

	t.Run("mtls_client_error", func(t *testing.T) {
		cfg := base
		cfg.ClientCertPath = filepath.Join(dir, "missing-client.crt")
		if _, err := newServer().buildConductorRollbackPoller(&config.Config{Conductor: cfg}, io.Discard); err == nil ||
			!strings.Contains(err.Error(), "mTLS client") {
			t.Fatalf("error = %v, want mTLS client failure", err)
		}
	})

	t.Run("trust_resolver_error_even_with_honor_false", func(t *testing.T) {
		cfg := base
		cfg.TrustRosterPath = filepath.Join(dir, "missing-roster.json")
		if _, err := newServer().buildConductorRollbackPoller(&config.Config{Conductor: cfg}, io.Discard); err == nil ||
			(!strings.Contains(err.Error(), "trust roster") && !strings.Contains(err.Error(), "trust resolver")) {
			t.Fatalf("error = %v, want trust roster/resolver failure", err)
		}
	})

	t.Run("poll_interval_error", func(t *testing.T) {
		cfg := base
		cfg.PollInterval = "not-a-duration"
		if _, err := newServer().buildConductorRollbackPoller(&config.Config{Conductor: cfg}, io.Discard); err == nil ||
			!strings.Contains(err.Error(), "parsing conductor rollback poll interval") {
			t.Fatalf("error = %v, want poll interval parse failure", err)
		}
	})

	t.Run("valid_builds_poller", func(t *testing.T) {
		poller, err := newServer().buildConductorRollbackPoller(&config.Config{Conductor: base}, nil)
		if err != nil {
			t.Fatalf("valid config: %v", err)
		}
		if poller == nil {
			t.Fatal("poller = nil, want a poller for enabled conductor")
		}
	})

	var _ policysync.RollbackApplier = conductorRollbackApplier{}
}
