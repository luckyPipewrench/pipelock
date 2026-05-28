//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var testNow = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

func TestStoreVerifiedPersistsLastKnownGood(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")

	verified, err := cache.storeVerified(bundle, testVerifyOptions(key))
	if err != nil {
		t.Fatalf("storeVerified() error = %v", err)
	}
	if verified.BundleHash == "" {
		t.Fatal("BundleHash = empty")
	}
	if _, err := os.Stat(verified.ConfigPath); err != nil {
		t.Fatalf("active config not persisted: %v", err)
	}

	reopened, err := Open(Config{Dir: cache.dir})
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	active, err := reopened.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if active.Bundle.BundleID != "bundle-1" || active.Bundle.Version != 1 {
		t.Fatalf("active bundle = %s/%d, want bundle-1/1", active.Bundle.BundleID, active.Bundle.Version)
	}
	if active.ConfigPath != verified.ConfigPath {
		t.Fatalf("ConfigPath = %q, want %q", active.ConfigPath, verified.ConfigPath)
	}
}

func TestStoreVerifiedRejectsTamperedSignature(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	bundle.Version = 2

	_, err := cache.storeVerified(bundle, testVerifyOptions(key))
	if !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("storeVerified(tampered) error = %v, want ErrSignatureVerification", err)
	}
	if _, activeErr := cache.Active(); !errors.Is(activeErr, ErrNoValidBundle) {
		t.Fatalf("Active() after rejected bundle = %v, want ErrNoValidBundle", activeErr)
	}
}

func TestStoreVerifiedRejectsWrongAudience(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	opts := testVerifyOptions(key)
	opts.Identity.InstanceID = "other-instance"

	_, err := cache.storeVerified(bundle, opts)
	if !errors.Is(err, conductor.ErrAudienceMismatch) {
		t.Fatalf("storeVerified(wrong audience) error = %v, want ErrAudienceMismatch", err)
	}
}

func TestStoreVerifiedRollbackRequiresAuthorization(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	v1 := signedTestBundle(t, key, "bundle-1", 1, "")
	if _, err := cache.storeVerified(v1, testVerifyOptions(key)); err != nil {
		t.Fatalf("storeVerified(v1) error = %v", err)
	}
	v1Hash, err := v1.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(v1) error = %v", err)
	}
	v2 := signedTestBundle(t, key, "bundle-2", 2, v1Hash)
	if _, err := cache.storeVerified(v2, testVerifyOptions(key)); err != nil {
		t.Fatalf("storeVerified(v2) error = %v", err)
	}

	_, err = cache.storeVerified(v1, testVerifyOptions(key))
	if !errors.Is(err, ErrRollbackRequired) {
		t.Fatalf("storeVerified(rollback without auth) error = %v, want ErrRollbackRequired", err)
	}
}

func TestStoreVerifiedForwardRequiresPreviousBundleHash(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	v1 := signedTestBundle(t, key, "bundle-1", 1, "")
	if _, err := cache.storeVerified(v1, testVerifyOptions(key)); err != nil {
		t.Fatalf("storeVerified(v1) error = %v", err)
	}
	v2 := signedTestBundle(t, key, "bundle-2", 2, "")

	_, err := cache.storeVerified(v2, testVerifyOptions(key))
	if !errors.Is(err, conductor.ErrInvalidRollback) {
		t.Fatalf("storeVerified(v2 missing previous hash) error = %v, want ErrInvalidRollback", err)
	}
}

func TestStoreVerifiedRollbackAuthorizationAllowsDowngrade(t *testing.T) {
	policyKey := newTestKey(t)
	rollbackKey1 := newPurposeKey(t, "rollback-1", signing.PurposePolicyBundleRollback)
	rollbackKey2 := newPurposeKey(t, "rollback-2", signing.PurposePolicyBundleRollback)
	cache := openTestCache(t)

	v1 := signedTestBundle(t, policyKey, "bundle-1", 1, "")
	if _, err := cache.storeVerified(v1, testVerifyOptions(policyKey, rollbackKey1, rollbackKey2)); err != nil {
		t.Fatalf("storeVerified(v1) error = %v", err)
	}
	v1Hash, err := v1.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(v1) error = %v", err)
	}
	v2 := signedTestBundle(t, policyKey, "bundle-2", 2, v1Hash)
	if _, err := cache.storeVerified(v2, testVerifyOptions(policyKey, rollbackKey1, rollbackKey2)); err != nil {
		t.Fatalf("storeVerified(v2) error = %v", err)
	}
	auth := signedRollbackAuthorization(t, rollbackKey1, rollbackKey2, v2, v1)
	opts := testVerifyOptions(policyKey, rollbackKey1, rollbackKey2)
	opts.AllowRollback = true
	opts.Rollback = &auth

	active, err := cache.storeVerified(v1, opts)
	if err != nil {
		t.Fatalf("storeVerified(authorized rollback) error = %v", err)
	}
	if active.Bundle.BundleID != "bundle-1" {
		t.Fatalf("active bundle = %q, want bundle-1", active.Bundle.BundleID)
	}
}

func TestDecideStale(t *testing.T) {
	key := newTestKey(t)
	active := VerifiedBundle{Bundle: signedTestBundle(t, key, "bundle-1", 1, "")}
	policy := config.ConductorStalePolicy{GraceMultiplier: 1, AfterGrace: config.ConductorStaleStrictDenyAll}

	if got := DecideStale(&active, policy, testNow.Add(30*time.Minute)); got.State != StaleStateActive {
		t.Fatalf("active decision = %s, want active", got.State)
	}
	if got := DecideStale(&active, policy, testNow.Add(90*time.Minute)); got.State != StaleStateLastKnownGood {
		t.Fatalf("grace decision = %s, want last_known_good", got.State)
	}
	if got := DecideStale(&active, policy, testNow.Add(3*time.Hour)); got.State != StaleStateStrictDenyNoBundle {
		t.Fatalf("post-grace decision = %s, want strict deny", got.State)
	}
	policy.AfterGrace = config.ConductorStaleContinueLastKnownGood
	if got := DecideStale(&active, policy, testNow.Add(3*time.Hour)); got.State != StaleStateLastKnownGood {
		t.Fatalf("continue decision = %s, want last_known_good", got.State)
	}
	if got := DecideStale(nil, policy, testNow); got.State != StaleStateStrictDenyNoBundle {
		t.Fatalf("nil decision = %s, want strict deny", got.State)
	}
}

func TestBoundaryApplyLoadsActiveYAMLAndCallsReload(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	var reloaded *config.Config
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(cfg *config.Config) error {
			reloaded = cfg
			return nil
		},
	}

	applied, err := boundary.Apply(signedTestBundle(t, key, "bundle-1", 1, ""), ApplyOptions{})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if applied.ReloadedConfigHash == "" {
		t.Fatal("ReloadedConfigHash = empty")
	}
	if reloaded == nil {
		t.Fatal("Reload was not called")
	}
	if reloaded.Mode != config.ModeStrict {
		t.Fatalf("reloaded Mode = %q, want strict", reloaded.Mode)
	}
	if filepath.Dir(applied.ConfigPath) != cache.configsDir {
		t.Fatalf("ConfigPath = %q, want under %q", applied.ConfigPath, cache.configsDir)
	}
}

func TestBoundaryApplyDoesNotActivateWhenReloadFails(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(_ *config.Config) error {
			return errors.New("reload rejected")
		},
	}

	_, err := boundary.Apply(signedTestBundle(t, key, "bundle-1", 1, ""), ApplyOptions{})
	if err == nil {
		t.Fatal("Apply() error = nil, want reload error")
	}
	if _, activeErr := cache.Active(); !errors.Is(activeErr, ErrNoValidBundle) {
		t.Fatalf("Active() after failed reload = %v, want ErrNoValidBundle", activeErr)
	}
}

func TestBoundaryApplyRequiresCacheAndReload(t *testing.T) {
	key := newTestKey(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	base := Boundary{
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
	}
	if _, err := base.Apply(bundle, ApplyOptions{}); !errors.Is(err, ErrCacheRequired) {
		t.Fatalf("Apply(missing cache) = %v, want ErrCacheRequired", err)
	}
	base.Cache = openTestCache(t)
	if _, err := base.Apply(bundle, ApplyOptions{}); err == nil {
		t.Fatal("Apply(missing reload) = nil, want error")
	}
}

func TestBoundaryApplySurfacesStageAndLoadFailures(t *testing.T) {
	key := newTestKey(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	boundary := Boundary{
		Cache:        openTestCache(t),
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload:       func(_ *config.Config) error { return nil },
	}
	wrongAudience := boundary
	wrongAudience.Identity.InstanceID = "other"
	if _, err := wrongAudience.Apply(bundle, ApplyOptions{}); !errors.Is(err, conductor.ErrAudienceMismatch) {
		t.Fatalf("Apply(wrong audience) = %v, want ErrAudienceMismatch", err)
	}

	boundary.LoadConfig = func(string) (*config.Config, error) {
		return nil, errors.New("load rejected")
	}
	if _, err := boundary.Apply(bundle, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "loading verified") {
		t.Fatalf("Apply(load failure) = %v, want loading error", err)
	}
}

func TestBoundaryApplyDoesNotActivateWhenActivationFails(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	var loadedPath string
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		LoadConfig: func(path string) (*config.Config, error) {
			loadedPath = path
			return config.Load(path)
		},
		Reload: func(_ *config.Config) error {
			if err := os.Remove(loadedPath); err != nil {
				return err
			}
			return nil
		},
	}
	_, err := boundary.Apply(signedTestBundle(t, key, "bundle-1", 1, ""), ApplyOptions{})
	if err == nil || !strings.Contains(err.Error(), "activating verified") {
		t.Fatalf("Apply(activation failure) = %v, want activating error", err)
	}
	if _, activeErr := cache.Active(); !errors.Is(activeErr, ErrNoValidBundle) {
		t.Fatalf("Active() after failed activation = %v, want ErrNoValidBundle", activeErr)
	}
}

type testKey struct {
	id      string
	purpose signing.KeyPurpose
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	return newPurposeKey(t, "policy-signer-1", signing.PurposePolicyBundleSigning)
}

func newPurposeKey(t *testing.T, id string, purpose signing.KeyPurpose) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return testKey{id: id, purpose: purpose, pub: pub, priv: priv}
}

func openTestCache(t *testing.T) *Cache {
	t.Helper()
	cache, err := Open(Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return cache
}

func testVerifyOptions(keys ...testKey) verifyOptions {
	return verifyOptions{
		Identity:     testIdentity(),
		Resolver:     testResolver(keys...),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
	}
}

func testIdentity() Identity {
	return Identity{
		OrgID:      "org-1",
		FleetID:    "fleet-1",
		InstanceID: "instance-1",
	}
}

func testResolver(keys ...testKey) conductor.SignatureKeyResolver {
	lookup := make(map[string]conductor.SignatureKey, len(keys))
	for _, key := range keys {
		lookup[key.id] = conductor.SignatureKey{
			PublicKey:  key.pub,
			KeyPurpose: key.purpose,
			NotBefore:  testNow.Add(-time.Hour),
			NotAfter:   testNow.Add(time.Hour),
		}
	}
	return func(signerKeyID string) (conductor.SignatureKey, error) {
		key, ok := lookup[signerKeyID]
		if !ok {
			return conductor.SignatureKey{}, conductor.ErrSignatureVerification
		}
		return key, nil
	}
}

func signedTestBundle(t *testing.T, key testKey, id string, version uint64, previousHash string) conductor.PolicyBundle {
	t.Helper()
	payload := conductor.PolicyBundlePayload{ConfigYAML: "mode: strict\napi_allowlist:\n  - api.example.com\n"}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash() error = %v", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash() error = %v", err)
	}
	bundle := conductor.PolicyBundle{
		SchemaVersion:      conductor.SchemaVersion,
		BundleID:           id,
		OrgID:              "org-1",
		FleetID:            "fleet-1",
		Environment:        "prod",
		Audience:           conductor.Audience{InstanceIDs: []string{"instance-1"}},
		Version:            version,
		PreviousBundleHash: previousHash,
		CreatedAt:          testNow.Add(-time.Minute),
		NotBefore:          testNow.Add(-time.Minute),
		ExpiresAt:          testNow.Add(time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	bundle.Signatures = []conductor.SignatureProof{signProof(t, key, bundle.SignablePreimage)}
	return bundle
}

func signedRollbackAuthorization(t *testing.T, key1, key2 testKey, current, target conductor.PolicyBundle) conductor.RollbackAuthorization {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: "rollback-1",
		OrgID:           "org-1",
		FleetID:         "fleet-1",
		Audience:        conductor.Audience{InstanceIDs: []string{"instance-1"}},
		CurrentBundleID: current.BundleID,
		CurrentVersion:  current.Version,
		TargetBundleID:  target.BundleID,
		TargetVersion:   target.Version,
		Counter:         1,
		Reason:          "operator rollback",
		CreatedAt:       testNow.Add(-time.Minute),
		ExpiresAt:       testNow.Add(time.Hour),
	}
	auth.Signatures = []conductor.SignatureProof{
		signProof(t, key1, auth.SignablePreimage),
		signProof(t, key2, auth.SignablePreimage),
	}
	return auth
}

func signProof(t *testing.T, key testKey, preimage func() ([]byte, error)) conductor.SignatureProof {
	t.Helper()
	msg, err := preimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	sig := ed25519.Sign(key.priv, msg)
	return conductor.SignatureProof{
		SignerKeyID: key.id,
		KeyPurpose:  key.purpose,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(sig),
	}
}
