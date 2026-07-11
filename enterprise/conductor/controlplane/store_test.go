//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var testNow = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

func TestFileBundleStorePublishesIdempotentlyAndReloads(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})

	record, created, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if !created {
		t.Fatal("Publish() created = false, want true")
	}
	again, created, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow.Add(time.Second)})
	if err != nil {
		t.Fatalf("Publish(idempotent) error = %v", err)
	}
	if created || again.BundleHash != record.BundleHash {
		t.Fatalf("Publish(idempotent) created=%v hash=%q, want existing %q", created, again.BundleHash, record.BundleHash)
	}

	reopened, err := OpenFileBundleStore(store.dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(reopen) error = %v", err)
	}
	latest, err := reopened.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
	}, testNow)
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if latest.BundleHash != record.BundleHash || latest.Bundle.BundleID != "bundle-1" {
		t.Fatalf("Latest() = hash=%q id=%q, want %q bundle-1", latest.BundleHash, latest.Bundle.BundleID, record.BundleHash)
	}
	info, err := os.Stat(filepath.Join(store.bundlesDir, record.BundleHash+".json"))
	if err != nil {
		t.Fatalf("stat bundle record: %v", err)
	}
	if got := info.Mode().Perm(); got != bundleRecordFileMode {
		t.Fatalf("bundle record mode = %v, want %v", got, bundleRecordFileMode)
	}
}

func TestFileBundleStoreBundleByIDVersion(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-lookup-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	published, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	got, err := store.BundleByIDVersion(t.Context(), "bundle-lookup-1", 1)
	if err != nil {
		t.Fatalf("BundleByIDVersion() error = %v", err)
	}
	if got.BundleHash != published.BundleHash {
		t.Fatalf("BundleByIDVersion() hash=%q, want %q", got.BundleHash, published.BundleHash)
	}
	if _, err := store.BundleByIDVersion(t.Context(), "bundle-lookup-1", 2); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("BundleByIDVersion(missing version) err=%v, want ErrBundleNotFound", err)
	}
	if _, err := store.BundleByIDVersion(t.Context(), "bundle-missing", 1); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("BundleByIDVersion(missing id) err=%v, want ErrBundleNotFound", err)
	}
}

func TestFileBundleStoreRejectsDuplicateBundleIDVersionGlobally(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	first := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-global-dup",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), first, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(first) error = %v", err)
	}
	duplicate := signedControlBundle(t, signer, bundleSpec{
		id:         "bundle-global-dup",
		version:    1,
		audience:   conductor.Audience{Labels: map[string]string{"ring": "canary"}},
		configYAML: "mode: strict\napi_allowlist:\n  - canary.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), duplicate, PublishOptions{Now: testNow.Add(time.Minute)}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(duplicate id/version) err=%v, want ErrBundleConflict", err)
	}
}

func TestFileBundleStoreRejectsDuplicateBundleIDVersionOnOpen(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	first := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-load-dup",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), first, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(first) error = %v", err)
	}
	duplicate := signedControlBundle(t, signer, bundleSpec{
		id:         "bundle-load-dup",
		version:    1,
		audience:   conductor.Audience{Labels: map[string]string{"ring": "canary"}},
		configYAML: "mode: strict\napi_allowlist:\n  - load-dup.example.com\n",
	})
	hash, err := duplicate.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(duplicate) error = %v", err)
	}
	streamKey, err := streamKey(duplicate)
	if err != nil {
		t.Fatalf("streamKey(duplicate) error = %v", err)
	}
	if err := writeBundleRecord(store.bundlesDir, PublishedBundle{
		Bundle:      duplicate,
		BundleHash:  hash,
		StreamKey:   streamKey,
		PublishedAt: testNow.Add(time.Minute),
	}); err != nil {
		t.Fatalf("write duplicate record: %v", err)
	}
	if _, err := OpenFileBundleStore(store.dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(duplicate id/version) error=%v, want ErrInvalidStoreRecord", err)
	}
}

func TestFileBundleStoreApplyRollbackHeadDurableAndTTLIndependent(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-head-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-head-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth := signedRollbackAuthorizationForBundles(t, "rollback-head-reset", v2, v1, testNow)

	if err := store.ApplyRollbackHead(t.Context(), auth, testNow); err != nil {
		t.Fatalf("ApplyRollbackHead() error = %v", err)
	}
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow.Add(time.Minute)); err != nil {
		t.Fatalf("ApplyRollbackHead(idempotent) error = %v", err)
	}
	latest, err := store.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("Latest(after expired auth window) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-head-v1" {
		t.Fatalf("Latest(after rollback) bundle=%q, want bundle-head-v1", latest.Bundle.BundleID)
	}

	reopened, err := OpenFileBundleStore(store.dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(reopen) error = %v", err)
	}
	latest, err = reopened.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(90*time.Minute))
	if err != nil {
		t.Fatalf("Latest(reopened) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-head-v1" {
		t.Fatalf("Latest(reopened) bundle=%q, want durable bundle-head-v1", latest.Bundle.BundleID)
	}
}

func TestRollbackHeadReconciliationRecoversAfterTTL(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	emergencyStore, err := OpenFileEmergencyStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-reconcile-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-reconcile-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - reconcile2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-reconcile", v2, v1, testNow)
	if _, created, err := emergencyStore.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
	}

	reopenedStore, err := OpenFileBundleStore(store.dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(reopen before reconcile) error = %v", err)
	}
	latest, err := reopenedStore.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Latest(before reconcile) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-reconcile-v2" {
		t.Fatalf("Latest(before reconcile) bundle=%q, want unreconciled bundle-reconcile-v2", latest.Bundle.BundleID)
	}
	reopenedEmergency, err := OpenFileEmergencyStore(emergencyStore.dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore(reopen) error = %v", err)
	}
	// Reconcile consumes the signature-verifying view, exactly as NewHandler
	// wires it, so the persisted rollback must verify against the trusted keys
	// to move the head.
	verified := newVerifiedEmergencyStore(reopenedEmergency, resolver, nil, nil)
	if err := reconcileRollbackHeads(reopenedStore, verified, testNow.Add(2*time.Hour), nil); err != nil {
		t.Fatalf("reconcileRollbackHeads(after TTL) error = %v", err)
	}
	latest, err = reopenedStore.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Latest(after reconcile) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-reconcile-v1" {
		t.Fatalf("Latest(after reconcile) bundle=%q, want bundle-reconcile-v1", latest.Bundle.BundleID)
	}
}

func TestRollbackHeadReconciliationDoesNotRearmSupersededAuthorization(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	emergencyStore, err := OpenFileEmergencyStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-reconcile-superseded-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-reconcile-superseded-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - reconcile-superseded2.example.com\n",
	})
	r2, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rollback-reconcile-superseded", v2, v1, testNow)
	if _, created, err := emergencyStore.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
	}
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-reconcile-superseded-v3",
		version:      3,
		previousHash: r2.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - reconcile-superseded3.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v3, PublishOptions{Now: testNow.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("Publish(v3) error = %v", err)
	}

	reopenedStore, err := OpenFileBundleStore(store.dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(reopen) error = %v", err)
	}
	reopenedEmergency, err := OpenFileEmergencyStore(emergencyStore.dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore(reopen) error = %v", err)
	}
	verified := newVerifiedEmergencyStore(reopenedEmergency, resolver, nil, nil)
	if err := reconcileRollbackHeads(reopenedStore, verified, testNow.Add(3*time.Minute), nil); err != nil {
		t.Fatalf("reconcileRollbackHeads(superseded) error = %v", err)
	}
	latest, err := reopenedStore.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("Latest(after superseded reconcile) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-reconcile-superseded-v3" {
		t.Fatalf("Latest(after superseded reconcile) bundle=%q, want bundle-reconcile-superseded-v3", latest.Bundle.BundleID)
	}
}

func TestRollbackHeadReconciliationLoadsLegacyAudienceEmergencyState(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	emergencyDir := t.TempDir()
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-reconcile-legacy-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-reconcile-legacy-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - legacy-reconcile2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: "rollback-reconcile-legacy-audience",
		OrgID:           v2.OrgID,
		FleetID:         v2.FleetID,
		Audience:        conductor.Audience{Labels: map[string]string{"tier": "legacy"}},
		CurrentBundleID: v2.BundleID,
		CurrentVersion:  v2.Version,
		TargetBundleID:  v1.BundleID,
		TargetVersion:   v1.Version,
		Counter:         1,
		Reason:          "operator rollback",
		CreatedAt:       testNow,
		ExpiresAt:       testNow.Add(time.Hour),
	}
	var resolver conductor.SignatureKeyResolver
	auth.Signatures, resolver = signConductorPreimage(t, auth.SignablePreimage, signing.PurposePolicyBundleRollback, "rollback-signer-1", "rollback-signer-2")
	authHash, err := auth.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(rollback): %v", err)
	}
	record := StoredRollbackAuthorization{
		Authorization:     auth,
		AuthorizationHash: authHash,
		PublishedAt:       testNow,
	}
	if err := writeEmergencyState(filepath.Join(emergencyDir, emergencyStateFileName), emergencyStateRecord{Rollbacks: []StoredRollbackAuthorization{record}}); err != nil {
		t.Fatalf("writeEmergencyState(legacy rollback): %v", err)
	}

	reopenedEmergency, err := OpenFileEmergencyStore(emergencyDir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore(legacy rollback) error = %v", err)
	}
	// A legacy audience'd record is structurally valid and correctly signed; it
	// must still verify and reconcile through the signature-verifying view.
	verified := newVerifiedEmergencyStore(reopenedEmergency, resolver, nil, nil)
	if err := reconcileRollbackHeads(store, verified, testNow.Add(2*time.Minute), nil); err != nil {
		t.Fatalf("reconcileRollbackHeads(legacy rollback) error = %v", err)
	}
	latest, err := store.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("Latest(after legacy reconcile) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-reconcile-legacy-v1" {
		t.Fatalf("Latest(after legacy reconcile) bundle=%q, want bundle-reconcile-legacy-v1", latest.Bundle.BundleID)
	}
}

func TestFileBundleStoreApplyRollbackHeadForwardProgress(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-progress-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-progress-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	r2, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth := signedRollbackAuthorizationForBundles(t, "rollback-progress", v2, v1, testNow)
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow); err != nil {
		t.Fatalf("ApplyRollbackHead() error = %v", err)
	}

	v3FromSuperseded := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-progress-v3-bad",
		version:      3,
		previousHash: r2.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3-bad.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v3FromSuperseded, PublishOptions{Now: testNow.Add(2 * time.Minute)}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(v3 from superseded head) err=%v, want ErrBundleConflict", err)
	}
	v2Reuse := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-progress-v2-reuse",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2-reuse.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2Reuse, PublishOptions{Now: testNow.Add(2 * time.Minute)}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(reused superseded version) err=%v, want ErrBundleConflict", err)
	}
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-progress-v3",
		version:      3,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v3, PublishOptions{Now: testNow.Add(3 * time.Minute)}); err != nil {
		t.Fatalf("Publish(v3 from rollback target) error = %v", err)
	}
	latest, err := store.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("Latest(after v3) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-progress-v3" {
		t.Fatalf("Latest(after v3) bundle=%q, want bundle-progress-v3", latest.Bundle.BundleID)
	}
}

func TestFileBundleStoreApplyRollbackHeadValidation(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-validate-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-validate-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	missingTarget := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-validate-missing",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	missingAuth := signedRollbackAuthorizationForBundles(t, "rollback-missing-bundle", v2, missingTarget, testNow)
	if err := store.ApplyRollbackHead(t.Context(), missingAuth, testNow); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("ApplyRollbackHead(missing target) err=%v, want ErrBundleNotFound", err)
	}
	mismatched := signedRollbackAuthorizationForBundles(t, "rollback-wrong-current", v2, v1, testNow)
	mismatched.CurrentBundleID = "bundle-validate-ghost"
	if err := store.ApplyRollbackHead(t.Context(), mismatched, testNow); !errors.Is(err, conductor.ErrInvalidRollback) {
		t.Fatalf("ApplyRollbackHead(wrong current) err=%v, want ErrInvalidRollback", err)
	}
}

func TestFileBundleStoreRejectsStreamConflicts(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	first := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	firstRecord, _, err := store.Publish(t.Context(), first, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(first) error = %v", err)
	}

	wrongPrev := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: stringsOf("a", 64),
		audience:     conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	if _, _, err := store.Publish(t.Context(), wrongPrev, PublishOptions{Now: testNow}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(wrong prev) error = %v, want ErrBundleConflict", err)
	}

	second := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: firstRecord.BundleHash,
		audience:     conductor.Audience{Labels: map[string]string{"ring": "stable"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), second, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(second) error = %v", err)
	}

	sameVersionSwap := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2b",
		version:      2,
		previousHash: firstRecord.BundleHash,
		audience:     conductor.Audience{Labels: map[string]string{"ring": "stable"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), sameVersionSwap, PublishOptions{Now: testNow}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(same version swap) error = %v, want ErrBundleConflict", err)
	}

	downgrade := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-old",
		version:  1,
		audience: conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	if _, _, err := store.Publish(t.Context(), downgrade, PublishOptions{Now: testNow, Rollback: true}); !errors.Is(err, ErrUnsupportedRollback) {
		t.Fatalf("Publish(rollback) error = %v, want ErrUnsupportedRollback", err)
	}
}

// TestFileBundleStoreForwardPublishConflictsAreDistinct proves the store
// returns three operationally DISTINCT, errors.Is-testable sentinels for the
// three forward-publish conflict cases, so the publish error can no longer be
// conflated into a single misleading "version is stale". The third case (the
// below-stream-max trap) is the one that cost a real operator a failed publish
// during a live recovery: after a rollback the head sits at vN while vN+1..vM
// still exist, so a naive forward publish of vN+1 is below the stream MAX.
func TestFileBundleStoreForwardPublishConflictsAreDistinct(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	aud := conductor.Audience{InstanceIDs: []string{"*"}}

	v1 := signedControlBundle(t, signer, bundleSpec{id: "distinct-v1", version: 1, audience: aud})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id: "distinct-v2", version: 2, previousHash: r1.BundleHash, audience: aud,
		configYAML: "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}

	// Case 3: previous_bundle_hash mismatch. Version (3) is above the stream max
	// (2), so the only fault is the chain pointer.
	prevHashMismatch := signedControlBundle(t, signer, bundleSpec{
		id: "distinct-v3-badprev", version: 3, previousHash: stringsOf("a", 64), audience: aud,
		configYAML: "mode: strict\napi_allowlist:\n  - api3-badprev.example.com\n",
	})
	err = publishErr(t, store, prevHashMismatch, testNow.Add(2*time.Minute))
	if !errors.Is(err, ErrPreviousHashMismatch) {
		t.Fatalf("prev-hash case err=%v, want ErrPreviousHashMismatch", err)
	}
	assertConflictExclusive(t, err, ErrPreviousHashMismatch)

	// Case 1: rollback attempt. While the head is still v2, publishing version 1
	// (strictly below the current head) is a rollback, not a forward publish, and
	// must surface as ErrUnsupportedRollback, distinct from the below-stream-max
	// and prev-hash cases. Asserted here, before the rollback below, because once
	// the head is rolled back to v1 a version-below-head publish is no longer
	// expressible (versions are >= 1).
	rollbackAttempt := signedControlBundle(t, signer, bundleSpec{
		id: "distinct-rollback-attempt", version: 1, previousHash: r1.BundleHash, audience: aud,
		configYAML: "mode: strict\napi_allowlist:\n  - api1-rollback.example.com\n",
	})
	err = publishErr(t, store, rollbackAttempt, testNow.Add(150*time.Second))
	if !errors.Is(err, ErrUnsupportedRollback) {
		t.Fatalf("rollback-attempt case err=%v, want ErrUnsupportedRollback", err)
	}
	assertConflictExclusive(t, err, ErrUnsupportedRollback)

	// Roll the head back to v1 so the head (1) is now BELOW the stream max (2).
	auth := signedRollbackAuthorizationForBundles(t, "distinct-rollback", v2, v1, testNow)
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow.Add(3*time.Minute)); err != nil {
		t.Fatalf("ApplyRollbackHead() error = %v", err)
	}

	// Case 2 (THE key fix): below-stream-max trap. Head is v1 after rollback, but
	// max is still 2. A naive operator publishes version 2 (head+1) chained to the
	// current head v1 — that is <= max(2) and >= head(1), so it must be reported
	// as below-stream-max, NOT as a stale/rollback error.
	belowMax := signedControlBundle(t, signer, bundleSpec{
		id: "distinct-v2-trap", version: 2, previousHash: r1.BundleHash, audience: aud,
		configYAML: "mode: strict\napi_allowlist:\n  - api2-trap.example.com\n",
	})
	err = publishErr(t, store, belowMax, testNow.Add(4*time.Minute))
	if !errors.Is(err, ErrVersionBelowStreamMax) {
		t.Fatalf("below-stream-max case err=%v, want ErrVersionBelowStreamMax", err)
	}
	assertConflictExclusive(t, err, ErrVersionBelowStreamMax)

	// A correct forward publish above the stream max (3) chained to the head still
	// succeeds: detection is preserved, only the message is de-conflated.
	ok := signedControlBundle(t, signer, bundleSpec{
		id: "distinct-v3-good", version: 3, previousHash: r1.BundleHash, audience: aud,
		configYAML: "mode: strict\napi_allowlist:\n  - api3-good.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), ok, PublishOptions{Now: testNow.Add(5 * time.Minute)}); err != nil {
		t.Fatalf("Publish(v3 above max) error = %v, want success", err)
	}
}

// publishErr publishes a bundle and returns only the error (helper to keep the
// distinctness assertions terse).
func publishErr(t *testing.T, store *FileBundleStore, bundle conductor.PolicyBundle, now time.Time) error {
	t.Helper()
	_, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: now})
	return err
}

// assertConflictExclusive asserts err is the umbrella ErrBundleConflict and the
// expected specific sentinel, and is NOT any of the OTHER specific conflict
// sentinels — i.e. the three cases never alias each other.
func assertConflictExclusive(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("conflict err=%v does not wrap umbrella ErrBundleConflict", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("conflict err=%v does not match expected sentinel %v", err, want)
	}
	for _, other := range []error{ErrUnsupportedRollback, ErrVersionBelowStreamMax, ErrPreviousHashMismatch} {
		if errors.Is(other, want) {
			continue
		}
		if errors.Is(err, other) {
			t.Fatalf("conflict err=%v conflated: also matches %v", err, other)
		}
	}
}

func TestFileBundleStoreLatestSelectsMatchingValidBundle(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	stable := signedControlBundle(t, signer, bundleSpec{
		id:       "stable-1",
		version:  1,
		audience: conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	if _, _, err := store.Publish(t.Context(), stable, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(stable) error = %v", err)
	}
	canary := signedControlBundle(t, signer, bundleSpec{
		id:       "canary-3",
		version:  3,
		audience: conductor.Audience{Labels: map[string]string{"ring": "canary"}},
	})
	if _, _, err := store.Publish(t.Context(), canary, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(canary) error = %v", err)
	}
	wildcard := signedControlBundle(t, signer, bundleSpec{
		id:       "wildcard-9",
		version:  9,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), wildcard, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(wildcard) error = %v", err)
	}

	latest, err := store.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
		Labels:      map[string]string{"ring": "canary"},
	}, testNow)
	if err != nil {
		t.Fatalf("Latest(canary) error = %v", err)
	}
	if latest.Bundle.BundleID != "canary-3" {
		t.Fatalf("Latest(canary) = %q, want canary-3", latest.Bundle.BundleID)
	}
	latest, err = store.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-2",
		Environment: "prod",
		Labels:      map[string]string{"ring": "missing"},
	}, testNow)
	if err != nil {
		t.Fatalf("Latest(wildcard fallback) error = %v", err)
	}
	if latest.Bundle.BundleID != "wildcard-9" {
		t.Fatalf("Latest(wildcard fallback) = %q, want wildcard-9", latest.Bundle.BundleID)
	}
	if _, err := store.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
		Labels:      map[string]string{"ring": "canary"},
	}, testNow.Add(3*time.Hour)); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("Latest(expired) error = %v, want ErrBundleNotFound", err)
	}
}

func TestFileBundleStoreRejectsTamperedRecordOnOpen(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	record, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	path := filepath.Join(store.bundlesDir, record.BundleHash+".json")
	data, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // test path is under the temp store dir.
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	data = []byte(stringsReplaceOnce(string(data), `"version": 1`, `"version": 2`))
	if err := os.WriteFile(path, data, bundleRecordFileMode); err != nil {
		t.Fatalf("tamper record: %v", err)
	}
	if _, err := OpenFileBundleStore(store.dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(tampered) error = %v, want ErrInvalidStoreRecord", err)
	}
}

func TestStoredRecordValidationGuards(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	record, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*PublishedBundle)
	}{
		{name: "missing_hash", mutate: func(r *PublishedBundle) { r.BundleHash = "" }},
		{name: "non_hex_hash", mutate: func(r *PublishedBundle) { r.BundleHash = stringsOf("z", 64) }},
		{name: "hash_mismatch", mutate: func(r *PublishedBundle) { r.Bundle.BundleID = "changed" }},
		{name: "stream_key_mismatch", mutate: func(r *PublishedBundle) { r.StreamKey = "wrong" }},
		{name: "missing_published_at", mutate: func(r *PublishedBundle) { r.PublishedAt = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := record
			tc.mutate(&tampered)
			if err := validateStoredRecord(tampered); !errors.Is(err, ErrInvalidStoreRecord) {
				t.Fatalf("validateStoredRecord() error = %v, want ErrInvalidStoreRecord", err)
			}
		})
	}
}

func TestReadBundleRecordRejectsTrailingDocument(t *testing.T) {
	store := mustStore(t)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	record, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	path := filepath.Join(store.bundlesDir, "trailing.json")
	if err := os.WriteFile(path, append(data, []byte(`{}`)...), bundleRecordFileMode); err != nil {
		t.Fatalf("write trailing record: %v", err)
	}
	if _, err := readBundleRecord(path); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("readBundleRecord(trailing) error = %v, want ErrInvalidStoreRecord", err)
	}
}

func TestNewerRecordTieBreakers(t *testing.T) {
	a := PublishedBundle{Bundle: conductor.PolicyBundle{Version: 2}, BundleHash: "b", PublishedAt: testNow}
	b := PublishedBundle{Bundle: conductor.PolicyBundle{Version: 1}, BundleHash: "c", PublishedAt: testNow.Add(time.Hour)}
	if !newerRecord(a, b) {
		t.Fatal("newerRecord(version) = false, want true")
	}
	a.Bundle.Version = 1
	a.PublishedAt = testNow.Add(2 * time.Hour)
	if !newerRecord(a, b) {
		t.Fatal("newerRecord(published_at) = false, want true")
	}
	a.PublishedAt = b.PublishedAt
	a.BundleHash = "d"
	if !newerRecord(a, b) {
		t.Fatal("newerRecord(hash tie-breaker) = false, want true")
	}
	a.BundleHash = "a"
	if newerRecord(a, b) {
		t.Fatal("newerRecord(older hash tie-breaker) = true, want false")
	}
}

type testSigner struct {
	keyID string
	priv  ed25519.PrivateKey
}

type bundleSpec struct {
	id           string
	version      uint64
	previousHash string
	audience     conductor.Audience
	configYAML   string
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return testSigner{keyID: "policy-key-1", priv: priv}
}

func signedControlBundle(t *testing.T, signer testSigner, spec bundleSpec) conductor.PolicyBundle {
	t.Helper()
	if spec.configYAML == "" {
		spec.configYAML = "mode: strict\napi_allowlist:\n  - api.example.com\n"
	}
	payload := conductor.PolicyBundlePayload{ConfigYAML: spec.configYAML}
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
		BundleID:           spec.id,
		OrgID:              "org-main",
		FleetID:            "prod",
		Environment:        "prod",
		Audience:           spec.audience,
		Version:            spec.version,
		PreviousBundleHash: spec.previousHash,
		CreatedAt:          testNow.Add(-time.Minute),
		NotBefore:          testNow.Add(-time.Minute),
		ExpiresAt:          testNow.Add(2 * time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	signature := ed25519.Sign(signer.priv, preimage)
	bundle.Signatures = []conductor.SignatureProof{{
		SignerKeyID: signer.keyID,
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(signature),
	}}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("test bundle Validate() error = %v", err)
	}
	return bundle
}

func stringsOf(value string, count int) string {
	var b strings.Builder
	for range count {
		b.WriteString(value)
	}
	return b.String()
}

func stringsReplaceOnce(s, old, replacement string) string {
	idx := strings.Index(s, old)
	if idx < 0 {
		return s
	}
	return s[:idx] + replacement + s[idx+len(old):]
}
