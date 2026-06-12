//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// TestApplyRollbackHeadGuards exercises the nil-receiver, structurally invalid
// authorization, and current<=target rejection branches that the durable/forward
// tests do not reach.
func TestApplyRollbackHeadGuards(t *testing.T) {
	var nilStore *FileBundleStore
	if err := nilStore.ApplyRollbackHead(t.Context(), conductor.RollbackAuthorization{}, testNow); !errors.Is(err, ErrStoreRequired) {
		t.Fatalf("ApplyRollbackHead(nil store) err=%v, want ErrStoreRequired", err)
	}

	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	// Empty authorization fails RollbackAuthorization.Validate() before any
	// store lookup.
	if err := store.ApplyRollbackHead(t.Context(), conductor.RollbackAuthorization{}, testNow); err == nil {
		t.Fatal("ApplyRollbackHead(empty auth) error = nil, want validation error")
	}

	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-guard-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-guard-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - guard2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}

	// Zero now defaults to time.Now().UTC() inside ApplyRollbackHead. A valid
	// v2->v1 rollback applied with a zero now must still succeed.
	auth := signedRollbackAuthorizationForBundles(t, "rollback-zero-now", v2, v1, testNow)
	if err := store.ApplyRollbackHead(t.Context(), auth, time.Time{}); err != nil {
		t.Fatalf("ApplyRollbackHead(zero now) error = %v", err)
	}
}

// TestApplyRollbackHeadSupersededHeadNoOp covers the branch where a later forward
// publish has already moved the head past the rollback's current version, so a
// stale operator retry must be a no-op (nil) rather than moving the head
// backward again.
func TestApplyRollbackHeadSupersededHeadNoOp(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-superseded-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-superseded-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - superseded2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	// Roll back v2 -> v1, then publish v3 forward from the rollback target.
	auth := signedRollbackAuthorizationForBundles(t, "rollback-superseded", v2, v1, testNow)
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow); err != nil {
		t.Fatalf("ApplyRollbackHead() error = %v", err)
	}
	v3 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-superseded-v3",
		version:      3,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - superseded3.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v3, PublishOptions{Now: testNow.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("Publish(v3) error = %v", err)
	}
	// Head is now v3 (version 3) > auth.CurrentVersion (2): a stale retry of the
	// v2->v1 rollback must be a no-op and leave the head at v3.
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow.Add(3*time.Minute)); err != nil {
		t.Fatalf("ApplyRollbackHead(stale retry) error = %v", err)
	}
	latest, err := store.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-superseded-v3" {
		t.Fatalf("Latest() bundle=%q, want bundle-superseded-v3 (stale rollback must not move head back)", latest.Bundle.BundleID)
	}
}

// TestApplyRollbackHeadCurrentInDifferentStream covers the branch where the
// rollback's current bundle exists but lives in a different stream than the
// target, which is rejected as ErrInvalidRollback.
func TestApplyRollbackHeadCurrentInDifferentStream(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	// Target stream (wildcard audience).
	targetV1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-xstream-target",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), targetV1, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(target) error = %v", err)
	}
	// A separate canary stream holds the "current" bundle at a higher version.
	currentV2 := signedControlBundle(t, signer, bundleSpec{
		id:         "bundle-xstream-current",
		version:    2,
		audience:   conductor.Audience{Labels: map[string]string{"ring": "canary"}},
		configYAML: "mode: strict\napi_allowlist:\n  - xstream-current.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), currentV2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(current) error = %v", err)
	}
	// current (canary stream) and target (wildcard stream) are in different
	// streams; the rollback must be rejected.
	auth := signedRollbackAuthorizationForBundles(t, "rollback-xstream", currentV2, targetV1, testNow)
	if err := store.ApplyRollbackHead(t.Context(), auth, testNow); !errors.Is(err, conductor.ErrInvalidRollback) {
		t.Fatalf("ApplyRollbackHead(cross-stream current) err=%v, want ErrInvalidRollback", err)
	}
}

// TestBundleByIDVersionGuards covers the nil-store, invalid-identifier, and
// zero-version rejection paths plus the defensive duplicate-match error in
// bundleByIDVersionLocked.
func TestBundleByIDVersionGuards(t *testing.T) {
	var nilStore *FileBundleStore
	if _, err := nilStore.BundleByIDVersion(t.Context(), "bundle-x", 1); !errors.Is(err, ErrStoreRequired) {
		t.Fatalf("BundleByIDVersion(nil store) err=%v, want ErrStoreRequired", err)
	}

	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	if _, err := store.BundleByIDVersion(t.Context(), "bad id!", 1); err == nil {
		t.Fatal("BundleByIDVersion(invalid id) error = nil, want identifier error")
	}
	if _, err := store.BundleByIDVersion(t.Context(), "bundle-x", 0); !errors.Is(err, conductor.ErrMissingField) {
		t.Fatalf("BundleByIDVersion(zero version) err=%v, want ErrMissingField", err)
	}

	// Defensive duplicate guard: two in-memory records share the same
	// bundle_id/version. Publish enforces uniqueness, so inject records
	// directly to reach the locked-lookup branch.
	signer := newTestSigner(t)
	dupA := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-dup-lookup",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	dupB := signedControlBundle(t, signer, bundleSpec{
		id:         "bundle-dup-lookup",
		version:    1,
		audience:   conductor.Audience{Labels: map[string]string{"ring": "canary"}},
		configYAML: "mode: strict\napi_allowlist:\n  - dup-b.example.com\n",
	})
	store.records = map[string]PublishedBundle{
		"hash-a": {Bundle: dupA, BundleHash: "hash-a", StreamKey: "stream-a"},
		"hash-b": {Bundle: dupB, BundleHash: "hash-b", StreamKey: "stream-b"},
	}
	if _, err := store.BundleByIDVersion(t.Context(), "bundle-dup-lookup", 1); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("BundleByIDVersion(duplicate match) err=%v, want ErrInvalidStoreRecord", err)
	}
}

// TestReconcileRollbackHeadsBranches covers nil-store, empty-list no-op,
// newest-first ordering across multiple records, and the wrapped apply error.
func TestReconcileRollbackHeadsBranches(t *testing.T) {
	var nilStore *FileBundleStore
	if _, err := nilStore.ReconcileRollbackHeads(t.Context(), nil, testNow); !errors.Is(err, ErrStoreRequired) {
		t.Fatalf("ReconcileRollbackHeads(nil store) err=%v, want ErrStoreRequired", err)
	}

	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	if skips, err := store.ReconcileRollbackHeads(t.Context(), nil, testNow); err != nil || len(skips) != 0 {
		t.Fatalf("ReconcileRollbackHeads(empty) skips=%v err=%v, want nil no-op", skips, err)
	}

	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-reconcile-multi-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-reconcile-multi-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - reconcile-multi2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}

	// Two records both roll v2->v1. Sorting newest-first applies the newer
	// record first (head -> v1); the older record then converges idempotently
	// because the head already equals the target. The list-supplied (unsorted)
	// order is intentionally older-then-newer to exercise the sort.
	older := signedRollbackAuthorizationForBundles(t, "rollback-reconcile-older", v2, v1, testNow)
	newer := signedRollbackAuthorizationForBundles(t, "rollback-reconcile-newer", v2, v1, testNow.Add(time.Minute))
	// newer-first then older exercises the descending comparator's negative
	// branch (a newer than b => -1); the trailing older record then converges
	// idempotently.
	records := []StoredRollbackAuthorization{
		{Authorization: newer, PublishedAt: testNow.Add(time.Minute)},
		{Authorization: older, PublishedAt: testNow},
	}
	if skips, err := store.ReconcileRollbackHeads(t.Context(), records, testNow.Add(3*time.Minute)); err != nil || len(skips) != 0 {
		t.Fatalf("ReconcileRollbackHeads(multi) skips=%v err=%v", skips, err)
	}
	latest, err := store.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-reconcile-multi-v1" {
		t.Fatalf("Latest() bundle=%q, want bundle-reconcile-multi-v1", latest.Bundle.BundleID)
	}

	// An unapplyable record is TOLERATED, not fatal: a record whose target bundle
	// is absent fails ApplyRollbackHead with ErrBundleNotFound, is collected as a
	// skip carrying the authorization ID, and reconciliation returns no error so
	// one stale authorization never bricks startup.
	missingTarget := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-reconcile-absent",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	badAuth := signedRollbackAuthorizationForBundles(t, "rollback-reconcile-bad", v2, missingTarget, testNow)
	badRecords := []StoredRollbackAuthorization{{Authorization: badAuth, PublishedAt: testNow}}
	skips, err := store.ReconcileRollbackHeads(t.Context(), badRecords, testNow.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("ReconcileRollbackHeads(bad target) err=%v, want nil (tolerated)", err)
	}
	if len(skips) != 1 || skips[0].AuthorizationID != "rollback-reconcile-bad" || !errors.Is(skips[0].Err, ErrBundleNotFound) {
		t.Fatalf("ReconcileRollbackHeads(bad target) skips=%+v, want one ErrBundleNotFound skip for rollback-reconcile-bad", skips)
	}
}

// TestReconcileRollbackHeadsToleratesLegacyAudience is the regression for the
// startup-bricking migration bug: a rollback authorization persisted by an
// earlier release carried a non-empty audience. Reconciliation must ignore that
// legacy audience and apply the stream-wide rollback when the bundles are
// present.
func TestReconcileRollbackHeadsToleratesLegacyAudience(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-legacy-audience-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-legacy-audience-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - legacy2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	legacy := signedRollbackAuthorizationForBundles(t, "rollback-legacy-audience", v2, v1, testNow)
	legacy.Audience = conductor.Audience{InstanceIDs: []string{"edge-01"}}
	skips, err := store.ReconcileRollbackHeads(
		t.Context(),
		[]StoredRollbackAuthorization{{Authorization: legacy, PublishedAt: testNow}},
		testNow,
	)
	if err != nil {
		t.Fatalf("ReconcileRollbackHeads(legacy audience) err=%v, want nil (tolerated)", err)
	}
	if len(skips) != 0 {
		t.Fatalf("ReconcileRollbackHeads(legacy audience) skips=%+v, want none", skips)
	}
	latest, err := store.Latest(t.Context(), defaultFollowerIdentity(), testNow.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Latest(after legacy audience reconcile) error = %v", err)
	}
	if latest.Bundle.BundleID != "bundle-legacy-audience-v1" {
		t.Fatalf("Latest(after legacy audience reconcile) bundle=%q, want bundle-legacy-audience-v1", latest.Bundle.BundleID)
	}
}

func TestReconcileRollbackHeadsFatalOnStreamHeadWriteFailure(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-reconcile-fatal-v1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-reconcile-fatal-v2",
		version:      2,
		previousHash: r1.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - fatal2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	auth := signedRollbackAuthorizationForBundles(t, "rollback-reconcile-fatal", v2, v1, testNow)
	store.streamHeadsDir = filepath.Join(store.dir, "missing-stream-heads")

	skips, err := store.ReconcileRollbackHeads(
		t.Context(),
		[]StoredRollbackAuthorization{{Authorization: auth, PublishedAt: testNow}},
		testNow.Add(time.Minute),
	)
	if err == nil {
		t.Fatal("ReconcileRollbackHeads(write failure) error = nil, want fatal error")
	}
	if len(skips) != 0 {
		t.Fatalf("ReconcileRollbackHeads(write failure) skips=%+v, want none", skips)
	}
	if errors.Is(err, conductor.ErrInvalidRollback) || errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("ReconcileRollbackHeads(write failure) err=%v, want non-logical fatal error", err)
	}
}

// stubEnumerator implements EmergencyStore + the optional enumerator interface
// so reconcileRollbackHeads can reach the list/skip branches without a full
// emergency store.
type stubEnumerator struct {
	EmergencyStore
	records []StoredRollbackAuthorization
	err     error
}

func (s stubEnumerator) RollbackAuthorizations(context.Context) ([]StoredRollbackAuthorization, error) {
	return s.records, s.err
}

// TestReconcileRollbackHeadsHelperBranches covers the package-level
// reconcileRollbackHeads helper: nil emergency controls, stores/controls that do
// not implement the optional interfaces, and an enumerator that returns an error.
func TestReconcileRollbackHeadsHelperBranches(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}

	// nil emergency controls: no-op.
	if err := reconcileRollbackHeads(store, nil, testNow, nil); err != nil {
		t.Fatalf("reconcileRollbackHeads(nil emergency) error = %v", err)
	}

	// Emergency controls that do not implement rollbackAuthorizationEnumerator:
	// no-op. failingEmergencyStore has no RollbackAuthorizations method.
	if err := reconcileRollbackHeads(store, failingEmergencyStore{}, testNow, nil); err != nil {
		t.Fatalf("reconcileRollbackHeads(non-enumerator emergency) error = %v", err)
	}

	// Emergency controls enumerate but the store is not a rollbackHeadReconciler:
	// no-op. stubBundleStore does not implement ReconcileRollbackHeads.
	enumerator := stubEnumerator{EmergencyStore: failingEmergencyStore{}}
	if err := reconcileRollbackHeads(stubBundleStore{}, enumerator, testNow, nil); err != nil {
		t.Fatalf("reconcileRollbackHeads(non-reconciler store) error = %v", err)
	}

	// Enumerator returns an error: TOLERATED (logged, not surfaced) so the
	// control plane still starts even if persisted authorizations cannot be read.
	var logbuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logbuf, nil))
	failing := stubEnumerator{EmergencyStore: failingEmergencyStore{}, err: errors.New("enumerate failed")}
	if err := reconcileRollbackHeads(store, failing, testNow, logger); err != nil {
		t.Fatalf("reconcileRollbackHeads(enumerate error) err=%v, want nil (tolerated)", err)
	}
	if !strings.Contains(logbuf.String(), "conductor_rollback_reconcile_list_failed") {
		t.Fatalf("reconcileRollbackHeads(enumerate error) log=%q, want list-failed warning", logbuf.String())
	}
}

// stubBundleStore implements BundleStore but NOT rollbackHeadReconciler, so the
// reconcile helper takes the no-op type-assertion branch.
type stubBundleStore struct{}

func (stubBundleStore) Publish(context.Context, conductor.PolicyBundle, PublishOptions) (PublishedBundle, bool, error) {
	return PublishedBundle{}, false, nil
}

func (stubBundleStore) Latest(context.Context, FollowerIdentity, time.Time) (PublishedBundle, error) {
	return PublishedBundle{}, ErrBundleNotFound
}

func (stubBundleStore) BundleByIDVersion(context.Context, string, uint64) (PublishedBundle, error) {
	return PublishedBundle{}, ErrBundleNotFound
}

func (stubBundleStore) ApplyRollbackHead(context.Context, conductor.RollbackAuthorization, time.Time) error {
	return nil
}

// TestApplyRollbackCeilingUnavailableBundles drives the leader-side ceiling
// helper through the current-unavailable, target-unavailable, and cross-stream
// branches by serving GET latest with a published rollback authorization whose
// referenced bundles are missing or live in a different stream.
func TestApplyRollbackCeilingUnavailableBundles(t *testing.T) {
	// current unavailable: rollback references a current bundle that was never
	// published, while the target IS present. The ceiling returns a 404-mapped
	// error rather than serving any bundle.
	t.Run("current unavailable", func(t *testing.T) {
		store := mustStore(t)
		handler := newTestHandler(t, store, nil)
		signer := newTestSigner(t)
		audience := conductor.Audience{InstanceIDs: []string{"*"}}
		target := signedControlBundle(t, signer, bundleSpec{
			id:       "bundle-ceiling-cur-target",
			version:  1,
			audience: audience,
		})
		if _, _, err := store.Publish(t.Context(), target, PublishOptions{Now: testNow}); err != nil {
			t.Fatalf("Publish(target) error = %v", err)
		}
		// current (version 2) is referenced by the auth but never published.
		missingCurrent := signedControlBundle(t, signer, bundleSpec{
			id:         "bundle-ceiling-cur-current",
			version:    2,
			audience:   audience,
			configYAML: "mode: strict\napi_allowlist:\n  - cur-current.example.com\n",
		})
		auth := signedRollbackAuthorizationForBundles(t, "rollback-ceiling-cur", missingCurrent, target, testNow)
		if _, created, err := handler.emergencyControls.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
			t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
		}
		w := latestPolicyBundle(t, handler, nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("current-unavailable status=%d body=%s, want 404", w.Code, w.Body.String())
		}
	})

	// target unavailable: rollback references a current bundle that IS present
	// but a target bundle that was never published. The ceiling returns a
	// 404-mapped error.
	t.Run("target unavailable", func(t *testing.T) {
		store := mustStore(t)
		handler := newTestHandler(t, store, nil)
		signer := newTestSigner(t)
		audience := conductor.Audience{InstanceIDs: []string{"*"}}
		current := signedControlBundle(t, signer, bundleSpec{
			id:       "bundle-ceiling-tgt-current",
			version:  2,
			audience: audience,
		})
		if _, _, err := store.Publish(t.Context(), current, PublishOptions{Now: testNow}); err != nil {
			t.Fatalf("Publish(current) error = %v", err)
		}
		// target (version 1) is referenced by the auth but never published.
		missingTarget := signedControlBundle(t, signer, bundleSpec{
			id:         "bundle-ceiling-tgt-target",
			version:    1,
			audience:   audience,
			configYAML: "mode: strict\napi_allowlist:\n  - tgt-target.example.com\n",
		})
		auth := signedRollbackAuthorizationForBundles(t, "rollback-ceiling-tgt", current, missingTarget, testNow)
		if _, created, err := handler.emergencyControls.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
			t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
		}
		w := latestPolicyBundle(t, handler, nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("target-unavailable status=%d body=%s, want 404", w.Code, w.Body.String())
		}
	})

	// cross-stream: current and target live in a different stream than the
	// follower's latest bundle, so the ceiling leaves the latest unchanged.
	t.Run("cross stream returns latest unchanged", func(t *testing.T) {
		store := mustStore(t)
		handler := newTestHandler(t, store, nil)
		signer := newTestSigner(t)

		// Follower's matching stream: a wildcard-audience bundle (the latest the
		// default follower identity resolves to).
		wildcard := signedControlBundle(t, signer, bundleSpec{
			id:       "bundle-ceiling-cross-wild",
			version:  1,
			audience: conductor.Audience{InstanceIDs: []string{"*"}},
		})
		if _, _, err := store.Publish(t.Context(), wildcard, PublishOptions{Now: testNow}); err != nil {
			t.Fatalf("Publish(wildcard) error = %v", err)
		}

		// A separate canary stream holds the rollback's current/target bundles.
		canary := conductor.Audience{Labels: map[string]string{"ring": "canary"}}
		canaryV1 := signedControlBundle(t, signer, bundleSpec{
			id:         "bundle-ceiling-cross-canary-v1",
			version:    1,
			audience:   canary,
			configYAML: "mode: strict\napi_allowlist:\n  - cross-canary1.example.com\n",
		})
		cr1, _, err := store.Publish(t.Context(), canaryV1, PublishOptions{Now: testNow})
		if err != nil {
			t.Fatalf("Publish(canary v1) error = %v", err)
		}
		canaryV2 := signedControlBundle(t, signer, bundleSpec{
			id:           "bundle-ceiling-cross-canary-v2",
			version:      2,
			previousHash: cr1.BundleHash,
			audience:     canary,
			configYAML:   "mode: strict\napi_allowlist:\n  - cross-canary2.example.com\n",
		})
		if _, _, err := store.Publish(t.Context(), canaryV2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
			t.Fatalf("Publish(canary v2) error = %v", err)
		}
		auth := signedRollbackAuthorizationForBundles(t, "rollback-ceiling-cross", canaryV2, canaryV1, testNow)
		if _, created, err := handler.emergencyControls.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
			t.Fatalf("PublishRollbackAuthorization() created=%v err=%v, want created", created, err)
		}
		// The default follower resolves to the wildcard stream; the canary
		// rollback is cross-stream so the wildcard latest is served unchanged.
		w := latestPolicyBundle(t, handler, nil)
		assertLatestBundleID(t, w, "bundle-ceiling-cross-wild")
	})
}

// TestApplyRollbackCeilingNilEmergencyControls covers the early return when the
// handler has no emergency controls configured.
func TestApplyRollbackCeilingNilEmergencyControls(t *testing.T) {
	store := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-ceiling-noemerg",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	handler := newTestHandler(t, store, nil)
	handler.emergencyControls = nil
	got, err := handler.applyRollbackCeiling(
		httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil),
		defaultFollowerIdentity(),
		PublishedBundle{Bundle: v1},
		testNow,
	)
	if err != nil {
		t.Fatalf("applyRollbackCeiling(nil emergency) error = %v", err)
	}
	if got.Bundle.BundleID != "bundle-ceiling-noemerg" {
		t.Fatalf("applyRollbackCeiling(nil emergency) bundle=%q, want latest unchanged", got.Bundle.BundleID)
	}
}

// TestApplyRollbackCeilingActiveLookupError covers the branch where
// ActiveRollbackForFollower returns an error: the ceiling propagates it rather
// than serving a possibly-stale bundle.
func TestApplyRollbackCeilingActiveLookupError(t *testing.T) {
	store := mustStore(t)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-ceiling-activeerr",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	handler := newTestHandler(t, store, nil)
	handler.emergencyControls = failingEmergencyStore{}
	_, err := handler.applyRollbackCeiling(
		httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil),
		defaultFollowerIdentity(),
		PublishedBundle{Bundle: v1},
		testNow,
	)
	if err == nil || !strings.Contains(err.Error(), "emergency store failed") {
		t.Fatalf("applyRollbackCeiling(active lookup error) err=%v, want propagated error", err)
	}
}
