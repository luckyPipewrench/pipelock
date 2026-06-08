//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestBoundaryApplyAbortsWhenEntitlementLostBeforeReload proves the in-flight
// apply window is closed: a verified bundle that finishes staging AFTER the
// fleet entitlement was torn down must not reach the live-config Reload and must
// not activate. StillEntitled reporting false is the deterministic stand-in for
// a teardownConductor that fired mid-apply.
func TestBoundaryApplyAbortsWhenEntitlementLostBeforeReload(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	reloadCalled := false
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(_ *config.Config) error {
			reloadCalled = true
			return nil
		},
		StillEntitled: func() bool { return false },
	}

	_, err := boundary.Apply(signedTestBundle(t, key, "bundle-1", 1, ""), ApplyOptions{})
	if !errors.Is(err, ErrEntitlementLost) {
		t.Fatalf("Apply(entitlement lost) = %v, want ErrEntitlementLost", err)
	}
	if reloadCalled {
		t.Fatal("Reload must not run once the fleet entitlement is lost mid-apply")
	}
	if _, activeErr := cache.Active(); !errors.Is(activeErr, ErrNoValidBundle) {
		t.Fatalf("Active() after aborted apply = %v, want ErrNoValidBundle (nothing activated)", activeErr)
	}
}

// TestBoundaryApplyProceedsWhenStillEntitled is the positive control: an apply
// whose StillEntitled stays true reloads and activates normally, proving the
// guard only blocks the lost-entitlement case.
func TestBoundaryApplyProceedsWhenStillEntitled(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	reloadCalled := false
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(_ *config.Config) error {
			reloadCalled = true
			return nil
		},
		StillEntitled: func() bool { return true },
	}

	applied, err := boundary.Apply(signedTestBundle(t, key, "bundle-1", 1, ""), ApplyOptions{})
	if err != nil {
		t.Fatalf("Apply(still entitled) error = %v", err)
	}
	if !reloadCalled {
		t.Fatal("Reload must run when the entitlement is intact")
	}
	if applied.ReloadedConfigHash == "" {
		t.Fatal("ReloadedConfigHash = empty, want an activated bundle")
	}
	if _, activeErr := cache.Active(); activeErr != nil {
		t.Fatalf("Active() after successful apply = %v, want activated bundle", activeErr)
	}
}
