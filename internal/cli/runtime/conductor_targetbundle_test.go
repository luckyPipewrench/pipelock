//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
)

// TestTargetBundleActiveError covers the branch where cache.Active() fails (no
// bundle has ever been applied): targetBundle fails closed rather than rolling
// back to nothing.
func TestTargetBundleActiveError(t *testing.T) {
	cache, err := applycache.Open(applycache.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open(cache): %v", err)
	}
	applier := conductorRollbackApplier{cache: cache}
	if _, err := applier.targetBundle(); !errors.Is(err, applycache.ErrNoValidBundle) {
		t.Fatalf("targetBundle(empty cache) err=%v, want ErrNoValidBundle", err)
	}
}

// TestTargetBundleEmptyBaseHash covers the predecessor-missing branch: a single
// applied bundle has no BaseHash, so there is nothing to roll back to.
func TestTargetBundleEmptyBaseHash(t *testing.T) {
	s, policy := newConductorApplyTestServer(t)
	b1 := signedRuntimePolicyBundle(t, policy, "bundle-target-1", 1, "", rollbackTestBundle1YAML)
	if _, err := s.ApplyConductorPolicyBundle(b1, ConductorApplyOptions{Resolver: policy.resolver()}); err != nil {
		t.Fatalf("apply bundle-1: %v", err)
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	applier := conductorRollbackApplier{server: s, cache: cache, resolver: policy.resolver()}
	if _, err := applier.targetBundle(); !errors.Is(err, applycache.ErrNoValidBundle) {
		t.Fatalf("targetBundle(no predecessor) err=%v, want ErrNoValidBundle", err)
	}
}

// TestTargetBundleUnreadableTargetRecord covers the branch where the active
// bundle's predecessor record (reached via BaseHash) cannot be read. After two
// bundles are applied, corrupting bundle-1's on-disk record makes the BaseHash
// lookup fail so targetBundle returns the read error rather than a stale target.
func TestTargetBundleUnreadableTargetRecord(t *testing.T) {
	s, policy := newConductorApplyTestServer(t)
	cache, b1, _ := applyTwoBundles(t, s, policy)

	b1Hash, err := b1.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(bundle-1): %v", err)
	}
	// Predecessor record lives at <bundle_cache_dir>/bundles/<b1Hash>.json.
	recordPath := filepath.Join(s.cfg.Conductor.BundleCacheDir, "bundles", b1Hash+".json")
	if _, statErr := os.Stat(recordPath); statErr != nil {
		t.Fatalf("predecessor record missing before corruption: %v", statErr)
	}
	if err := os.WriteFile(recordPath, []byte("{ not valid json"), 0o600); err != nil {
		t.Fatalf("corrupt predecessor record: %v", err)
	}

	applier := conductorRollbackApplier{server: s, cache: cache, resolver: policy.resolver()}
	if _, err := applier.targetBundle(); err == nil {
		t.Fatal("targetBundle(corrupt predecessor) error = nil, want read failure")
	}
}
