// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// TestConfigHoldsCanonicalPolicyHashOrigin proves a Config keeps the origin
// of its cached canonical policy hash for its own lifetime, so receipts
// stamped with it never have it scanned as content however long it runs.
func TestConfigHoldsCanonicalPolicyHashOrigin(t *testing.T) {
	cfg := Defaults()
	hash := cfg.CanonicalPolicyHash()
	cached, ok := cfg.canonicalHashCache.Load().(cachedPolicyHash)
	if !ok || cached.hash != hash || !cached.origin.Held() || cached.origin.String() != hash {
		t.Fatal("config does not hold the origin of its canonical policy hash")
	}
	if again := cfg.CanonicalPolicyHash(); again != hash {
		t.Fatalf("cached hash changed: %q != %q", again, hash)
	}
}
