// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"os"
	"testing"
)

// The wasm verifier behind the viewer's "Verify in your browser" button serves
// BOTH surfaces: viewer-live.js drives it for a live session bundle, and the
// Replay tab drives it for the published archive. They need different semantics,
// so both are asserted here. Shipping only the archive half would break live
// verification; shipping only the strict half leaves the Replay tab failing on
// an artifact the downloadable kit accepts, which is worse than either alone
// because it makes the product disagree with itself about its own evidence.
func TestVerifyPublishedBundleBytes_ArchiveAndLiveSemantics(t *testing.T) {
	t.Run("root_authorized_archive_verifies", func(t *testing.T) {
		bundle, err := os.ReadFile("/tmp/archive-proof/replay-bundle.tar.gz")
		if err != nil {
			t.Skipf("archived proof bundle not present: %v", err)
		}
		rep, err := VerifyPublishedBundleBytes(bundle)
		if err != nil {
			t.Fatalf("VerifyPublishedBundleBytes: %v", err)
		}
		if !rep.OK {
			t.Fatalf("the browser verifier rejected a root-authorized published replay: %s", rep.FailureSummary())
		}
	})

	// A live bundle carries no archive authorization. It must take the strict
	// path, where an expired delegation still fails closed exactly as it does
	// for the CLI.
	t.Run("bundle_without_authorization_stays_strict", func(t *testing.T) {
		bundle, err := os.ReadFile("/tmp/pg-artifacts/replay-bundle.tar.gz")
		if err != nil {
			t.Skipf("unauthorized proof bundle not present: %v", err)
		}
		rep, err := VerifyPublishedBundleBytes(bundle)
		if err != nil {
			t.Fatalf("VerifyPublishedBundleBytes: %v", err)
		}
		if rep.OK {
			t.Fatal("a bundle with no archive authorization must be verified strictly, and this one's delegation has expired")
		}
	})
}
