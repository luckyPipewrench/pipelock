// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"encoding/hex"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// The wasm verifier behind the viewer's "Verify in your browser" button serves
// BOTH surfaces: viewer-live.js drives it for a live session bundle, and the
// Replay tab drives it for the published archive. Because it takes no flags, it
// decides for itself which semantics to apply, and this is the test of that
// decision.
//
// It asserts the MODE rather than a passing verification, which is what makes it
// hermetic. VerifyPublishedBundleBytes pins the compiled published root, so a
// bundle signed by a test key can never verify OK here and any test that
// demanded OK would have to read a machine-local artifact and skip on CI. The
// routing is the part this code owns, and the mode reports it directly.
func TestVerifyPublishedBundleBytes_SelectsModeFromAuthorization(t *testing.T) {
	t.Run("authorization present selects archive semantics", func(t *testing.T) {
		dir, _, orchPriv := buildDelegatedRunDir(t)
		bundle, err := playground.ArchiveRunForPublishedReplay(dir, orchPriv)
		if err != nil {
			t.Fatalf("ArchiveRunForPublishedReplay: %v", err)
		}
		rep, err := playground.VerifyPublishedBundleBytes(bundle)
		if err != nil {
			t.Fatalf("VerifyPublishedBundleBytes: %v", err)
		}
		if rep.Mode != "published-replay-archive" {
			t.Fatalf("mode = %q, want the archive mode; the Replay tab would fail on an artifact the kit accepts", rep.Mode)
		}
	})

	// A live bundle carries no archive authorization and must take the strict
	// path, where an expired delegation still fails closed exactly as it does for
	// the command-line verifier.
	t.Run("no authorization stays strict", func(t *testing.T) {
		dir, pubHex, _ := buildDelegatedRunDir(t)
		bundle, err := playground.ArchiveRunForDownload(dir, pubHex)
		if err != nil {
			t.Fatalf("ArchiveRunForDownload: %v", err)
		}
		rep, err := playground.VerifyPublishedBundleBytes(bundle)
		if err != nil {
			t.Fatalf("VerifyPublishedBundleBytes: %v", err)
		}
		if rep.Mode != "strict-live" {
			t.Fatalf("mode = %q, want strict; a bundle must not select its own leniency", rep.Mode)
		}
	})

	// Guard against the fixture accidentally being signed by the published root,
	// which would make the assertions above pass for the wrong reason.
	t.Run("the test root is not the published root", func(t *testing.T) {
		_, pubHex, _ := buildDelegatedRunDir(t)
		if pubHex == playground.PublishedOrchestratorPubKeyHex {
			t.Fatal("the test fixture is signed by the published root")
		}
		if _, err := hex.DecodeString(pubHex); err != nil {
			t.Fatalf("fixture key is not hex: %v", err)
		}
	})
}
