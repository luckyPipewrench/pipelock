// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveEvidenceLocationRefusesEscapingID pins the containment property
// rather than one implementation of it. Two mechanisms currently enforce it:
// the location-ID cleaner rejects a dot-dot path, and a resolved ID must match
// a discovered descendant location. Either alone contains an escape today, so
// this asserts the outcome so a later change to the matching logic cannot open
// the escape while the cleaner is the only thing left holding it shut.
func TestResolveEvidenceLocationRefusesEscapingID(t *testing.T) {
	t.Parallel()
	escaping := []string{
		"..",
		"../..",
		filepath.Join("..", "..", "etc"),
		filepath.Join("..", "sibling-root"),
	}
	for _, locationID := range escaping {
		t.Run(locationID, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeDiscoveryShard(t, root)
			// Give the escape a real target so a resolved path would succeed if
			// containment failed, making the assertion meaningful rather than a
			// missing-directory artifact.
			writeDiscoveryShard(t, filepath.Join(filepath.Dir(root), "sibling-root"))
			if _, err := ResolveEvidenceLocation(root, locationID); err == nil {
				t.Fatalf("ResolveEvidenceLocation(%q) resolved outside the evidence root, want refusal", locationID)
			}
		})
	}
}

// TestDiscoverEvidenceLocationsFailsClosedOnUnreadableDir proves an unreadable
// directory surfaces an error instead of being skipped. Skipping would make
// missing evidence indistinguishable from absent evidence, which is a fail-open
// on evidence completeness. One live recorder directory is owned by a separate
// service account, so this state is real rather than theoretical.
func TestDiscoverEvidenceLocationsFailsClosedOnUnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := t.TempDir()
	writeDiscoveryShard(t, root)
	// An empty directory is enough: discovery fails when it cannot read the
	// directory, whatever it holds. Keeping it empty also lets the temp-dir
	// cleanup rmdir it without needing its traversal bit restored, so the test
	// never has to chmod a directory back to a permissive mode.
	blocked := filepath.Join(root, "unreadable")
	if err := os.Mkdir(blocked, 0o750); err != nil {
		t.Fatalf("Mkdir blocked directory: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Skipf("chmod unavailable: %v", err)
	}

	if _, err := DiscoverEvidenceLocations(root); err == nil {
		t.Fatal("DiscoverEvidenceLocations() succeeded over an unreadable directory, want a surfaced error so missing evidence cannot look absent")
	}
}
