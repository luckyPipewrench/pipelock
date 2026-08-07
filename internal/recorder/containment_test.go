// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"os"
	"path/filepath"
	"strings"
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

func TestResolvedEvidenceLocationRejectsDirectorySwap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	locationDir := filepath.Join(root, "recorder-a", "run-a")
	writeDiscoveryShard(t, locationDir)
	location, err := ResolveEvidenceLocation(root, "recorder-a/run-a")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation: %v", err)
	}
	original := locationDir + "-original"
	if err := os.Rename(locationDir, original); err != nil {
		t.Fatalf("move selected location: %v", err)
	}
	external := t.TempDir()
	writeDiscoveryShard(t, external)
	if err := os.Symlink(external, locationDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ReadEvidenceLocationEntries(location); err == nil {
		t.Fatal("resolved location followed a substituted directory symlink")
	}
}

func TestResolvedEvidenceLocationRejectsRootSwap(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "evidence")
	writeDiscoveryShard(t, root)
	location, err := ResolveEvidenceLocation(root, "")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation: %v", err)
	}
	if err := os.Rename(root, root+"-original"); err != nil {
		t.Fatalf("move evidence root: %v", err)
	}
	external := t.TempDir()
	writeDiscoveryShard(t, external)
	if err := os.Symlink(external, root); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ReadEvidenceLocationEntries(location); err == nil {
		t.Fatal("resolved location followed a substituted root symlink")
	}
}

func TestResolvedEvidenceLocationRejectsFileSwap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeDiscoveryShard(t, root)
	location, err := ResolveEvidenceLocation(root, "")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation: %v", err)
	}
	shard := filepath.Join(root, discoveryShardName)
	if err := os.Remove(shard); err != nil {
		t.Fatalf("remove evidence shard: %v", err)
	}
	external := filepath.Join(t.TempDir(), "external.jsonl")
	if err := os.WriteFile(external, []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("write external evidence: %v", err)
	}
	if err := os.Symlink(external, shard); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ReadEvidenceLocationFileBounded(location, discoveryShardName, 1024); err == nil {
		t.Fatal("resolved location followed a substituted evidence-file symlink")
	} else if strings.Contains(err.Error(), "outside") {
		t.Fatalf("error exposed substituted evidence contents: %v", err)
	}
}
