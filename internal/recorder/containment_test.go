// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"errors"
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

func TestResolvedEvidenceLocationBoundedAndTailReads(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	name := "evidence-proxy-0.jsonl"
	content := []byte("0123456789")
	if err := os.WriteFile(filepath.Join(root, name), content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "evidence-proxy-1.jsonl"), []byte("second"), 0o600); err != nil {
		t.Fatalf("WriteFile second shard: %v", err)
	}
	location, err := ResolveEvidenceLocation(root, "")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation: %v", err)
	}

	entries, truncated, err := readEvidenceLocationDirectoryEntries(location, 1)
	if err != nil {
		t.Fatalf("readEvidenceLocationDirectoryEntries bounded: %v", err)
	}
	if len(entries) != 1 || !truncated {
		t.Fatalf("bounded directory entries = %d, truncated=%v; want 1, true", len(entries), truncated)
	}
	entries, truncated, err = readEvidenceLocationDirectoryEntries(location, 0)
	if err != nil {
		t.Fatalf("readEvidenceLocationDirectoryEntries unbounded: %v", err)
	}
	if len(entries) != 2 || truncated {
		t.Fatalf("unbounded directory entries = %d, truncated=%v; want 2, false", len(entries), truncated)
	}

	whole, err := ReadEvidenceLocationFileBounded(location, name, 0)
	if err != nil {
		t.Fatalf("ReadEvidenceLocationFileBounded default: %v", err)
	}
	if !bytes.Equal(whole, content) {
		t.Fatalf("bounded read = %q, want %q", whole, content)
	}
	if _, err := ReadEvidenceLocationFileBounded(location, name, 5); !errors.Is(err, ErrEvidenceReadLimitExceeded) {
		t.Fatalf("small bounded read error = %v, want ErrEvidenceReadLimitExceeded", err)
	}

	tail, omitted, err := ReadEvidenceLocationFileTail(location, name, 4)
	if err != nil {
		t.Fatalf("ReadEvidenceLocationFileTail partial: %v", err)
	}
	if string(tail) != "6789" || !omitted {
		t.Fatalf("partial tail = %q, omitted=%v; want 6789, true", tail, omitted)
	}
	tail, omitted, err = ReadEvidenceLocationFileTail(location, name, 20)
	if err != nil {
		t.Fatalf("ReadEvidenceLocationFileTail whole: %v", err)
	}
	if !bytes.Equal(tail, content) || omitted {
		t.Fatalf("whole tail = %q, omitted=%v; want %q, false", tail, omitted, content)
	}
	if _, _, err := ReadEvidenceLocationFileTail(location, name, 0); err == nil {
		t.Fatal("ReadEvidenceLocationFileTail accepted a non-positive limit")
	}
	if _, err := ReadEvidenceLocationFileBounded(location, "../escape", 20); err == nil {
		t.Fatal("ReadEvidenceLocationFileBounded accepted a non-base filename")
	}
	if _, _, err := ReadEvidenceLocationFileTail(location, "../escape", 20); err == nil {
		t.Fatal("ReadEvidenceLocationFileTail accepted a non-base filename")
	}
}

func TestResolvedEvidenceLocationRejectsInvalidDescriptors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeDiscoveryShard(t, root)
	writeDiscoveryShard(t, filepath.Join(root, "other"))
	if err := os.Mkdir(filepath.Join(root, "run"), 0o750); err != nil {
		t.Fatalf("Mkdir run: %v", err)
	}
	tests := []struct {
		name     string
		location EvidenceLocation
	}{
		{name: "empty descriptor"},
		{name: "directory does not match ID", location: EvidenceLocation{Root: root, ID: "run", Dir: root}},
		{name: "ID escapes root", location: EvidenceLocation{Root: root, ID: "../escape", Dir: filepath.Join(root, "..", "escape")}},
		{name: "ID is not clean", location: EvidenceLocation{Root: root, ID: "run/../other", Dir: filepath.Join(root, "other")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ReadEvidenceLocationEntries(tt.location); err == nil {
				t.Fatalf("ReadEvidenceLocationEntries(%+v) accepted invalid descriptor", tt.location)
			}
			if _, _, _, err := readEntriesAtEvidenceLocation(tt.location, discoveryShardName, entryReadLimits{}); err == nil {
				t.Fatalf("readEntriesAtEvidenceLocation(%+v) accepted invalid descriptor", tt.location)
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
