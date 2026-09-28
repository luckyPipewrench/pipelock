// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !aix

package recorder

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEvidenceLocationReadsThroughSearchOnlyAncestor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	base := t.TempDir()
	ancestor := filepath.Join(base, "search-only")
	root := filepath.Join(ancestor, "evidence")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	writeDiscoveryShard(t, root)
	if err := unix.Chmod(ancestor, 0o111); err != nil {
		t.Skipf("chmod unavailable: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chmod(ancestor, 0o700) })
	locations, err := DiscoverEvidenceLocations(root)
	if err != nil {
		t.Fatalf("discover through search-only ancestor: %v", err)
	}
	if len(locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(locations))
	}
	entries, err := ReadEvidenceLocationEntries(locations[0])
	if err != nil {
		t.Fatalf("read location through search-only ancestor: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("read location returned no evidence files")
	}
}
