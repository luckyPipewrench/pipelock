// Licensed under the Apache License, Version 2.0. See LICENSE.

package recorder

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDirectoryEntriesBounded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed entry %q: %v", name, err)
		}
	}

	// Unbounded (maxEntries <= 0) returns every entry.
	all, err := readDirectoryEntries(dir, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("unbounded readDirectoryEntries = %d entries, err %v; want 3", len(all), err)
	}

	// Bounded at or above the entry count succeeds.
	within, err := readDirectoryEntries(dir, 3)
	if err != nil || len(within) != 3 {
		t.Fatalf("bounded-within readDirectoryEntries = %d entries, err %v; want 3", len(within), err)
	}

	// Bounded below the entry count fails closed.
	if _, err := readDirectoryEntries(dir, 2); err == nil {
		t.Fatal("readDirectoryEntries accepted a directory exceeding the entry cap")
	}

	// A missing directory surfaces the open error rather than silently succeeding.
	if _, err := readDirectoryEntries(filepath.Join(dir, "missing"), 1); err == nil {
		t.Fatal("readDirectoryEntries accepted a missing directory")
	}
}
