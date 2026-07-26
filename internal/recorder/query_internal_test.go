// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0. See LICENSE.

package recorder

import (
	"errors"
	"math"
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

	tests := []struct {
		name          string
		maxEntries    int
		wantEntries   int
		wantTruncated bool
	}{
		{name: "unbounded", maxEntries: 0, wantEntries: 3},
		{name: "bounded within", maxEntries: 3, wantEntries: 3},
		{name: "bounded over", maxEntries: 2, wantEntries: 2, wantTruncated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries, truncated, err := readDirectoryEntries(dir, test.maxEntries)
			if err != nil || truncated != test.wantTruncated || len(entries) != test.wantEntries {
				t.Fatalf("readDirectoryEntries = %d entries, truncated %t, err %v; want %d, %t, nil", len(entries), truncated, err, test.wantEntries, test.wantTruncated)
			}
		})
	}

	// A missing directory surfaces the open error rather than silently succeeding.
	if _, _, err := readDirectoryEntries(filepath.Join(dir, "missing"), 1); err == nil {
		t.Fatal("readDirectoryEntries accepted a missing directory")
	}

	regularFile := filepath.Join(dir, "regular-file")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readDirectoryEntries(regularFile, 1); err == nil {
		t.Fatal("readDirectoryEntries accepted a regular file as a directory")
	}
}

func TestReadDirectoryEntriesMaxIntNoOverflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed entry %q: %v", name, err)
		}
	}
	// maxEntries at math.MaxInt must not overflow maxEntries+1 into a negative
	// count (which would make ReadDir read the directory unbounded).
	entries, truncated, err := readDirectoryEntries(dir, math.MaxInt)
	if err != nil || truncated || len(entries) != 2 {
		t.Fatalf("readDirectoryEntries(MaxInt) = %d entries, truncated %t, err %v; want 2, false, nil", len(entries), truncated, err)
	}
}

func TestListSessionsBoundedResultReportsTruncation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"evidence-b-0.jsonl", "evidence-a-0.jsonl", "evidence-c-0.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	result, err := ListSessionsBoundedResult(dir, 2)
	if err != nil {
		t.Fatalf("ListSessionsBoundedResult: %v", err)
	}
	if !result.Truncated || len(result.Sessions) != 2 {
		t.Fatalf("result = %+v, want two sessions with truncation", result)
	}

	if _, err := ListSessionsBounded(dir, 2); !errors.Is(err, ErrEvidenceReadLimitExceeded) {
		t.Fatalf("ListSessionsBounded error = %v, want ErrEvidenceReadLimitExceeded", err)
	}
}

func TestMaxDirectoryEntriesUsesExplicitFilterLimit(t *testing.T) {
	t.Parallel()

	got := maxDirectoryEntries(&QueryFilter{MaxDirectoryEntries: 7})
	if got != 7 {
		t.Fatalf("maxDirectoryEntries = %d, want explicit filter limit", got)
	}
}
