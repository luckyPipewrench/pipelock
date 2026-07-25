// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package recorder

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsExpiryLockNeverClaimsAcquired guards a fail-open.
//
// The expiry path treats a true return as proof that no live writer holds the
// file and deletes it. On Windows the writer-presence lock is a no-op, so
// nothing could ever contradict that claim, and returning true would let
// automatic expiry delete evidence out from under an active writer. Refusing
// the lock is the only fail-closed answer until real LockFileEx locking lands.
func TestWindowsExpiryLockNeverClaimsAcquired(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "evidence-proxy-0.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = file.Close() }()

	// An unlocked, uncontended file is the most favorable possible input. Even
	// here the answer must be "not acquired".
	locked, lockErr := tryLockEvidenceFileForExpiry(file)
	if lockErr != nil {
		t.Fatalf("unexpected error: %v", lockErr)
	}
	if locked {
		t.Fatal("tryLockEvidenceFileForExpiry returned true on Windows: expiry would delete files with no writer coordination")
	}
}
