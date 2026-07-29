//go:build !windows

// The permission refusals asserted here depend on POSIX mode bits.
// secperm.TooPermissive and OwnedGroupWritableAllowed are deliberate no-ops on
// Windows, so these assertions cannot hold there.

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadOwnedStateAcceptsPlatformWidenedMode covers the OwnedState branch in
// this package rather than only through its callers in other packages.
//
// Coverage is measured per package, so a branch exercised solely by an
// enterprise-tagged caller elsewhere earns this package no credit and the gap is
// invisible until someone reads the report. The behaviour is worth pinning here
// anyway: it is the difference between a non-root workload being able to read its
// own state off a persistent volume and refusing to start.
func TestReadOwnedStateAcceptsPlatformWidenedMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	// The mode a Kubernetes fsGroup mount leaves behind on a file we wrote 0600.
	groupRW := fs.FileMode(0o660)
	if err := os.Chmod(path, groupRW); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	// Strict policy refuses it, which is the failure that crashlooped the
	// conductor. Asserting both halves here keeps the two policies honest about
	// differing.
	if _, err := Read(path, Options{MaxBytes: 1024, DisallowedPerms: 0o037}); err == nil {
		t.Fatal("Read(strict, 0660) = nil error, want refusal")
	}

	data, err := Read(path, Options{MaxBytes: 1024, OwnedState: true})
	if err != nil {
		t.Fatalf("Read(OwnedState, 0660) error = %v, want nil", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("Read() = %q, want the file contents", data)
	}
}

// TestReadOwnedStateStillRefusesWorldAccess pins the limit of the tolerance. Group
// bits from the platform are accepted; world access never is, under either policy.
func TestReadOwnedStateStillRefusesWorldAccess(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		mode fs.FileMode
	}{
		{name: "world_readable_0664", mode: 0o664},
		{name: "world_writable_0666", mode: 0o666},
		{name: "world_read_only_0604", mode: 0o604},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
			if _, err := Read(path, Options{MaxBytes: 1024, OwnedState: true}); err == nil {
				t.Fatalf("Read(OwnedState, %04o) = nil error, want refusal for world access", tc.mode)
			}
		})
	}
}

// TestReadOwnedStateBoundsSizeLikeStrict confirms the tolerance changed only the
// permission decision. Every other guard in Read still applies, so a caller
// cannot use OwnedState to escape the size bound.
func TestReadOwnedStateBoundsSizeLikeStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Read(path, Options{MaxBytes: 8, OwnedState: true}); err == nil {
		t.Fatal("Read(OwnedState, oversize) = nil error, want size refusal")
	}
}
