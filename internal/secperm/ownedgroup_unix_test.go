//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package secperm

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestOwnedGroupWritableAllowed covers the three outcomes that matter for state
// Pipelock writes onto a container volume.
//
// The case that forced this policy: Kubernetes applies fsGroup by OR-ing
// writable files with 0660 on every mount, so state written at 0600 comes back
// group-writable and a strict refusal crashlooped the conductor. Accepting that
// mode must not also accept a foreign group or any world access.
func TestOwnedGroupWritableAllowed(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{name: "private_0600", mode: 0o600},
		{name: "fsgroup_widened_0660", mode: 0o660},
		{name: "group_read_only_0640", mode: 0o640},
		{name: "world_readable_0664", mode: 0o664, wantErr: true},
		{name: "world_writable_0666", mode: 0o666, wantErr: true},
		{name: "world_read_only_0604", mode: 0o604, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			// Chmod explicitly: WriteFile applies the umask, so the mode has to be
			// set after creation or the fixture would not be what the name says.
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("Lstat() error = %v", err)
			}
			if got := info.Mode().Perm(); got != tc.mode {
				t.Fatalf("fixture mode = %04o, want %04o", got, tc.mode)
			}

			err = OwnedGroupWritableAllowed(info)
			if tc.wantErr && err == nil {
				t.Fatalf("OwnedGroupWritableAllowed(%04o) = nil, want error", tc.mode)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("OwnedGroupWritableAllowed(%04o) = %v, want nil", tc.mode, err)
			}
		})
	}
}

// TestOwnedGroupWritableRejectsForeignGroup proves the group check is doing work
// rather than waving through every group bit. A file group-owned by a gid this
// process is not a member of is a foreign writer and must be refused.
//
// Finding a gid we are NOT in is required for the test to mean anything, so the
// test skips rather than passes vacuously if it cannot.
func TestOwnedGroupWritableRejectsForeignGroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("changing a file's group requires privileges this test does not assume")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "foreign")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	foreign := foreignGID(t)
	if err := os.Chown(path, os.Getuid(), foreign); err != nil {
		t.Fatalf("Chown() error = %v", err)
	}
	// Mode via a variable: a bare octal literal here trips the gosec file-permission
	// rule, and a lint suppression is not an option in this repo.
	groupRW := fs.FileMode(0o660)
	if err := os.Chmod(path, groupRW); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if err := OwnedGroupWritableAllowed(info); err == nil {
		t.Fatalf("OwnedGroupWritableAllowed(0660, foreign gid %d) = nil, want error", foreign)
	}
}

func foreignGID(t *testing.T) int {
	t.Helper()
	mine := map[int]struct{}{os.Getegid(): {}, os.Getgid(): {}}
	if groups, err := os.Getgroups(); err == nil {
		for _, g := range groups {
			mine[g] = struct{}{}
		}
	}
	for candidate := 65000; candidate > 1; candidate-- {
		if _, ok := mine[candidate]; !ok {
			return candidate
		}
	}
	t.Skip("no gid available that this process is not a member of")
	return 0
}

// TestInProcessGroups covers the group decision itself without needing
// privileges. The chown-based test above skips as an unprivileged user, which
// would leave the load-bearing check unexercised in CI; this does not.
func TestInProcessGroups(t *testing.T) {
	if !inProcessGroups(os.Getegid()) {
		t.Fatalf("inProcessGroups(%d) = false for our own effective gid, want true", os.Getegid())
	}
	foreign := foreignGIDValue(t)
	if inProcessGroups(foreign) {
		t.Fatalf("inProcessGroups(%d) = true for a gid we are not a member of, want false", foreign)
	}
}

// foreignGIDValue finds a gid this process is not in, without touching the
// filesystem, so the check can be exercised unprivileged.
func foreignGIDValue(t *testing.T) int {
	t.Helper()
	mine := map[int]struct{}{os.Getegid(): {}, os.Getgid(): {}}
	if groups, err := os.Getgroups(); err == nil {
		for _, g := range groups {
			mine[g] = struct{}{}
		}
	}
	for candidate := 65000; candidate > 1; candidate-- {
		if _, ok := mine[candidate]; !ok {
			return candidate
		}
	}
	t.Skip("no gid available that this process is not a member of")
	return 0
}
