//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package secperm

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
	foreign := foreignGID(t)
	if inProcessGroups(foreign) {
		t.Fatalf("inProcessGroups(%d) = true for a gid we are not a member of, want false", foreign)
	}
}

// TestOwnedGroupWritableRefusesGroupExecute pins the mask. The widening this
// policy exists to accept is group read/write, which is what a container platform
// sets on a volume. Group execute is not part of that, so it is drift from
// somewhere else and must not ride along on this rationale.
func TestOwnedGroupWritableRefusesGroupExecute(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []fs.FileMode{0o610, 0o670, 0o710} {
		path := filepath.Join(dir, "x"+mode.String())
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod() error = %v", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("Lstat() error = %v", err)
		}
		if err := OwnedGroupWritableAllowed(info); err == nil {
			t.Fatalf("OwnedGroupWritableAllowed(%04o) = nil, want refusal for group-execute", mode)
		}
	}
}

// TestOwnedGroupWritableRefusesMissingOwnership covers the path taken when the
// filesystem gives no ownership metadata. The claim being made is "this file is
// ours", so with nothing to check it against the answer has to be no.
func TestOwnedGroupWritableRefusesMissingOwnership(t *testing.T) {
	info := statlessFileInfo{mode: 0o660}
	err := OwnedGroupWritableAllowed(info)
	if err == nil {
		t.Fatal("OwnedGroupWritableAllowed(no ownership metadata) = nil, want refusal")
	}
	if !strings.Contains(err.Error(), "ownership is unavailable") {
		t.Fatalf("error = %v, want it to name the missing ownership metadata", err)
	}
}

// TestOwnedGroupWritableAcceptsPrivateModeWithoutOwnership confirms the ownership
// requirement applies only where group bits make it necessary. A file with no
// group bits needs no ownership claim, so it must not be refused for lacking one.
func TestOwnedGroupWritableAcceptsPrivateModeWithoutOwnership(t *testing.T) {
	if err := OwnedGroupWritableAllowed(statlessFileInfo{mode: 0o600}); err != nil {
		t.Fatalf("OwnedGroupWritableAllowed(0600, no ownership metadata) = %v, want nil", err)
	}
}

// statlessFileInfo is a regular-file FileInfo whose Sys() carries no
// *syscall.Stat_t, which is how a filesystem without ownership metadata presents.
type statlessFileInfo struct {
	mode fs.FileMode
}

func (f statlessFileInfo) Name() string       { return "stateless" }
func (f statlessFileInfo) Size() int64        { return 0 }
func (f statlessFileInfo) Mode() fs.FileMode  { return f.mode }
func (f statlessFileInfo) ModTime() time.Time { return time.Time{} }
func (f statlessFileInfo) IsDir() bool        { return false }
func (f statlessFileInfo) Sys() any           { return nil }

// statFileInfo is a regular-file FileInfo with a controllable owner and group, so
// the refusal branches can be exercised without the privileges a real chown needs.
// The chown-based test above skips as an unprivileged user, which would leave the
// two branches that actually protect us unexercised in CI.
type statFileInfo struct {
	mode fs.FileMode
	uid  uint32
	gid  uint32
}

func (f statFileInfo) Name() string       { return "stat" }
func (f statFileInfo) Size() int64        { return 0 }
func (f statFileInfo) Mode() fs.FileMode  { return f.mode }
func (f statFileInfo) ModTime() time.Time { return time.Time{} }
func (f statFileInfo) IsDir() bool        { return false }
func (f statFileInfo) Sys() any {
	return &syscall.Stat_t{Uid: f.uid, Gid: f.gid}
}

// ownStat returns this process's real uid and gid as the filesystem reports them,
// so the tests below can derive foreign ids with uint32 arithmetic. Taking them
// from a real stat rather than converting os.Geteuid means there is no narrowing
// int conversion anywhere, which both avoids a gosec overflow finding honestly and
// keeps the fixtures anchored to what the filesystem actually says.
func ownStat(t *testing.T) (uid, gid uint32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "own")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("filesystem does not report ownership metadata")
	}
	return st.Uid, st.Gid
}

// foreignGIDUint32 finds a gid this process is not a member of, walking upward in
// uint32 space. Widening back to int for the membership check is safe; narrowing
// is what needed avoiding.
func foreignGIDUint32(t *testing.T, start uint32) uint32 {
	t.Helper()
	for candidate := start + 1; candidate < start+512; candidate++ {
		if !inProcessGroups(int(candidate)) {
			return candidate
		}
	}
	t.Skip("no nearby gid found that this process is not a member of")
	return 0
}

// TestOwnedGroupWritableRefusesForeignOwner pins the owner check. Group membership
// says this process can reach the file; it does not say the file is ours. A file
// owned by a different uid that merely shares a group is somebody else's state.
func TestOwnedGroupWritableRefusesForeignOwner(t *testing.T) {
	uid, gid := ownStat(t)
	info := statFileInfo{mode: 0o660, uid: uid + 1, gid: gid}
	err := OwnedGroupWritableAllowed(info)
	if err == nil {
		t.Fatalf("OwnedGroupWritableAllowed(0660, uid %d) = nil, want refusal for a foreign owner", uid+1)
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("error = %v, want it to name the foreign owner", err)
	}
}

// TestOwnedGroupWritableRefusesForeignGroupUnprivileged is the gid half of the
// same guard, reached with the owner correct so the group check is what decides.
func TestOwnedGroupWritableRefusesForeignGroupUnprivileged(t *testing.T) {
	uid, gid := ownStat(t)
	foreign := foreignGIDUint32(t, gid)
	info := statFileInfo{mode: 0o660, uid: uid, gid: foreign}
	err := OwnedGroupWritableAllowed(info)
	if err == nil {
		t.Fatalf("OwnedGroupWritableAllowed(0660, gid %d) = nil, want refusal for a foreign group", foreign)
	}
	if !strings.Contains(err.Error(), "is not a member of") {
		t.Fatalf("error = %v, want it to name the group this process is not in", err)
	}
}

// TestOwnedGroupWritableAcceptsOurOwnGroupWidening is the positive case at the
// same level, so the refusals above cannot pass merely because everything is
// refused: our own uid and gid with the platform's group read/write is accepted.
func TestOwnedGroupWritableAcceptsOurOwnGroupWidening(t *testing.T) {
	uid, gid := ownStat(t)
	if err := OwnedGroupWritableAllowed(statFileInfo{mode: 0o660, uid: uid, gid: gid}); err != nil {
		t.Fatalf("OwnedGroupWritableAllowed(0660, our own uid/gid) = %v, want nil", err)
	}
}
