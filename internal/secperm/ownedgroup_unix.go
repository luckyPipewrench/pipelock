//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package secperm

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// OwnedGroupWritableAllowed reports whether group read/write on a file Pipelock
// wrote for itself is acceptable, given who this process is.
//
// Why this exists: a container platform can widen the mode of a file we wrote
// correctly. Kubernetes applies fsGroup to a volume by chowning its contents to
// that gid and OR-ing writable files with 0660, and it does so on every mount.
// Pipelock writes its own state at 0600, so the widening is entirely the
// platform's, it reappears after each restart, and fixing the writer cannot
// avoid it. Refusing the file means a non-root workload cannot use a persistent
// volume at all, which is how a strict permission check turned into a
// crashlooping control plane.
//
// The judgement made here is narrow: group read/write is tolerable only when the
// group is one this process already belongs to, so the access it grants is
// access this process already has. Group-write for a group we are NOT in is a
// foreign writer and stays refused. Any other-perms bit stays refused outright.
//
// This is deliberately NOT proof of exclusivity. Unix cannot show that a gid is
// private to one workload, so a gid shared with unrelated writers is a real
// integrity exposure that this check cannot detect. Deployments should give the
// workload its own fsGroup, and where the platform supports it set
// supplementalGroupsPolicy to Strict so implicit image groups cannot widen the
// set silently.
//
// Use it only for state Pipelock writes and owns. Operator-supplied credentials
// and private keys must keep the strict policy: for those, group-write is a
// genuine confidentiality and tamper concern rather than a platform artifact.
func OwnedGroupWritableAllowed(info fs.FileInfo) error {
	perm := info.Mode().Perm()
	if perm&0o007 != 0 {
		return fmt.Errorf("has world-accessible permissions %04o", perm)
	}
	if perm&0o070 == 0 {
		// No group bits at all, so there is nothing to justify.
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Without ownership metadata the claim cannot be checked, so refuse
		// rather than assume. Failing closed here costs an operator a clear
		// error; assuming would accept a foreign writer unseen.
		return fmt.Errorf("has group permissions %04o and file ownership is unavailable", perm)
	}
	fileGID := int(stat.Gid)
	if inProcessGroups(fileGID) {
		return nil
	}
	return fmt.Errorf(
		"has group permissions %04o for gid %d, which this process (uid %d, groups %v) is not a member of",
		perm, fileGID, os.Getuid(), processGroups())
}

func inProcessGroups(gid int) bool {
	if gid == os.Getegid() || gid == os.Getgid() {
		return true
	}
	for _, g := range processGroups() {
		if g == gid {
			return true
		}
	}
	return false
}

// processGroups returns the effective gid plus supplementary groups. fsGroup can
// appear as either, depending on how the platform applies it, so both count.
func processGroups() []int {
	groups, err := os.Getgroups()
	if err != nil {
		return []int{os.Getegid()}
	}
	return groups
}
