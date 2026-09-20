// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBrowserCAOwnershipRefusesASymlinkedLeaf drives the real descriptor-based
// operation against the attack it exists to stop: the contained agent owns the
// directory holding its NSS files, so it can replace a leaf with a symlink and
// try to redirect a privileged mode change onto a file elsewhere on the host.
//
// The suite elsewhere substitutes an unprivileged stand-in for this function
// because Fchown needs root. Nothing exercised the real one, and a comment in
// that suite claimed this test already existed when it did not, so the whole
// attack path was covered by an assertion that was never written.
func TestBrowserCAOwnershipRefusesASymlinkedLeaf(t *testing.T) {
	dir := t.TempDir()

	// The file the attacker wants the privileged change applied to. 0400 is
	// chosen so a redirected chmod to 0600 would be visible as a change, while
	// staying inside the repository's file-permission rule.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o400); err != nil {
		t.Fatal(err)
	}
	victimBefore, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}

	leaf := filepath.Join(dir, "cert9.db")
	if err := os.Symlink(victim, leaf); err != nil {
		t.Fatal(err)
	}

	err = applyAgentOwnershipNoFollow(leaf, 0o600, os.Getuid(), os.Getgid())
	if err == nil {
		t.Fatal("applyAgentOwnershipNoFollow followed a symlinked leaf")
	}
	if !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("err = %v, want the open refusal naming the no-follow open", err)
	}

	// The refusal is only meaningful if the target was left alone.
	victimAfter, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if victimAfter.Mode().Perm() != victimBefore.Mode().Perm() {
		t.Fatalf("symlink target mode changed from %v to %v; the privileged change was redirected",
			victimBefore.Mode().Perm(), victimAfter.Mode().Perm())
	}
}

// TestBrowserCAOwnershipAppliesToARegularLeaf is the positive control. Without
// it, the refusal above would still pass if applyAgentOwnershipNoFollow
// refused everything, which is the shape a vacuous negative test takes.
func TestBrowserCAOwnershipAppliesToARegularLeaf(t *testing.T) {
	leaf := filepath.Join(t.TempDir(), "cert9.db")
	if err := os.WriteFile(leaf, []byte("db"), 0o400); err != nil {
		t.Fatal(err)
	}
	// Pass this process's own ids so Fchown is a no-op rather than a privileged
	// change; the mode change from 0400 to 0600 is what this control observes.
	if err := applyAgentOwnershipNoFollow(leaf, 0o600, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("applyAgentOwnershipNoFollow on a regular file: %v", err)
	}
	info, err := os.Stat(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestBrowserCAOwnershipRefusesANonRegularLeaf covers the other refusal branch:
// a directory where install wrote a file.
func TestBrowserCAOwnershipRefusesANonRegularLeaf(t *testing.T) {
	leaf := filepath.Join(t.TempDir(), "cert9.db")
	if err := os.Mkdir(leaf, 0o750); err != nil {
		t.Fatal(err)
	}
	err := applyAgentOwnershipNoFollow(leaf, 0o600, os.Getuid(), os.Getgid())
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v, want the non-regular-file refusal", err)
	}
}
