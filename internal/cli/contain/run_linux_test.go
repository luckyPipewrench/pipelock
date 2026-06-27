// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import "testing"

// TestAgentSysProcAttr_DropsCallerGroups locks in the privilege-separation
// invariant for the contained launch: setgroups(2) MUST run (NoSetGroups
// false) so the child drops root's supplementary groups instead of inheriting
// them, and it launches under exactly the agent's resolved group set.
func TestAgentSysProcAttr_DropsCallerGroups(t *testing.T) {
	groups := []uint32{966, 1001}
	attr := agentSysProcAttr(966, 966, groups)

	if attr.Credential == nil {
		t.Fatal("credential must not be nil")
	}
	if attr.Credential.NoSetGroups {
		t.Fatal("NoSetGroups must be false so setgroups(2) drops the launcher's (root's) supplementary groups")
	}
	if attr.Credential.Uid != 966 || attr.Credential.Gid != 966 {
		t.Fatalf("uid/gid = %d/%d, want 966/966", attr.Credential.Uid, attr.Credential.Gid)
	}
	if !equalGIDs(attr.Credential.Groups, groups) {
		t.Fatalf("groups = %v, want %v", attr.Credential.Groups, groups)
	}
	for _, g := range attr.Credential.Groups {
		if g == 0 {
			t.Fatalf("contained launch must not carry root group 0: %v", attr.Credential.Groups)
		}
	}
}
