// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"io"
	"os/user"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

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

func TestLaunchContainedAgent_RejectsRootUIDOrGID(t *testing.T) {
	tests := []struct {
		name string
		uid  string
		gid  string
	}{
		{name: "root uid", uid: "0", gid: "966"},
		{name: "root gid", uid: "966", gid: "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := containRunLinuxGuardEnv(tt.uid, tt.gid, defaultLaunchScript)
			err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
			if err == nil {
				t.Fatal("expected root uid/gid rejection")
			}
			if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
			}
			if !strings.Contains(err.Error(), "refusing to launch a contained tool as root") {
				t.Fatalf("error = %v, want root launch refusal", err)
			}
		})
	}
}

func TestLaunchContainedAgent_RejectsUnexpectedLaunchPath(t *testing.T) {
	env := containRunLinuxGuardEnv("966", "966", "/tmp/plk-launch")
	err := launchContainedAgent(context.Background(), env, []string{"claude"}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected unexpected launcher path rejection")
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("error = %v, want launcher path mismatch", err)
	}
}

func containRunLinuxGuardEnv(uid, gid, launchPath string) *probeEnv {
	return &probeEnv{
		agentUserName: testAgentUser,
		launchPath:    launchPath,
		lookupUser: func(name string) (*user.User, error) {
			return &user.User{
				Uid:      uid,
				Gid:      gid,
				Username: name,
				HomeDir:  "/home/" + name,
			}, nil
		},
	}
}
