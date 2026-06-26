// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !js

package playground

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

type containedAgentIDs struct {
	uid32 uint32
	gid32 uint32
	uid   int
	gid   int
}

func resolveContainedAgent(agentUser string) (containedAgentIDs, error) {
	if os.Geteuid() != 0 {
		return containedAgentIDs{}, fmt.Errorf("contained toy-agent execution requires root (euid=%d)", os.Geteuid())
	}
	if agentUser == "" {
		agentUser = defaultContainedAgentUser
	}
	u, err := user.Lookup(agentUser)
	if err != nil {
		return containedAgentIDs{}, fmt.Errorf("lookup contained agent user %q: %w", agentUser, err)
	}
	uid32, uid, err := parseContainedAgentID(agentUser, "uid", u.Uid)
	if err != nil {
		return containedAgentIDs{}, err
	}
	gid32, gid, err := parseContainedAgentID(agentUser, "gid", u.Gid)
	if err != nil {
		return containedAgentIDs{}, err
	}
	return containedAgentIDs{uid32: uid32, gid32: gid32, uid: uid, gid: gid}, nil
}

func parseContainedAgentID(agentUser, label, raw string) (uint32, int, error) {
	id32, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse %s for %q: %w", label, agentUser, err)
	}
	id, err := strconv.Atoi(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("parse %s for %q: value %s overflows int: %w", label, agentUser, raw, err)
	}
	return uint32(id32), id, nil
}

func configureContainedCommand(cmd *exec.Cmd, agentUser string) error {
	ids, err := resolveContainedAgent(agentUser)
	if err != nil {
		return err
	}
	configureContainedCommandID(cmd, ids)
	return nil
}

func configureContainedCommandID(cmd *exec.Cmd, ids containedAgentIDs) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: ids.uid32, Gid: ids.gid32},
	}
}

// applyAgentContainment runs the LLM agent subprocess as the contained agent
// user (so the kernel owner-match drops its direct egress, including run_command
// children) and hands ownership of the per-session scratch tree to that user so
// the agent can read the seeded credentials, cd into the scratch, and write
// there. It is fail-closed: it returns an error if it cannot establish
// containment (not root, unknown user, chown failure), so a session that claims
// to be contained never silently launches an UNcontained agent. cmd's
// SysProcAttr must be set before Start, which is why the caller invokes this
// before spawning the subprocess.
func applyAgentContainment(cmd *exec.Cmd, scratchDir, agentUser string) error {
	ids, err := resolveContainedAgent(agentUser)
	if err != nil {
		return err
	}
	configureContainedCommandID(cmd, ids)
	return chownTreeToAgentID(scratchDir, ids)
}

// chownTreeToAgent hands the server-seeded scratch paths to the contained agent
// user so the agent (running as that uid) can traverse the scratch, read the
// seeded credentials, and write there. It chowns the exact paths the server
// created (the scratch dir, the .aws dir, the credentials file) rather than
// walking the tree: at call time only the server's seed exists (the agent has
// not started), and chowning known paths with Lchown avoids any symlink-follow.
// Files the agent later creates are already owned by it (the process runs as the
// agent uid). Requires root, established by the caller via
// configureContainedCommand (which checks euid==0 first). Empty dir is a no-op.
func chownTreeToAgent(dir, agentUser string) error {
	if dir == "" {
		return nil
	}
	ids, err := resolveContainedAgent(agentUser)
	if err != nil {
		return err
	}
	return chownTreeToAgentID(dir, ids)
}

func chownTreeToAgentID(dir string, ids containedAgentIDs) error {
	if dir == "" {
		return nil
	}
	clean := filepath.Clean(dir)
	paths := []string{
		clean,
		filepath.Join(clean, ".aws"),
		filepath.Join(clean, ".aws", "credentials"),
	}
	for _, p := range paths {
		if _, statErr := os.Lstat(p); statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			return fmt.Errorf("stat %q: %w", p, statErr)
		}
		if err := os.Lchown(p, ids.uid, ids.gid); err != nil {
			return fmt.Errorf("chown %q to agent: %w", p, err)
		}
	}
	return nil
}

// containedAgentUserName returns the contained agent username, defaulting to
// pipelock-agent. Used to record the probe identity in the witness.
func containedAgentUserName(agentUser string) string {
	if agentUser == "" {
		return defaultContainedAgentUser
	}
	return agentUser
}

// containedAgentUID resolves the contained agent user's numeric uid for the
// witness record. Best-effort: returns -1 if the user cannot be resolved (the
// privileged probe path resolves and validates the user separately).
func containedAgentUID(agentUser string) int {
	u, err := user.Lookup(containedAgentUserName(agentUser))
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}
