// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func configureContainedCommand(cmd *exec.Cmd, agentUser string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("contained toy-agent execution requires root (euid=%d)", os.Geteuid())
	}
	if agentUser == "" {
		agentUser = defaultContainedAgentUser
	}
	u, err := user.Lookup(agentUser)
	if err != nil {
		return fmt.Errorf("lookup contained agent user %q: %w", agentUser, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("parse uid for %q: %w", agentUser, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("parse gid for %q: %w", agentUser, err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
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
