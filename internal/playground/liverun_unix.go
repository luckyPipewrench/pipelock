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
