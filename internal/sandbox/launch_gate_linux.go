// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"os/exec"
	"syscall"
)

// CmdNeedsHardeningGate reports whether cmd carries a UID/GID map phase and so
// must be started through PreparedSandboxCmd.StartWithParentHardening rather
// than by calling Start on it directly.
//
// A mapped launch cannot be hardened before Start: the parent has to stay
// dumpable long enough to write the child's map, because a non-dumpable
// process's /proc/<pid>/uid_map is root-owned. A caller that starts a mapped
// command itself therefore gets neither the map ordering nor the hardening, and
// gets them missing silently. This predicate exists so the legacy plain-command
// entry point can refuse that command instead of running it ungated.
func CmdNeedsHardeningGate(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.SysProcAttr == nil {
		return false
	}
	return len(cmd.SysProcAttr.UidMappings) > 0 ||
		len(cmd.SysProcAttr.GidMappings) > 0 ||
		cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWUSER != 0
}
