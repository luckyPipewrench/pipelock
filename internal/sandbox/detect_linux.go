// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Capabilities reports what sandbox layers are available on this system.
type Capabilities struct {
	LandlockABI    int    // 0 = unavailable, 1-7 = ABI version
	UserNamespaces bool   // can create user namespaces (unprivileged)
	Seccomp        bool   // seccomp filter mode available
	MaxUserNS      int    // max_user_namespaces sysctl value
	SELinux        string // "enforcing", "permissive", "disabled", or ""
}

// Detect probes the current system for sandbox capability support.
func Detect() Capabilities {
	var c Capabilities

	// Landlock ABI version.
	if abi, err := llsys.LandlockGetABIVersion(); err == nil && abi > 0 {
		c.LandlockABI = abi
	}

	// User namespaces: try a quick unshare probe.
	c.UserNamespaces = probeUserNamespace()

	// Max user namespaces sysctl.
	if data, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if val, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			c.MaxUserNS = val
		}
	}

	// Seccomp: check /proc/self/status for Seccomp line.
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				// Value 0 = disabled, 1 = strict, 2 = filter
				// If the field exists at all, seccomp is supported.
				c.Seccomp = true
				break
			}
		}
	}

	// SELinux status.
	ctx := context.Background()
	if data, err := exec.CommandContext(ctx, "getenforce").Output(); err == nil {
		c.SELinux = strings.TrimSpace(strings.ToLower(string(data)))
	}

	return c
}

// probeUserNamespace attempts to create a user namespace via clone.
// Returns true if the kernel allows unprivileged user namespace creation.
func probeUserNamespace() bool {
	// Fork a child with CLONE_NEWUSER. If it succeeds, user namespaces work.
	// The child immediately exits.
	r, _, errno := syscall.RawSyscall6(
		syscall.SYS_CLONE,
		uintptr(syscall.CLONE_NEWUSER|syscall.SIGCHLD),
		0, 0, 0, 0, 0,
	)
	if errno != 0 {
		return false
	}
	if r == 0 {
		// Child: exit immediately.
		syscall.Exit(0)
	}
	// Parent: reap child.
	var ws syscall.WaitStatus
	_, _ = syscall.Wait4(int(r), &ws, 0, nil) //nolint:gosec // G115: clone returns pid which fits in int
	return true
}

// Summary returns a human-readable summary of available capabilities.
func (c Capabilities) Summary() string {
	var parts []string

	if c.LandlockABI > 0 {
		parts = append(parts, fmt.Sprintf("Landlock ABI v%d", c.LandlockABI))
	} else {
		parts = append(parts, "Landlock: unavailable")
	}

	if c.UserNamespaces {
		parts = append(parts, "user namespaces: available")
	} else {
		parts = append(parts, "user namespaces: unavailable")
	}

	if c.Seccomp {
		parts = append(parts, "seccomp: available")
	} else {
		parts = append(parts, "seccomp: unavailable")
	}

	return strings.Join(parts, ", ")
}
