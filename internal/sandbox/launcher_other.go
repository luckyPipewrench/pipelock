// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux || darwin)

package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
)

// LaunchConfig configures how the sandbox launcher forks the child process.
// On non-Linux platforms, all launcher functions return ErrUnavailable.
type LaunchConfig struct {
	Ctx       context.Context
	Command   []string
	Workspace string
	Policy    *Policy
	ExtraEnv  []string
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
}

// StandaloneLaunchConfig configures the standalone sandbox launcher.
type StandaloneLaunchConfig struct {
	Ctx          context.Context
	Command      []string
	Workspace    string
	Policy       *Policy
	ExtraEnv     []string
	ProxyHandler func(conn net.Conn)
}

// PrepareSandboxCmd returns ErrUnavailable on non-Linux platforms.
func PrepareSandboxCmd(_ LaunchConfig) (*exec.Cmd, error) {
	return nil, fmt.Errorf("%w: requires linux", ErrUnavailable)
}

// LaunchSandboxed returns ErrUnavailable on non-Linux platforms.
func LaunchSandboxed(_ LaunchConfig) (*exec.Cmd, error) {
	return nil, fmt.Errorf("%w: requires linux", ErrUnavailable)
}

// LaunchStandalone returns ErrUnavailable on non-Linux platforms.
func LaunchStandalone(_ StandaloneLaunchConfig) error {
	return fmt.Errorf("%w: requires linux", ErrUnavailable)
}

// CleanupChildSandboxDir is a no-op on unsupported platforms.
func CleanupChildSandboxDir(_ int) {}

// CleanupSandboxCmd is a no-op on unsupported platforms.
func CleanupSandboxCmd(_ *exec.Cmd) {}
