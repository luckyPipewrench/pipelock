// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package sandbox

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// LaunchConfig configures how the sandbox launcher forks the child process.
// On non-Linux platforms, all launcher functions return ErrUnavailable.
type LaunchConfig struct {
	Ctx        context.Context
	Command    []string
	Workspace  string
	Policy     *Policy
	Strict     bool
	BestEffort bool
	ExtraEnv   []string
	// BridgeSocketPath is Linux-only.
	BridgeSocketPath string
	// BridgeIdleTimeoutSeconds is Linux-only.
	BridgeIdleTimeoutSeconds int
	// GateTargetStart is Linux-only.
	GateTargetStart bool
	Stdin           io.Reader
	Stdout          io.Writer
	Stderr          io.Writer
}

// PreparedSandboxCmd exists for cross-platform callers. Unsupported platforms
// never produce one because PrepareSandboxLaunch returns ErrUnavailable.
type PreparedSandboxCmd struct {
	Cmd *exec.Cmd
	// ParentHardeningAfterStart is ignored outside Linux; hardening always
	// happens before Cmd.Start on these platforms.
	ParentHardeningAfterStart bool
}

func (p *PreparedSandboxCmd) Close() {}

func (p *PreparedSandboxCmd) StartWithParentHardening(harden func() error) error {
	if p == nil || p.Cmd == nil {
		return fmt.Errorf("sandbox launch is nil")
	}
	if harden == nil {
		return fmt.Errorf("sandbox parent hardening callback is nil")
	}
	if err := harden(); err != nil {
		return fmt.Errorf("hardening parent before sandbox start: %w", err)
	}
	if err := p.Cmd.Start(); err != nil {
		return fmt.Errorf("starting sandbox child: %w", err)
	}
	return nil
}

// PrepareSandboxCmd returns ErrUnavailable on non-Linux platforms.
func PrepareSandboxCmd(_ LaunchConfig) (*exec.Cmd, error) {
	return nil, fmt.Errorf("%w: requires linux", ErrUnavailable)
}

// PrepareSandboxLaunch returns ErrUnavailable on non-Linux platforms.
func PrepareSandboxLaunch(_ LaunchConfig) (*PreparedSandboxCmd, error) {
	return nil, fmt.Errorf("%w: requires linux", ErrUnavailable)
}

// LaunchSandboxed returns ErrUnavailable on non-Linux platforms.
func LaunchSandboxed(_ LaunchConfig) (*exec.Cmd, error) {
	return nil, fmt.Errorf("%w: requires linux", ErrUnavailable)
}

// LaunchStandalone returns ErrUnavailable on non-Linux platforms.
func LaunchStandalone(cfg StandaloneLaunchConfig) error {
	if cfg.GuardDeclaration != nil {
		return fmt.Errorf("%w: Guard execution requires Linux", ErrUnavailable)
	}
	return fmt.Errorf("%w: requires linux", ErrUnavailable)
}

// CleanupChildSandboxDir is a no-op on non-Linux/non-darwin platforms.
func CleanupChildSandboxDir(_ int) {}

// CleanupSandboxCmd is a no-op on non-Linux/non-darwin platforms.
func CleanupSandboxCmd(_ *exec.Cmd) {}
