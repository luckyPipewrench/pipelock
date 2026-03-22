// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

// LaunchConfig configures how the sandbox launcher wraps the child process.
// On macOS, the child is launched via sandbox-exec with an SBPL profile.
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

// PrepareSandboxCmd builds an exec.Cmd that wraps the child command with
// sandbox-exec using a generated SBPL profile. No re-exec needed — the
// child is launched directly under the sandbox profile.
func PrepareSandboxCmd(cfg LaunchConfig) (*exec.Cmd, error) {
	if _, err := os.Stat(seatbeltBinary); err != nil {
		return nil, fmt.Errorf("%w: sandbox-exec not found at %s", ErrUnavailable, seatbeltBinary)
	}

	if err := ValidateWorkspace(cfg.Workspace); err != nil {
		return nil, fmt.Errorf("workspace validation: %w", err)
	}

	policy := DefaultPolicyDarwin(cfg.Workspace)
	if cfg.Policy != nil {
		policy = *cfg.Policy
	}
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}

	// Create a per-sandbox temp directory to prevent cross-sandbox leakage.
	// Matches the Linux model where global /tmp is excluded and each sandbox
	// gets its own temp dir.
	sandboxTmp, tmpErr := os.MkdirTemp("", "pipelock-sandbox-*")
	if tmpErr != nil {
		return nil, fmt.Errorf("creating sandbox temp dir: %w", tmpErr)
	}

	// cleanupTmp removes the sandbox temp dir on error paths.
	cleanupTmp := func() { _ = os.RemoveAll(sandboxTmp) }

	policy.AllowRWDirs = append(policy.AllowRWDirs, sandboxTmp)

	profile := GenerateSBPL(policy)

	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Build sandbox-exec command: sandbox-exec -p <profile> -- <command> <args...>
	args := make([]string, 0, 3+len(cfg.Command))
	args = append(args, "-p", profile, "--")
	args = append(args, cfg.Command...)

	cmd := exec.CommandContext(ctx, seatbeltBinary, args...) //nolint:gosec // G204: sandbox-exec is a fixed system binary
	cmd.Dir = cfg.Workspace
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr

	// Build child environment with per-sandbox temp dir.
	env, envErr := SyntheticEnv(sandboxTmp, cfg.Workspace, cfg.ExtraEnv)
	if envErr != nil {
		cleanupTmp()
		return nil, fmt.Errorf("building sandbox env: %w", envErr)
	}
	// Store sandbox root path in a hidden env var for cleanup after exit.
	// CleanupSandboxCmd extracts this to find and remove the temp dir.
	env = append(env, "__PIPELOCK_SANDBOX_ROOT="+sandboxTmp)
	cmd.Env = env

	return cmd, nil
}

// LaunchSandboxed prepares and starts a sandboxed child process.
// Returns the started cmd (caller must call Wait).
func LaunchSandboxed(cfg LaunchConfig) (*exec.Cmd, error) {
	cmd, err := PrepareSandboxCmd(cfg)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		CleanupSandboxCmd(cmd)
		return nil, fmt.Errorf("starting sandbox child: %w", err)
	}
	return cmd, nil
}

// LaunchStandalone returns ErrUnavailable on macOS.
// Standalone mode (veth routing) requires Linux network namespaces.
// MCP mode (stdio) works on macOS via PrepareSandboxCmd.
func LaunchStandalone(_ StandaloneLaunchConfig) error {
	return fmt.Errorf("%w: standalone sandbox mode requires Linux (use MCP mode on macOS)", ErrUnavailable)
}

// sandboxRootEnvKey is the env var used to pass the sandbox temp root
// from PrepareSandboxCmd to CleanupChildSandboxDir.
const sandboxRootEnvKey = "__PIPELOCK_SANDBOX_ROOT"

// CleanupChildSandboxDir removes the sandbox temp directory on macOS.
// Ignores the PID (Linux uses PID-based paths, macOS uses env-based paths).
// Use CleanupSandboxCmd for cmd-aware cleanup.
func CleanupChildSandboxDir(_ int) {}

// CleanupSandboxCmd removes the sandbox temp directory by extracting the
// root path from the cmd's environment. Works for both the MCP path
// (PrepareSandboxCmd) and the convenience path (LaunchSandboxed).
func CleanupSandboxCmd(cmd *exec.Cmd) {
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, sandboxRootEnvKey+"=") {
			dir := strings.TrimPrefix(e, sandboxRootEnvKey+"=")
			if dir != "" {
				_ = os.RemoveAll(dir)
			}
			return
		}
	}
}
