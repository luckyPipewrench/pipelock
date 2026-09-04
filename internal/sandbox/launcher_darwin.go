// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import (
	"context"
	"fmt"
	"io"
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

	// Strict is accepted for API compatibility with Linux but has no
	// additional effect on macOS. macOS sandbox-exec does not support
	// seccomp or mount namespace isolation.
	Strict bool

	// BestEffort is accepted for API compatibility with Linux but has
	// no effect on macOS (sandbox-exec doesn't use namespaces).
	BestEffort bool

	ExtraEnv                 []string
	BridgeSocketPath         string // Linux-only; ignored by sandbox-exec.
	BridgeIdleTimeoutSeconds int    // Linux-only; ignored by sandbox-exec.
	GateTargetStart          bool   // Linux-only; no UID/GID mappings on macOS.
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
}

// PreparedSandboxCmd records the parent hardening ordering for a sandbox
// command. macOS has no user-namespace map phase, so hardening stays eager.
type PreparedSandboxCmd struct {
	Cmd                       *exec.Cmd
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
		CleanupSandboxCmd(p.Cmd)
		return fmt.Errorf("starting sandbox child: %w", err)
	}
	return nil
}

// PrepareSandboxCmd builds an exec.Cmd that wraps the child command with
// sandbox-exec using a generated SBPL profile. No re-exec needed - the
// child is launched directly under the sandbox profile.
func PrepareSandboxCmd(cfg LaunchConfig) (*exec.Cmd, error) {
	if cfg.GateTargetStart {
		return nil, fmt.Errorf("sandbox target-start gate requires PrepareSandboxLaunch")
	}
	launch, err := PrepareSandboxLaunch(cfg)
	if err != nil {
		return nil, err
	}
	return launch.Cmd, nil
}

// PrepareSandboxLaunch builds a launch with its explicit parent-hardening
// ordering. macOS has no UID/GID mapping phase, so it is always eager.
func PrepareSandboxLaunch(cfg LaunchConfig) (*PreparedSandboxCmd, error) {
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
	env = append(env, sandboxRootEnvKey+"="+sandboxTmp)
	cmd.Env = env

	return &PreparedSandboxCmd{Cmd: cmd}, nil
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
func LaunchStandalone(cfg StandaloneLaunchConfig) error {
	if cfg.GuardDeclaration != nil {
		return fmt.Errorf("%w: Guard execution requires Linux", ErrUnavailable)
	}
	return fmt.Errorf("%w: standalone sandbox mode requires Linux (use MCP mode on macOS)", ErrUnavailable)
}

// sandboxRootEnvKey is the env var used to pass the sandbox temp root
// from PrepareSandboxCmd to CleanupSandboxCmd.
const sandboxRootEnvKey = "__PIPELOCK_SANDBOX_ROOT"

// CleanupChildSandboxDir is a no-op on macOS. Use CleanupSandboxCmd instead.
// macOS uses env-based temp paths, not PID-based.
func CleanupChildSandboxDir(_ int) {}

// CleanupSandboxCmd removes the sandbox temp directory by extracting the
// root path from the cmd's environment.
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
