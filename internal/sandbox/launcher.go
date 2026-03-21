// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// LaunchConfig configures how the sandbox launcher forks the child process.
type LaunchConfig struct {
	// Ctx controls the child's lifetime. When cancelled, the child process
	// group is killed. If nil, context.Background() is used.
	Ctx context.Context

	// Command is the command and arguments to execute inside the sandbox.
	Command []string

	// Workspace is the resolved absolute workspace path.
	Workspace string

	// Policy overrides the default sandbox policy. If nil, DefaultPolicy(Workspace)
	// is used. This allows config to pass custom filesystem rules from the
	// sandbox.filesystem YAML section.
	Policy *Policy

	// Strict enables strict containment: error on missing layers,
	// private /dev/shm mount, clone3 blocked.
	Strict bool

	// ExtraEnv contains additional KEY=VALUE pairs to pass to the child.
	ExtraEnv []string

	// Stdin, Stdout, Stderr are connected to the child process.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// PrepareSandboxCmd builds an exec.Cmd configured to re-exec pipelock in
// sandbox-init mode with user + network namespace isolation. The returned
// cmd is NOT started — the caller can set up pipes (StdinPipe, StdoutPipe)
// before calling cmd.Start().
//
// For simple cases, use LaunchSandboxed which calls Start automatically.
func PrepareSandboxCmd(cfg LaunchConfig) (*exec.Cmd, error) {
	if runtime.GOOS != osLinux {
		return nil, fmt.Errorf("%w: sandbox requires Linux", ErrUnavailable)
	}

	if err := ValidateWorkspace(cfg.Workspace); err != nil {
		return nil, fmt.Errorf("workspace validation: %w", err)
	}

	// Validate policy doesn't re-authorize secret directories.
	policy := DefaultPolicy(cfg.Workspace)
	if cfg.Policy != nil {
		policy = *cfg.Policy
	}
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}

	// Re-exec ourselves as sandbox-init. Using /proc/self/exe ensures we
	// re-exec the exact same binary (not a PATH lookup that could be hijacked).
	selfExe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/self/exe: %w", err)
	}

	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, selfExe) //nolint:gosec // G204: re-exec of self for sandbox-init
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr

	// Encode command and extra env as unit-separator-delimited strings.
	cmd.Env = []string{
		initEnvKey + "=1",
		"__PIPELOCK_SANDBOX_WORKSPACE=" + cfg.Workspace,
		"__PIPELOCK_SANDBOX_COMMAND=" + strings.Join(cfg.Command, "\x1f"),
	}
	if cfg.Strict {
		cmd.Env = append(cmd.Env, strictEnvKey+"=1")
	}
	if len(cfg.ExtraEnv) > 0 {
		cmd.Env = append(cmd.Env, "__PIPELOCK_SANDBOX_EXTRA_ENV="+strings.Join(cfg.ExtraEnv, "\x1f"))
	}

	// Pass custom policy as JSON if provided. Otherwise child uses DefaultPolicy.
	if cfg.Policy != nil {
		policyJSON, jsonErr := encodePolicyJSON(cfg.Policy)
		if jsonErr != nil {
			return nil, fmt.Errorf("encoding sandbox policy: %w", jsonErr)
		}
		cmd.Env = append(cmd.Env, "__PIPELOCK_SANDBOX_POLICY="+policyJSON)
	}

	// Create child in new user + network namespace.
	// Strict mode adds CLONE_NEWNS (mount namespace) for private /dev/shm.
	cloneFlags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET)
	if cfg.Strict {
		cloneFlags |= syscall.CLONE_NEWNS
	}
	uid := os.Getuid()
	gid := os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		Pdeathsig: syscall.SIGTERM, // kill child if parent dies
		Setpgid:   true,            // own process group for cleanup
	}

	return cmd, nil
}

// LaunchSandboxed is a convenience wrapper that prepares and starts a
// sandboxed child process. Returns the started cmd (caller must call Wait).
func LaunchSandboxed(cfg LaunchConfig) (*exec.Cmd, error) {
	cmd, err := PrepareSandboxCmd(cfg)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting sandbox child: %w", err)
	}
	return cmd, nil
}

// CleanupChildSandboxDir removes the child's per-sandbox temp directory.
// Call after cmd.Wait() returns when the child PID is known.
func CleanupChildSandboxDir(childPID int) {
	dir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", childPID)
	_ = os.RemoveAll(dir)
}

// CleanupSandboxCmd removes the sandbox temp directory associated with a cmd.
// On Linux, delegates to CleanupChildSandboxDir using the process PID.
func CleanupSandboxCmd(cmd *exec.Cmd) {
	if cmd.Process != nil {
		CleanupChildSandboxDir(cmd.Process.Pid)
	}
}
