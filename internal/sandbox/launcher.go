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
	"strconv"
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

	// BestEffort skips namespace isolation when unavailable (e.g. inside
	// containers where CLONE_NEWUSER is blocked by seccomp). Landlock and
	// seccomp are still applied. Mutually exclusive with Strict.
	BestEffort bool

	// ExtraEnv contains additional KEY=VALUE pairs to pass to the child.
	ExtraEnv []string

	// BridgeSocketPath enables namespace-to-proxy bridge mode. When set,
	// sandbox-init keeps a child-side loopback proxy alive, injects
	// HTTP(S)_PROXY for the wrapped command, and forwards those connections
	// to this parent Unix socket path.
	BridgeSocketPath string

	// GateTargetStart blocks sandbox-init before it starts or execs Command
	// when this launch uses UID/GID mappings. The parent must start the
	// returned PreparedSandboxCmd through StartWithParentHardening so the
	// target cannot run until the parent hardens itself after mapping setup.
	// Launches without mappings deliberately do not get this gate: they retain
	// eager, pre-spawn parent hardening.
	GateTargetStart bool

	// Stdin, Stdout, Stderr are connected to the child process.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// PreparedSandboxCmd is a sandbox command together with its explicit launch
// ordering contract. ParentHardeningAfterStart is true only when Go must write
// UID/GID mappings before the parent becomes non-dumpable.
//
// Call StartWithParentHardening instead of Cmd.Start. It owns both safe
// orderings: eager hardening for no-map launches and gated post-map hardening
// for launches that use UID/GID mappings.
type PreparedSandboxCmd struct {
	Cmd                       *exec.Cmd
	ParentHardeningAfterStart bool

	readinessReader *os.File
	readinessWriter *os.File
}

// Close releases unstarted readiness-pipe descriptors. It is safe to call
// after StartWithParentHardening; successful launches close both ends there.
func (p *PreparedSandboxCmd) Close() {
	if p == nil {
		return
	}
	if p.readinessReader != nil {
		_ = p.readinessReader.Close()
		p.readinessReader = nil
	}
	if p.readinessWriter != nil {
		_ = p.readinessWriter.Close()
		p.readinessWriter = nil
	}
}

// StartWithParentHardening starts the sandbox child in the ordering selected
// by PrepareSandboxLaunch. Full namespace launches keep the parent dumpable
// until Go has written UID/GID mappings, then harden and release sandbox-init.
// All other launches harden before the first child starts.
//
// Any post-start failure closes the readiness pipe, kills the child, waits for
// it, and removes the child sandbox directory. No blocked child is left behind.
func (p *PreparedSandboxCmd) StartWithParentHardening(harden func() error) error {
	if p == nil || p.Cmd == nil {
		return fmt.Errorf("sandbox launch is nil")
	}
	if harden == nil {
		return fmt.Errorf("sandbox parent hardening callback is nil")
	}

	if !p.ParentHardeningAfterStart {
		if err := harden(); err != nil {
			return fmt.Errorf("hardening parent before sandbox start: %w", err)
		}
		if err := recordParentHardeningForTest(); err != nil {
			return fmt.Errorf("recording parent hardening: %w", err)
		}
		if err := p.Cmd.Start(); err != nil {
			p.Close()
			return fmt.Errorf("starting sandbox child: %w", err)
		}
		p.closeReadinessReader()
		return nil
	}

	if err := p.Cmd.Start(); err != nil {
		p.Close()
		return fmt.Errorf("starting mapped sandbox child: %w", err)
	}
	p.closeReadinessReader()

	if err := harden(); err != nil {
		p.abortStartedChild()
		return fmt.Errorf("hardening parent after sandbox mapping: %w", err)
	}
	if err := recordParentHardeningForTest(); err != nil {
		p.abortStartedChild()
		return fmt.Errorf("recording parent hardening: %w", err)
	}
	if err := p.releaseTargetStart(); err != nil {
		p.abortStartedChild()
		return fmt.Errorf("releasing sandbox target after parent hardening: %w", err)
	}
	return nil
}

func (p *PreparedSandboxCmd) closeReadinessReader() {
	if p.readinessReader != nil {
		_ = p.readinessReader.Close()
		p.readinessReader = nil
	}
}

func (p *PreparedSandboxCmd) releaseTargetStart() error {
	if p.readinessWriter == nil {
		return fmt.Errorf("sandbox readiness writer is unavailable")
	}
	n, err := p.readinessWriter.Write([]byte{1})
	if err == nil && n != 1 {
		err = io.ErrShortWrite
	}
	if closeErr := p.readinessWriter.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	p.readinessWriter = nil
	return err
}

func (p *PreparedSandboxCmd) abortStartedChild() {
	p.Close()
	if p.Cmd.Process != nil {
		_ = p.Cmd.Process.Kill()
		_ = p.Cmd.Wait()
	}
	CleanupSandboxCmd(p.Cmd)
}

// PrepareSandboxCmd builds an exec.Cmd configured to re-exec pipelock in
// sandbox-init mode with user + network namespace isolation. The returned
// cmd is NOT started - the caller can set up pipes (StdinPipe, StdoutPipe)
// before calling cmd.Start().
//
// When BestEffort is true and user namespaces are unavailable (e.g. inside
// containers), the child is launched without namespace isolation. Landlock
// and seccomp containment are still applied.
//
// For simple cases, use LaunchSandboxed which calls Start automatically.
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

// PrepareSandboxLaunch builds a sandbox command and records which parent
// hardening ordering applies. A readiness pipe is installed only when both the
// caller requested it and this launch uses user-namespace UID/GID mappings.
func PrepareSandboxLaunch(cfg LaunchConfig) (*PreparedSandboxCmd, error) {
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
	policy, coverageEnv := prepareSubprocessCoverage(policy, nil)
	policy, err := ResolvePolicyPaths(policy)
	if err != nil {
		return nil, fmt.Errorf("resolve policy paths: %w", err)
	}
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}

	// Strict and BestEffort are mutually exclusive - catch misuse by callers.
	if cfg.Strict && cfg.BestEffort {
		return nil, fmt.Errorf("sandbox: strict and best_effort are mutually exclusive")
	}

	// Probe namespace support before setting clone flags.
	// Only CLONE_NEWUSER is probed because CLONE_NEWNET requires CLONE_NEWUSER
	// on unprivileged processes - if user namespaces work, network namespaces
	// will too (created inside the user namespace with CAP_SYS_ADMIN).
	hasNamespaces := probeUserNamespace()
	if !hasNamespaces && !cfg.BestEffort {
		return nil, fmt.Errorf("%w: user namespaces unavailable (blocked by seccomp or sysctl? enable best_effort for degraded mode)", ErrUnavailable)
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
	cmd.Env = append(cmd.Env, coverageEnv...)
	if cfg.BridgeSocketPath != "" {
		cmd.Env = append(cmd.Env, sandboxSocketEnv+"="+cfg.BridgeSocketPath)
	}
	if cfg.Strict {
		cmd.Env = append(cmd.Env, strictEnvKey+"=1")
	}
	if len(cfg.ExtraEnv) > 0 {
		cmd.Env = append(cmd.Env, "__PIPELOCK_SANDBOX_EXTRA_ENV="+strings.Join(cfg.ExtraEnv, "\x1f"))
	}

	policyJSON, jsonErr := encodePolicyJSON(&policy)
	if jsonErr != nil {
		return nil, fmt.Errorf("encoding sandbox policy: %w", jsonErr)
	}
	cmd.Env = append(cmd.Env, "__PIPELOCK_SANDBOX_POLICY="+policyJSON)

	usesUserNamespaceMappings := hasNamespaces
	if usesUserNamespaceMappings {
		// Full isolation: user + network namespace.
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
	} else {
		// Best-effort: no namespace isolation. Child still gets Landlock + seccomp.
		cmd.Env = append(cmd.Env, noNetNSEnvKey+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGTERM,
			Setpgid:   true,
		}
	}

	launch := &PreparedSandboxCmd{
		Cmd:                       cmd,
		ParentHardeningAfterStart: cfg.GateTargetStart && usesUserNamespaceMappings,
	}
	if launch.ParentHardeningAfterStart {
		reader, writer, pipeErr := os.Pipe()
		if pipeErr != nil {
			return nil, fmt.Errorf("creating sandbox readiness pipe: %w", pipeErr)
		}
		launch.readinessReader = reader
		launch.readinessWriter = writer
		cmd.ExtraFiles = append(cmd.ExtraFiles, reader)
		fd := 3 + len(cmd.ExtraFiles) - 1
		cmd.Env = append(cmd.Env, sandboxReadinessFDEnv+"="+strconv.Itoa(fd))
	}

	return launch, nil
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
// Cross-platform: on Linux delegates to CleanupChildSandboxDir via PID.
func CleanupSandboxCmd(cmd *exec.Cmd) {
	if cmd.Process != nil {
		CleanupChildSandboxDir(cmd.Process.Pid)
	}
}
