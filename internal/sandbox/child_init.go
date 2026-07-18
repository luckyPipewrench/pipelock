// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Child-process entry points for sandbox-init mode. These functions run
// inside re-exec'd child processes. They are exercised by subprocess
// integration tests that verify kernel enforcement. CI uses an instrumented
// build and GOCOVERDIR to merge their coverage with the parent process.

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// RunInit is the entry point for the MCP sandbox-init child process.
// It applies all containment layers, then execs the real command.
// This function does not return on success (syscall.Exec replaces the process).
func RunInit() {
	workspace := os.Getenv("__PIPELOCK_SANDBOX_WORKSPACE")
	commandStr := os.Getenv("__PIPELOCK_SANDBOX_COMMAND")
	extraEnvStr := os.Getenv("__PIPELOCK_SANDBOX_EXTRA_ENV")
	socketPath := os.Getenv(sandboxSocketEnv)

	if workspace == "" || commandStr == "" {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] missing workspace or command env vars\n")
		exitSandboxProcess(1)
	}

	command := strings.Split(commandStr, "\x1f")
	var extraEnv []string
	if extraEnvStr != "" {
		extraEnv = strings.Split(extraEnvStr, "\x1f")
	}

	// FD safety: Go sets O_CLOEXEC on all FDs by default. The final
	// syscall.Exec() closes all CLOEXEC FDs, so the exec'd command
	// only inherits stdin/stdout/stderr. No manual FD closing needed.

	strict := IsStrictMode()

	var bridgeSignals chan os.Signal
	if socketPath != "" {
		// Initialize Go's signal thread before RLIMIT_NPROC is lowered. On a
		// shared UID that is already above the limit, doing this afterward can
		// crash the runtime instead of returning a controlled command error.
		bridgeSignals = make(chan os.Signal, 1)
		signal.Notify(bridgeSignals, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(bridgeSignals)
	}

	// Build synthetic environment.
	sandboxDir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", os.Getpid())
	env, err := SyntheticEnv(sandboxDir, workspace, extraEnv)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] env setup: %v\n", err)
		exitSandboxProcess(1)
	}

	// Strict mode: mount private /dev/shm BEFORE Landlock so the
	// Landlock rule sees the mounted path, not the host's.
	if strict {
		if err := mountPrivateShm(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] private /dev/shm: %v\n", err)
			exitSandboxProcess(1) // fatal in strict mode
		}
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] /dev/shm: PRIVATE (strict)\n")
	}

	// Apply Landlock (filesystem restriction).
	// Add the per-sandbox temp dir to the policy so the child has a
	// scoped /tmp equivalent. Host /tmp is NOT in the default policy -
	// this prevents cross-sandbox data leakage via temp files.
	policy := resolvePolicy(workspace)
	policy.AllowRWDirs = append(policy.AllowRWDirs, sandboxDir)
	if socketPath != "" {
		// Bridge mode grants RW to a fresh 0o700 per-invocation dir so the
		// child can connect to proxy.sock. The parent owns the bound socket
		// inode for this session and removes the whole dir on teardown.
		// A malicious child can create files in the dir, but the parent never
		// reopens proxy.sock after binding it, so replacement affects no future
		// parent listener and dies with the per-invocation directory.
		policy.AllowRWDirs = append(policy.AllowRWDirs, filepath.Dir(socketPath))
	}
	resolvedPolicy, err := ResolvePolicyPaths(policy)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] FATAL: resolve policy: %v\n", err)
		exitSandboxProcess(1)
	}
	if err := ValidatePolicy(resolvedPolicy); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] FATAL: validate policy: %v\n", err)
		exitSandboxProcess(1)
	}
	policy = resolvedPolicy
	llStatus, llErr := ApplyLandlock(policy)
	reportLayer(os.Stderr, llStatus, llErr)

	// Apply resource limits.
	if err := ApplyRlimits(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] rlimits: %v\n", err)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] rlimits: ACTIVE\n")
	}

	// Set no_new_privs (MUST come before seccomp).
	if err := SetNoNewPrivs(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] no_new_privs: %v\n", err)
	}

	// Apply seccomp filter (syscall restriction).
	// Strict mode blocks clone3 entirely (no namespace escape via BPF limitation).
	scStatus, scErr := ApplySeccomp(strict)
	reportLayer(os.Stderr, scStatus, scErr)

	// Report network namespace status (set at fork time by parent).
	noNetNS := IsNoNetNS()
	if noNetNS {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] network: DEGRADED (no namespace, best-effort mode)\n")
		// Containers without user namespaces (CAP_SYS_ADMIN / CLONE_NEWUSER
		// unavailable) cannot carve a private network namespace, so the
		// scanner's proxy routing is enforced ONLY by HTTP(S)_PROXY env
		// vars. A sandboxed process that unsets those env vars can open
		// direct outbound sockets and bypass pipelock entirely (the pre-tag gate
		// round-4 finding). This warning exists so operators running
		// best-effort deployments know the network layer is advisory,
		// not kernel-enforced, and can decide whether to alert on it.
		_, _ = fmt.Fprintf(os.Stderr,
			"[sandbox] WARNING: best-effort network mode relies on HTTP(S)_PROXY env; a child process that clears those can bypass pipelock. "+
				"For kernel-enforced isolation, run under a user namespace (CLONE_NEWUSER) or use the companion-proxy topology from `pipelock init sidecar`.\n")
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] network: ACTIVE (isolated namespace)\n")
		if socketPath != "" {
			// MCP stdio servers only need loopback when the bridge is wired.
			// Keeping it down otherwise preserves the empty-netns posture.
			if err := bringUpLoopback(); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "[sandbox] loopback: %v\n", err)
				exitSandboxProcess(1)
			}
		}
	}

	// Report summary.
	active := countActive(llStatus, scStatus)
	const totalLayers = 3
	if !noNetNS {
		active++ // count netns only when namespace isolation is active
	}
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] containment: %d/%d layers active\n", active, totalLayers)

	// Strict mode: fail-closed if any layer is inactive.
	if strict && active < totalLayers {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] FATAL: strict mode requires all %d layers active, got %d\n", totalLayers, active)
		exitSandboxProcess(1)
	}

	if socketPath != "" {
		runInitWithBridge(command, env, workspace, socketPath, bridgeSignals)
		return
	}

	// Clear sandbox env vars.
	for _, key := range []string{
		initEnvKey, "__PIPELOCK_SANDBOX_WORKSPACE", "__PIPELOCK_SANDBOX_COMMAND",
		"__PIPELOCK_SANDBOX_EXTRA_ENV", "__PIPELOCK_SANDBOX_POLICY",
		sandboxSocketEnv, noNetNSEnvKey,
	} {
		env = removeEnvKey(env, key)
	}

	// Exec the real command (replaces this process).
	binary, err := lookPathIn(command[0], env)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command not found: %s (%v)\n", command[0], err)
		exitSandboxProcess(127)
	}

	if err := os.Chdir(workspace); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] chdir %s: %v\n", workspace, err)
		exitSandboxProcess(1)
	}

	reportSubprocessCoverageError(flushSubprocessCoverage())
	err = syscall.Exec(binary, command, env) //nolint:gosec // G204: intentional exec of user-specified command
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] exec failed: %v\n", err)
	exitSandboxProcess(1)
}

func runInitWithBridge(command, env []string, workspace, socketPath string, sigCh <-chan os.Signal) {
	noNetNS := IsNoNetNS()
	bridgeAddr := ""
	if noNetNS {
		bridgeAddr = "127.0.0.1:0"
	}
	bridge, err := NewBridgeProxy(socketPath, bridgeAddr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] bridge proxy: %v\n", err)
		exitSandboxProcess(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go bridge.Serve(ctx)

	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] bridge proxy: %s → %s\n", bridge.Addr(), socketPath)

	env = appendBridgeProxyEnv(env, bridge.Addr())

	for _, key := range []string{
		initEnvKey, "__PIPELOCK_SANDBOX_WORKSPACE", "__PIPELOCK_SANDBOX_COMMAND",
		"__PIPELOCK_SANDBOX_EXTRA_ENV", "__PIPELOCK_SANDBOX_POLICY",
		sandboxSocketEnv, noNetNSEnvKey,
	} {
		env = removeEnvKey(env, key)
	}

	binary, err := lookPathIn(command[0], env)
	if err != nil {
		cancel()
		bridge.Close()
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command not found: %s (%v)\n", command[0], err)
		exitSandboxProcess(127)
	}

	childCmd := exec.CommandContext(context.Background(), binary, command[1:]...) //nolint:gosec // G204: user-specified MCP server command; signal lifecycle is handled explicitly below.
	childCmd.Stdin = os.Stdin
	childCmd.Stdout = os.Stdout
	childCmd.Stderr = os.Stderr
	childCmd.Env = env
	childCmd.Dir = workspace

	if err := childCmd.Start(); err != nil {
		cancel()
		bridge.Close()
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command error: %v\n", err)
		exitSandboxProcess(1)
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- childCmd.Wait()
	}()

	for {
		select {
		case sig := <-sigCh:
			if sig != nil && childCmd.Process != nil {
				_ = childCmd.Process.Signal(sig)
			}
		case err := <-waitCh:
			cancel()
			bridge.Close()
			exitBridgeChild(err)
			return
		}
	}
}

func exitBridgeChild(err error) {
	if err == nil {
		return
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			sig := status.Signal()
			terminateSelfWithSignal(sig)
		}
		exitSandboxProcess(exitErr.ExitCode())
	}
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command error: %v\n", err)
	exitSandboxProcess(1)
}

func appendBridgeProxyEnv(env []string, addr string) []string {
	env = removeProxyEnvKeys(env)
	// addr comes from BridgeProxy.Addr(), so it is a listener-backed host:port.
	proxyURL := "http://" + addr
	return append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
	)
}

func removeProxyEnvKeys(env []string) []string {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok && strings.HasSuffix(strings.ToUpper(key), "_PROXY") {
			continue
		}
		result = append(result, entry)
	}
	return result
}
