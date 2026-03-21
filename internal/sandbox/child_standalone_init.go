// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Standalone sandbox child-process entry point. Runs inside a re-exec'd
// child with network namespace isolation. Cannot be covered by Go's
// standard coverage tool (runs in a separate process).
//
// Follow-up: add GOCOVERDIR/covdata subprocess coverage merging.

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

// RunStandaloneInit is the entry point for standalone sandbox-init mode.
// Unlike MCP's RunInit (which execs the command), this stays alive to run
// a bridge proxy that routes the agent's HTTP traffic through pipelock's
// scanner via a Unix domain socket.
func RunStandaloneInit() {
	workspace := os.Getenv("__PIPELOCK_SANDBOX_WORKSPACE")
	commandStr := os.Getenv("__PIPELOCK_SANDBOX_COMMAND")
	socketPath := os.Getenv("__PIPELOCK_SANDBOX_SOCKET")
	extraEnvStr := os.Getenv("__PIPELOCK_SANDBOX_EXTRA_ENV")

	if workspace == "" || commandStr == "" || socketPath == "" {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] missing workspace, command, or socket path\n")
		os.Exit(1)
	}

	command := strings.Split(commandStr, "\x1f")
	var extraEnv []string
	if extraEnvStr != "" {
		extraEnv = strings.Split(extraEnvStr, "\x1f")
	}

	strict := IsStrictMode()

	// Build synthetic environment.
	sandboxDir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", os.Getpid())
	env, err := SyntheticEnv(sandboxDir, workspace, extraEnv)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] env setup: %v\n", err)
		os.Exit(1)
	}

	// Strict mode: mount private /dev/shm BEFORE Landlock.
	if strict {
		if err := mountPrivateShm(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] private /dev/shm: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] /dev/shm: PRIVATE (strict)\n")
	}

	// Apply Landlock.
	// Add per-sandbox temp dir and the parent's socket dir to the policy.
	// Host /tmp is NOT in the default policy to prevent cross-sandbox leakage.
	policy := resolvePolicy(workspace)
	policy.AllowRWDirs = append(policy.AllowRWDirs, sandboxDir)
	// The socket's parent dir must be accessible for the bridge proxy.
	if socketPath != "" {
		policy.AllowRWDirs = append(policy.AllowRWDirs, filepath.Dir(socketPath))
	}
	llStatus, llErr := ApplyLandlock(policy)
	reportLayer(os.Stderr, llStatus, llErr)

	// Apply resource limits.
	if err := ApplyRlimits(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] rlimits: %v\n", err)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] rlimits: ACTIVE\n")
	}

	// Set no_new_privs + seccomp (strict blocks clone3).
	if err := SetNoNewPrivs(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] no_new_privs: %v\n", err)
	}
	scStatus, scErr := ApplySeccomp(strict)
	reportLayer(os.Stderr, scStatus, scErr)

	// Network namespace is active (set at fork time).
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] network: ACTIVE (isolated namespace)\n")

	// Bring up loopback for the bridge proxy.
	if err := bringUpLoopback(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] loopback: %v\n", err)
		os.Exit(1)
	}

	// Start bridge proxy.
	bridge, err := NewBridgeProxy(socketPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] bridge proxy: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	go bridge.Serve(ctx)
	defer bridge.Close()

	// Report summary.
	active := countActive(llStatus, scStatus)
	active++ // network namespace
	const totalLayers = 3
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] containment: %d/%d layers active\n", active, totalLayers)

	// Strict mode: fail-closed if any layer is inactive.
	if strict && active < totalLayers {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] FATAL: strict mode requires all %d layers active, got %d\n", totalLayers, active)
		os.Exit(1)
	}
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] bridge proxy: %s → %s\n", bridge.Addr(), socketPath)

	// Add HTTP_PROXY/HTTPS_PROXY to agent's environment.
	proxyURL := "http://" + bridge.Addr()
	env = append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
	)

	// Clean sandbox env vars.
	for _, key := range []string{
		standaloneInitEnv, initEnvKey,
		"__PIPELOCK_SANDBOX_WORKSPACE", "__PIPELOCK_SANDBOX_COMMAND",
		"__PIPELOCK_SANDBOX_SOCKET", "__PIPELOCK_SANDBOX_EXTRA_ENV",
		"__PIPELOCK_SANDBOX_POLICY",
	} {
		env = removeEnvKey(env, key)
	}

	// Run the agent command as a subprocess.
	binary, err := lookPathIn(command[0], env)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command not found: %s (%v)\n", command[0], err)
		os.Exit(127)
	}

	agentCmd := exec.CommandContext(ctx, binary, command[1:]...) //nolint:gosec // G204: user-specified agent command
	agentCmd.Stdin = os.Stdin
	agentCmd.Stdout = os.Stdout
	agentCmd.Stderr = os.Stderr
	agentCmd.Env = env
	agentCmd.Dir = workspace

	if err := agentCmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command error: %v\n", err)
		os.Exit(1)
	}
}
