// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Child-process entry points for sandbox-init mode. These functions run
// inside re-exec'd child processes and cannot be covered by Go's standard
// coverage tool (coverage.out is per-process). They are exercised by
// subprocess integration tests that verify kernel enforcement.
//
// Follow-up: add GOCOVERDIR/covdata subprocess coverage merging.

package sandbox

import (
	"fmt"
	"os"
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

	if workspace == "" || commandStr == "" {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] missing workspace or command env vars\n")
		os.Exit(1)
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

	// Build synthetic environment.
	sandboxDir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", os.Getpid())
	env, err := SyntheticEnv(sandboxDir, workspace, extraEnv)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] env setup: %v\n", err)
		os.Exit(1)
	}

	// Strict mode: mount private /dev/shm BEFORE Landlock so the
	// Landlock rule sees the mounted path, not the host's.
	if strict {
		if err := mountPrivateShm(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] private /dev/shm: %v\n", err)
			os.Exit(1) // fatal in strict mode
		}
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] /dev/shm: PRIVATE (strict)\n")
	}

	// Apply Landlock (filesystem restriction).
	// Add the per-sandbox temp dir to the policy so the child has a
	// scoped /tmp equivalent. Host /tmp is NOT in the default policy —
	// this prevents cross-sandbox data leakage via temp files.
	policy := resolvePolicy(workspace)
	policy.AllowRWDirs = append(policy.AllowRWDirs, sandboxDir)
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
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] network: ACTIVE (isolated namespace)\n")
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
		os.Exit(1)
	}

	// Clear sandbox env vars.
	for _, key := range []string{
		initEnvKey, "__PIPELOCK_SANDBOX_WORKSPACE", "__PIPELOCK_SANDBOX_COMMAND",
		"__PIPELOCK_SANDBOX_EXTRA_ENV", "__PIPELOCK_SANDBOX_POLICY",
		noNetNSEnvKey,
	} {
		env = removeEnvKey(env, key)
	}

	// Exec the real command (replaces this process).
	binary, err := lookPathIn(command[0], env)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command not found: %s (%v)\n", command[0], err)
		os.Exit(127)
	}

	if err := os.Chdir(workspace); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] chdir %s: %v\n", workspace, err)
		os.Exit(1)
	}

	err = syscall.Exec(binary, command, env) //nolint:gosec // G204: intentional exec of user-specified command
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] exec failed: %v\n", err)
	os.Exit(1)
}
