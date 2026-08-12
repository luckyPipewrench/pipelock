// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Standalone sandbox child-process entry point. Runs inside a re-exec'd
// child with network namespace isolation. CI exercises it through an
// instrumented binary and merges its GOCOVERDIR output with parent coverage.

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/luckyPipewrench/pipelock/internal/config"
	guardruntime "github.com/luckyPipewrench/pipelock/internal/guard"
)

// RunStandaloneInit is the entry point for standalone sandbox-init mode.
// Unlike MCP's RunInit (which execs the command), this stays alive to run
// a bridge proxy that routes the agent's HTTP traffic through pipelock's
// scanner via a Unix domain socket.
func RunStandaloneInit() {
	workspace := os.Getenv("__PIPELOCK_SANDBOX_WORKSPACE")
	commandStr := os.Getenv("__PIPELOCK_SANDBOX_COMMAND")
	commandJSON := os.Getenv(standaloneCommandJSONEnv)
	socketPath := os.Getenv(sandboxSocketEnv)
	extraEnvStr := os.Getenv("__PIPELOCK_SANDBOX_EXTRA_ENV")
	developerEnvFDStr := os.Getenv(developerEnvironmentControlEnv)
	guardDeclarationRaw := os.Getenv(standaloneGuardDeclarationEnv)
	guardProfile := os.Getenv(standaloneGuardProfileEnv)
	guardPolicyHash := os.Getenv(standaloneGuardPolicyHashEnv)
	guardStatusFDStr := os.Getenv(guardStatusControlEnv)

	var guardDeclaration *config.Guard
	var guardStatus *os.File
	if guardDeclarationRaw != "" {
		guardDeclaration = &config.Guard{}
		if err := json.Unmarshal([]byte(guardDeclarationRaw), guardDeclaration); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] guard declaration: %v\n", err)
			exitSandboxProcess(1)
		}
		if guardPolicyHash == "" {
			_, _ = fmt.Fprintln(os.Stderr, "[sandbox] guard policy hash is missing")
			exitSandboxProcess(1)
		}
		fd, fdErr := strconv.Atoi(guardStatusFDStr)
		if fdErr != nil || fd < 3 {
			_, _ = fmt.Fprintln(os.Stderr, "[sandbox] guard status descriptor is invalid")
			exitSandboxProcess(1)
		}
		guardStatus = os.NewFile(uintptr(fd), "guard-status")
	}

	if workspace == "" || (commandJSON == "" && commandStr == "") || socketPath == "" {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] missing workspace, command, or socket path\n")
		exitSandboxProcess(1)
	}

	command, err := decodeStandaloneCommand(commandJSON, commandStr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command transport: %v\n", err)
		exitSandboxProcess(1)
	}
	var extraEnv []string
	if extraEnvStr != "" {
		extraEnv = strings.Split(extraEnvStr, "\x1f")
	}

	var developerEnvironment []string
	useDeveloperEnvironment := developerEnvFDStr != ""
	if useDeveloperEnvironment {
		fd, err := developerEnvironmentFDFromControl(developerEnvFDStr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] developer env transport: %v\n", err)
			exitSandboxProcess(1)
		}
		developerEnvironment, err = readDeveloperEnvironment(fd)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] developer env transport: %v\n", err)
			exitSandboxProcess(1)
		}
	}

	strict := IsStrictMode()

	// Initialize Go's signal thread before RLIMIT_NPROC is lowered. This keeps
	// process exhaustion on a shared UID in the controlled command-error path.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	sandboxDir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", os.Getpid())
	var env []string
	var binary string
	if useDeveloperEnvironment {
		// SyntheticEnv normally creates this directory before policy resolution.
		// The developer path preserves the caller environment instead, but the
		// Landlock policy still needs its private, non-secret scratch directory.
		if err := os.MkdirAll(sandboxDir, 0o700); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] developer scratch dir: %v\n", err)
			exitSandboxProcess(1)
		}
		if guardDeclaration != nil {
			binary, err = ResolveCommandInDir(command[0], developerEnvironment, workspace)
		} else {
			binary, err = lookPathIn(command[0], developerEnvironment)
		}
	} else {
		// Build synthetic environment.
		env, err = SyntheticEnv(sandboxDir, workspace, extraEnv)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] env setup: %v\n", err)
			exitSandboxProcess(1)
		}
		if guardDeclaration != nil {
			binary, err = ResolveCommandInDir(command[0], env, workspace)
		} else {
			binary, err = lookPathIn(command[0], env)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command not found: %s (%v)\n", command[0], err)
		exitSandboxProcess(127)
	}

	// Strict mode: mount private /dev/shm BEFORE Landlock.
	if strict {
		if err := mountPrivateShm(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] private /dev/shm: %v\n", err)
			exitSandboxProcess(1)
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

	// Set no_new_privs + seccomp (strict blocks clone3).
	if err := SetNoNewPrivs(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] no_new_privs: %v\n", err)
	}
	scStatus, scErr := ApplySeccomp(strict)
	reportLayer(os.Stderr, scStatus, scErr)

	// Network namespace status depends on whether parent created one.
	noNetNS := IsNoNetNS()
	if noNetNS {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] network: DEGRADED (no namespace, proxy-based routing only)\n")
		// Degraded mode enforces proxy routing via HTTP(S)_PROXY env only.
		// A child process that clears those env vars can open direct
		// outbound sockets and bypass pipelock entirely (round-4 of the pre-tag gate
		// finding, reconfirmed in a later round for the standalone sandbox
		// path that earlier prerelease builds missed). Kernel-enforced isolation requires
		// a user namespace (CLONE_NEWUSER) or the companion-proxy
		// topology generated by `pipelock init sidecar`.
		_, _ = fmt.Fprintf(os.Stderr,
			"[sandbox] WARNING: best-effort network mode relies on HTTP(S)_PROXY env; a child process that clears those can bypass pipelock. "+
				"For kernel-enforced isolation, run under a user namespace (CLONE_NEWUSER) or use the companion-proxy topology from `pipelock init sidecar`.\n")
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] network: ACTIVE (isolated namespace)\n")
		// Bring up loopback only in a new network namespace.
		// In best-effort mode without netns, loopback is already up.
		if err := bringUpLoopback(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] loopback: %v\n", err)
			exitSandboxProcess(1)
		}
	}

	// Start bridge proxy. In best-effort mode without netns, the bridge
	// still works - HTTP_PROXY routes cooperative agents through pipelock.
	// Network isolation is not kernel-enforced in this mode.
	//
	// Without a network namespace, the default port (8888) may conflict
	// with a pipelock sidecar already running in the same pod. Use port 0
	// (OS-assigned) to avoid the conflict - the agent gets the actual
	// address via HTTP_PROXY env var.
	var bridgeAddr string
	if noNetNS {
		bridgeAddr = "127.0.0.1:0" // dynamic port to avoid sidecar conflict
	}
	bridge, err := NewBridgeProxy(socketPath, bridgeAddr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] bridge proxy: %v\n", err)
		exitSandboxProcess(1)
	}

	bridgeErr := make(chan error, 1)
	go func() { bridgeErr <- bridge.Serve(ctx) }()
	defer bridge.Close()

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
	_, _ = fmt.Fprintf(os.Stderr, "[sandbox] bridge proxy: %s → %s\n", bridge.Addr(), socketPath)

	if useDeveloperEnvironment {
		env, err = DeveloperEnv(developerEnvironment, bridge.Addr())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] env setup: %v\n", err)
			exitSandboxProcess(1)
		}
		// The caller's environment may point PWD or TMPDIR outside the paths
		// granted to the final Guard process. Force both to the contained paths
		// so ordinary tools do not fail merely by honoring inherited metadata.
		env = forceEnvValue(env, "PWD", workspace)
		env = forceEnvValue(env, "TMPDIR", sandboxDir)
	} else {
		// Add HTTP_PROXY/HTTPS_PROXY to agent's environment.
		env = appendBridgeProxyEnv(env, bridge.Addr())
	}

	// Clean sandbox env vars.
	for _, key := range []string{
		standaloneInitEnv, initEnvKey,
		"__PIPELOCK_SANDBOX_WORKSPACE", "__PIPELOCK_SANDBOX_COMMAND",
		standaloneCommandJSONEnv,
		sandboxSocketEnv, "__PIPELOCK_SANDBOX_EXTRA_ENV",
		"__PIPELOCK_SANDBOX_POLICY", noNetNSEnvKey,
		developerEnvironmentControlEnv,
		standaloneGuardDeclarationEnv, standaloneGuardProfileEnv, standaloneGuardPolicyHashEnv,
		guardStatusControlEnv,
	} {
		env = removeEnvKey(env, key)
	}

	// Run the agent command as a subprocess. Guard adds one final self re-exec:
	// that helper applies the manifest to its calling thread and immediately
	// replaces itself with the operator command, leaving this bridge process
	// outside the workload filesystem restriction.
	var guardEnvironmentReader, guardEnvironmentWriter *os.File
	var guardEnvironmentPayload []byte
	if guardDeclaration != nil {
		selfExe, readErr := os.Readlink("/proc/self/exe")
		if readErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] guard helper path: %v\n", readErr)
			exitSandboxProcess(1)
		}
		guardEnvironmentPayload, readErr = json.Marshal(env)
		if readErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] guard environment: %v\n", readErr)
			exitSandboxProcess(1)
		}
		guardEnvironmentReader, guardEnvironmentWriter, readErr = os.Pipe()
		if readErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] guard environment pipe: %v\n", readErr)
			exitSandboxProcess(1)
		}
		controls, controlErr := guardruntime.ExecControlEnvironment(guardruntime.ExecControlOptions{
			Declaration: *guardDeclaration, Profile: guardProfile, PolicyHash: guardPolicyHash,
			Workspace: workspace, TempDir: sandboxDir, Binary: binary, EnvironmentFD: 3, StatusFD: 4,
		})
		if controlErr != nil {
			_ = guardEnvironmentReader.Close()
			_ = guardEnvironmentWriter.Close()
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] guard controls: %v\n", controlErr)
			exitSandboxProcess(1)
		}
		// The helper receives no developer-controlled loader or runtime hooks.
		// It reads the preserved environment as inert JSON over fd 3, applies
		// Guard, closes the pipe, and gives those values only to the final exec.
		env = append([]string{
			"PATH=/usr/bin:/bin",
			"PWD=" + workspace,
			"TMPDIR=" + sandboxDir,
		}, controls...)
		binary = selfExe
		command = append([]string{selfExe}, command...)
	}
	agentCmd := exec.CommandContext(ctx, binary, command[1:]...) //nolint:gosec // G204: user-specified agent command
	agentCmd.Stdin = os.Stdin
	agentCmd.Stdout = os.Stdout
	agentCmd.Stderr = os.Stderr
	agentCmd.Env = env
	agentCmd.Dir = workspace
	if guardEnvironmentReader != nil {
		agentCmd.ExtraFiles = []*os.File{guardEnvironmentReader, guardStatus}
	}

	if err := agentCmd.Start(); err != nil {
		if guardEnvironmentReader != nil {
			_ = guardEnvironmentReader.Close()
			_ = guardEnvironmentWriter.Close()
			_ = guardStatus.Close()
		}
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command error: %v\n", err)
		exitSandboxProcess(1)
	}
	if guardEnvironmentReader != nil {
		_ = guardEnvironmentReader.Close()
		_ = guardStatus.Close()
		written, writeErr := guardEnvironmentWriter.Write(guardEnvironmentPayload)
		if writeErr == nil && written != len(guardEnvironmentPayload) {
			writeErr = io.ErrShortWrite
		}
		closeErr := guardEnvironmentWriter.Close()
		if writeErr != nil || closeErr != nil {
			_ = agentCmd.Process.Kill()
			_ = agentCmd.Wait()
			_, _ = fmt.Fprintf(os.Stderr, "[sandbox] guard environment transport: %v\n", errors.Join(writeErr, closeErr))
			exitSandboxProcess(1)
		}
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agentCmd.Wait() }()

	agentErr, bridgeFailure := waitStandaloneAgentAndBridge(agentDone, bridgeErr, bridge.Close)
	if bridgeFailure != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] FATAL: bridge proxy: %v\n", bridgeFailure)
		// The parent observes this non-zero init exit and terminates the
		// standalone process group, including this agent and its descendants.
		exitSandboxProcess(1)
	}
	err = agentErr
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitSandboxProcess(exitErr.ExitCode())
		}
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] command error: %v\n", err)
		exitSandboxProcess(1)
	}
}

func decodeStandaloneCommand(encoded, legacy string) ([]string, error) {
	var command []string
	if encoded == "" {
		if legacy == "" {
			return nil, errors.New("missing command")
		}
		command = strings.Split(legacy, "\x1f")
	} else {
		if err := json.Unmarshal([]byte(encoded), &command); err != nil {
			return nil, fmt.Errorf("decoding command JSON: %w", err)
		}
	}
	if len(command) == 0 || command[0] == "" {
		return nil, errors.New("decoded command is empty")
	}
	for _, arg := range command {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("decoded command contains NUL")
		}
	}
	return command, nil
}

// waitStandaloneAgentAndBridge waits for the agent and its required bridge.
// When the agent exits first, it shuts the bridge down and consumes its
// terminal result before returning. This preserves a bridge failure that was
// already in progress instead of allowing a select race to turn it into a
// successful agent exit.
func waitStandaloneAgentAndBridge(agentDone, bridgeErr <-chan error, stopBridge func()) (agentErr, bridgeFailure error) {
	select {
	case bridgeFailure = <-bridgeErr:
		if bridgeFailure != nil {
			return nil, bridgeFailure
		}
		// A clean bridge return is only possible during cancellation or Close.
		// Wait for the command so its established exit behavior is preserved.
		return <-agentDone, nil
	case agentErr = <-agentDone:
		stopBridge()
		return agentErr, <-bridgeErr
	}
}
