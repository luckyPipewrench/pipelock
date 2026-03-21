// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// initEnvKey is the environment variable that signals the process is in
// sandbox-init mode. The re-exec launcher sets this before forking.
const initEnvKey = "__PIPELOCK_SANDBOX_INIT"

// IsInitMode returns true if the current process was re-exec'd as a
// sandbox-init child. Call this early in main() to enter sandbox-init
// before any other initialization.
func IsInitMode() bool {
	return os.Getenv(initEnvKey) == "1"
}

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
	if runtime.GOOS != "linux" {
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
	uid := os.Getuid()
	gid := os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
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

// reportLayer prints a sandbox layer status line to stderr.
func reportLayer(w io.Writer, status LayerStatus, err error) {
	if status.Active {
		if status.Version > 0 {
			_, _ = fmt.Fprintf(w, "[sandbox] %s: ACTIVE (v%d)\n", status.Name, status.Version)
		} else {
			_, _ = fmt.Fprintf(w, "[sandbox] %s: ACTIVE\n", status.Name)
		}
	} else {
		reason := status.Reason
		if reason == "" && err != nil {
			reason = err.Error()
		}
		_, _ = fmt.Fprintf(w, "[sandbox] %s: UNAVAILABLE (%s)\n", status.Name, reason)
	}
}

// countActive counts how many of the given layer statuses are active.
func countActive(layers ...LayerStatus) int {
	n := 0
	for _, l := range layers {
		if l.Active {
			n++
		}
	}
	return n
}

// removeEnvKey removes all entries with the given key from an env slice.
func removeEnvKey(env []string, key string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			result = append(result, e)
		}
	}
	return result
}

// lookPathIn resolves a command name to an absolute path using the PATH
// from the given environment slice (not os.Getenv).
func lookPathIn(name string, env []string) (string, error) {
	// If the name contains a slash, it's already a path.
	if strings.Contains(name, "/") {
		return filepath.Clean(name), nil
	}

	// Find PATH in the env slice.
	pathVal := "/usr/local/bin:/usr/bin:/bin" // fallback
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			pathVal = e[5:]
			break
		}
	}

	for _, dir := range filepath.SplitList(pathVal) {
		candidate := filepath.Join(dir, name)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%w: %s not found in PATH", exec.ErrNotFound, name)
}

// resolvePolicy builds the Landlock policy for the sandbox-init child.
// If a custom policy was passed via env JSON, it is used. Otherwise,
// DefaultPolicy(workspace) provides sensible defaults.
func resolvePolicy(workspace string) Policy {
	policyJSON := os.Getenv("__PIPELOCK_SANDBOX_POLICY")
	if policyJSON == "" {
		return DefaultPolicy(workspace)
	}

	var p Policy
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] invalid policy JSON, using defaults: %v\n", err)
		return DefaultPolicy(workspace)
	}

	// Ensure workspace is set even if the JSON didn't include it.
	if p.Workspace == "" {
		p.Workspace = workspace
	}
	return p
}

// CleanupChildSandboxDir removes the child's per-sandbox temp directory.
// Call after cmd.Wait() returns when the child PID is known.
func CleanupChildSandboxDir(childPID int) {
	dir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", childPID)
	_ = os.RemoveAll(dir)
}

// encodePolicyJSON serializes a Policy to JSON for passing via env var.
func encodePolicyJSON(p *Policy) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}
	return string(data), nil
}
