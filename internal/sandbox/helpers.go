// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		// Fail closed: corrupted policy could widen access if we fall back
		// to defaults. Log the error and exit — the parent validated this
		// JSON before passing it, so corruption indicates a real problem.
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] FATAL: invalid policy JSON: %v\n", err)
		os.Exit(1)
	}

	// Ensure workspace is set even if the JSON didn't include it.
	if p.Workspace == "" {
		p.Workspace = workspace
	}
	return p
}

// encodePolicyJSON serializes a Policy to JSON for passing via env var.
func encodePolicyJSON(p *Policy) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}
	return string(data), nil
}
