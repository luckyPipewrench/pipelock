// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

// strictEnvKey signals the child that strict mode is active.
const strictEnvKey = "__PIPELOCK_SANDBOX_STRICT"

// noNetNSEnvKey signals the child that network namespace was NOT created
// (best-effort mode where CLONE_NEWUSER is blocked, e.g. inside containers).
const noNetNSEnvKey = "__PIPELOCK_SANDBOX_NO_NETNS"

// sandboxReadinessFDEnv names the inherited read end of the parent-controlled
// gate. sandbox-init consumes one byte before it can exec or start its target.
const sandboxReadinessFDEnv = "__PIPELOCK_SANDBOX_READINESS_FD"

type AppliedLaunchOutcome string

const (
	LaunchOutcomeFull                    AppliedLaunchOutcome = "full"
	LaunchOutcomePartial                 AppliedLaunchOutcome = "partial"
	LaunchOutcomeAdvisoryOverride        AppliedLaunchOutcome = "advisory_override"
	LaunchOutcomeAdvisoryOverridePartial AppliedLaunchOutcome = "advisory_override_partial"
	LaunchOutcomeRefused                 AppliedLaunchOutcome = "refused"
)

// IsStrictMode returns true if the child process should enforce strict
// sandbox containment (error on missing layers, private /dev/shm, etc.).
func IsStrictMode() bool {
	return os.Getenv(strictEnvKey) == "1"
}

// IsNoNetNS returns true if the child was launched without network namespace
// isolation (best-effort fallback when CLONE_NEWUSER is unavailable).
func IsNoNetNS() bool {
	return os.Getenv(noNetNSEnvKey) == "1"
}

// waitForParentHardening establishes the target-start happens-after relation
// for mapped launches. EOF and malformed descriptors deny startup because the
// parent did not prove that it hardened before releasing this child.
func waitForParentHardening() error {
	rawFD := os.Getenv(sandboxReadinessFDEnv)
	if rawFD == "" {
		return nil
	}
	fd, err := strconv.Atoi(rawFD)
	if err != nil || fd < 0 {
		return fmt.Errorf("invalid readiness descriptor %q", rawFD)
	}
	ready := os.NewFile(uintptr(fd), "sandbox-readiness")
	if ready == nil {
		return fmt.Errorf("opening readiness descriptor %d", fd)
	}
	defer func() { _ = ready.Close() }()
	var token [1]byte
	readResult := make(chan error, 1)
	go func() {
		_, readErr := io.ReadFull(ready, token[:])
		readResult <- readErr
	}()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case err := <-readResult:
		if err == nil {
			return nil
		}
		return fmt.Errorf("waiting for parent hardening: %w", err)
	case <-timer.C:
		_ = ready.Close()
		<-readResult
		return errors.New("waiting for parent hardening: timed out")
	}
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

// appliedLaunchOutcome classifies only layers the child actually applied.
// Capability probes are deliberately excluded: they cannot prove the launch.
func appliedLaunchOutcome(strict, noNetNS, seccompSupported bool, landlock, seccomp LayerStatus) (AppliedLaunchOutcome, error) {
	if !landlock.Active {
		return LaunchOutcomeRefused, fmt.Errorf("landlock is required for sandbox filesystem containment; use a kernel with Landlock support or a separately labelled `pipelock contain` host boundary")
	}
	if !seccomp.Active && (strict || seccompSupported) {
		return LaunchOutcomeRefused, fmt.Errorf("seccomp was not applied; refusing a launch whose build supports the filter")
	}
	if strict && noNetNS {
		return LaunchOutcomeRefused, fmt.Errorf("strict mode requires a network namespace")
	}
	if noNetNS {
		if !seccomp.Active {
			return LaunchOutcomeAdvisoryOverridePartial, nil
		}
		return LaunchOutcomeAdvisoryOverride, nil
	}
	if !seccomp.Active {
		return LaunchOutcomePartial, nil
	}
	return LaunchOutcomeFull, nil
}

func reportAppliedLaunchOutcome(w io.Writer, outcome AppliedLaunchOutcome) {
	switch outcome {
	case LaunchOutcomeFull:
		_, _ = fmt.Fprintln(w, "[sandbox] launch outcome: FULL (Landlock + seccomp + network namespace applied)")
	case LaunchOutcomePartial:
		_, _ = fmt.Fprintln(w, "[sandbox] launch outcome: PARTIAL (Landlock + network namespace applied; seccomp filter unavailable in this build)")
	case LaunchOutcomeAdvisoryOverride:
		_, _ = fmt.Fprintln(w, "[sandbox] launch outcome: ADVISORY-OVERRIDE (no network namespace; direct egress may bypass Pipelock)")
	case LaunchOutcomeAdvisoryOverridePartial:
		_, _ = fmt.Fprintln(w, "[sandbox] launch outcome: ADVISORY-OVERRIDE (network) + PARTIAL (seccomp unavailable in this build; direct egress may bypass Pipelock)")
	}
}

// validateBestEffortOverride requires a bounded, operator-attributable
// exception before a launch may fall back from kernel-enforced network
// isolation to cooperative proxy environment variables.
func validateBestEffortOverride(reason, expiry string, now time.Time) (time.Time, error) {
	if strings.TrimSpace(reason) == "" {
		return time.Time{}, errors.New("best-effort override requires a reason")
	}
	if strings.TrimSpace(expiry) == "" {
		return time.Time{}, errors.New("best-effort override requires an expiry (duration or RFC3339 timestamp)")
	}
	if duration, err := time.ParseDuration(expiry); err == nil {
		if duration <= 0 {
			return time.Time{}, errors.New("best-effort override has expired")
		}
		return now.Add(duration), nil
	}
	expiresAt, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		return time.Time{}, fmt.Errorf("best-effort override expiry must be a duration or RFC3339 timestamp: %w", err)
	}
	if !expiresAt.After(now) {
		return time.Time{}, errors.New("best-effort override has expired")
	}
	return expiresAt, nil
}

// ValidateBestEffortOverride validates a best-effort override against the
// current time. CLI preflight uses this before reporting a launchable posture.
func ValidateBestEffortOverride(reason, expiry string) (time.Time, error) {
	return validateBestEffortOverride(reason, expiry, time.Now())
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

func forceEnvValue(env []string, key, value string) []string {
	env = removeEnvKey(env, key)
	return append(env, key+"="+value)
}

// lookPathIn resolves a command name to an absolute path using the PATH
// from the given environment slice (not os.Getenv).
func lookPathIn(name string, env []string) (string, error) {
	// If the name contains a slash, it's already a path.
	if strings.Contains(name, "/") {
		path := filepath.Clean(name)
		if !filepath.IsAbs(path) {
			return path, nil
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", fmt.Errorf("%w: %s", exec.ErrNotFound, path)
		}
		return path, nil
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

// ResolveCommandInDir resolves a Guard command exactly as it will execute from
// workingDir. Unlike lookPathIn, relative slash paths and relative PATH entries
// are anchored to the final working directory and the result is absolute, so
// the outer and final Landlock domains grant the same file.
func ResolveCommandInDir(name string, env []string, workingDir string) (string, error) {
	if name == "" || !filepath.IsAbs(workingDir) {
		return "", fmt.Errorf("%w: invalid command or working directory", exec.ErrNotFound)
	}
	check := func(path string) (string, bool) {
		if !filepath.IsAbs(path) {
			path = filepath.Join(workingDir, path)
		}
		path = filepath.Clean(path)
		info, err := os.Stat(path)
		return path, err == nil && !info.IsDir()
	}
	if strings.Contains(name, "/") {
		if path, ok := check(name); ok {
			return path, nil
		}
		return "", fmt.Errorf("%w: %s", exec.ErrNotFound, name)
	}

	pathValue := "/usr/local/bin:/usr/bin:/bin"
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			pathValue = entry[5:]
			break
		}
	}
	for _, dir := range filepath.SplitList(pathValue) {
		if path, ok := check(filepath.Join(dir, name)); ok {
			return path, nil
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
		// to defaults. Log the error and exit - the parent validated this
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
