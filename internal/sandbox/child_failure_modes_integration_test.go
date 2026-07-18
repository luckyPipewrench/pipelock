// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type initChildResult struct {
	stderr    string
	exitCode  int
	waitState syscall.WaitStatus
}

func runInitChildFailureCase(t *testing.T, binary string, env []string) initChildResult {
	return runInitChildFailureCaseWithNamespaces(t, binary, env, false)
}

func runNamespacedInitChildFailureCase(t *testing.T, binary string, env []string) initChildResult {
	t.Helper()
	result := runInitChildFailureCaseWithNamespaces(t, binary, env, true)
	if result.exitCode == 1 && strings.Contains(result.stderr, "[sandbox] loopback:") {
		t.Skipf("network namespace loopback unavailable:\n%s", result.stderr)
	}
	return result
}

func runInitChildFailureCaseWithNamespaces(t *testing.T, binary string, env []string, namespaced bool) initChildResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary) // #nosec G204 -- controlled test binary.
	cmd.Env = initChildEnvironment(env)
	cmd.Stderr = &stderr
	if namespaced {
		cmd.SysProcAttr = initChildNamespaceAttributes()
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("sandbox init child timed out: %v\nstderr: %s", ctx.Err(), stderr.String())
	}
	if namespaced && errors.Is(err, syscall.EPERM) {
		t.Skipf("user namespaces unavailable: %v", err)
	}
	if err == nil {
		return initChildResult{stderr: stderr.String()}
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("sandbox init child failed to execute: %v", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("sandbox init child returned unexpected process state %T", exitErr.Sys())
	}
	return initChildResult{
		stderr:    stderr.String(),
		exitCode:  exitErr.ExitCode(),
		waitState: status,
	}
}

func initChildNamespaceAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		Pdeathsig: syscall.SIGTERM,
		Setpgid:   true,
	}
}

func marshalInitPolicy(t *testing.T, policy Policy) string {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal child policy: %v", err)
	}
	return string(data)
}

func instrumentedInitPolicy(t *testing.T, workspace string) string {
	t.Helper()
	policy := DefaultPolicy(workspace)
	if dir := os.Getenv("GOCOVERDIR"); dir != "" {
		policy.AllowRWDirs = append(policy.AllowRWDirs, filepath.Clean(dir))
	}
	return marshalInitPolicy(t, policy)
}

func requireInitFailure(t *testing.T, result initChildResult, wantStderr string) {
	t.Helper()
	if result.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr: %s", result.exitCode, result.stderr)
	}
	if !strings.Contains(result.stderr, wantStderr) {
		t.Fatalf("stderr missing %q:\n%s", wantStderr, result.stderr)
	}
}

func TestIntegration_InitChildrenRejectUnsafeResolvedPolicies(t *testing.T) {
	binary := buildTestBinaryWithoutSandboxProbe(t)
	workspace := t.TempDir()
	socketPath := filepath.Join(t.TempDir(), "proxy.sock")
	missingPath := filepath.Join(t.TempDir(), "missing")

	protectedHome := t.TempDir()
	if err := os.Mkdir(filepath.Join(protectedHome, ".ssh"), 0o750); err != nil {
		t.Fatalf("create protected directory: %v", err)
	}

	tests := []struct {
		name       string
		modeEnv    string
		socketEnv  string
		policy     Policy
		wantStderr string
	}{
		{
			name:       "mcp rejects missing allow path",
			modeEnv:    initEnvKey + "=1",
			policy:     Policy{Workspace: workspace, AllowReadDirs: []string{missingPath}},
			wantStderr: "FATAL: resolve policy: sandbox allow_read path does not exist",
		},
		{
			name:       "standalone rejects missing allow path",
			modeEnv:    standaloneInitEnv + "=1",
			socketEnv:  sandboxSocketEnv + "=" + socketPath,
			policy:     Policy{Workspace: workspace, AllowReadDirs: []string{missingPath}},
			wantStderr: "FATAL: resolve policy: sandbox allow_read path does not exist",
		},
		{
			name:       "mcp rejects protected directory overlap",
			modeEnv:    initEnvKey + "=1",
			policy:     Policy{Workspace: workspace, AllowReadDirs: []string{"/"}},
			wantStderr: "FATAL: validate policy: sandbox allow_read",
		},
		{
			name:       "standalone rejects protected directory overlap",
			modeEnv:    standaloneInitEnv + "=1",
			socketEnv:  sandboxSocketEnv + "=" + socketPath,
			policy:     Policy{Workspace: workspace, AllowReadDirs: []string{"/"}},
			wantStderr: "FATAL: validate policy: sandbox allow_read",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "must-not-run")
			env := []string{
				tc.modeEnv,
				childWorkspaceEnv + "=" + workspace,
				childCommandEnv + "=/bin/sh\x1f-c\x1ftouch \"$1\"\x1fsh\x1f" + marker,
				childPolicyEnv + "=" + marshalInitPolicy(t, tc.policy),
				noNetNSEnvKey + "=1",
				"HOME=" + protectedHome,
			}
			if tc.socketEnv != "" {
				env = append(env, tc.socketEnv)
			}

			result := runInitChildFailureCase(t, binary, env)
			requireInitFailure(t, result, tc.wantStderr)
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("command ran despite rejected policy: stat error = %v", err)
			}
		})
	}
}

func TestIntegration_InitChildrenFailClosedOnEnvironmentAndNetworkStartup(t *testing.T) {
	binary := buildTestBinaryWithoutSandboxProbe(t)
	workspace := t.TempDir()
	socketPath := filepath.Join(t.TempDir(), "proxy.sock")

	t.Run("dangerous extra environment", func(t *testing.T) {
		for _, mode := range []struct {
			name      string
			modeEnv   string
			socketEnv string
		}{
			{name: "mcp", modeEnv: initEnvKey + "=1"},
			{name: "standalone", modeEnv: standaloneInitEnv + "=1", socketEnv: sandboxSocketEnv + "=" + socketPath},
		} {
			t.Run(mode.name, func(t *testing.T) {
				marker := filepath.Join(t.TempDir(), "must-not-run")
				env := []string{
					mode.modeEnv,
					childWorkspaceEnv + "=" + workspace,
					childCommandEnv + "=/bin/sh\x1f-c\x1ftouch \"$1\"\x1fsh\x1f" + marker,
					childExtraEnv + "=HTTP_PROXY=http://untrusted.invalid",
					noNetNSEnvKey + "=1",
				}
				if mode.socketEnv != "" {
					env = append(env, mode.socketEnv)
				}

				result := runInitChildFailureCase(t, binary, env)
				requireInitFailure(t, result, "env setup:")
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("command ran despite rejected environment: stat error = %v", err)
				}
			})
		}
	})

	t.Run("loopback activation denied", func(t *testing.T) {
		for _, mode := range []struct {
			name      string
			modeEnv   string
			socketEnv string
		}{
			{name: "mcp", modeEnv: initEnvKey + "=1", socketEnv: sandboxSocketEnv + "=" + socketPath},
			{name: "standalone", modeEnv: standaloneInitEnv + "=1", socketEnv: sandboxSocketEnv + "=" + socketPath},
		} {
			t.Run(mode.name, func(t *testing.T) {
				marker := filepath.Join(t.TempDir(), "must-not-run")
				result := runInitChildFailureCase(t, binary, []string{
					mode.modeEnv,
					childWorkspaceEnv + "=" + workspace,
					childCommandEnv + "=/bin/sh\x1f-c\x1ftouch \"$1\"\x1fsh\x1f" + marker,
					mode.socketEnv,
					childPolicyEnv + "=" + instrumentedInitPolicy(t, workspace),
				})
				requireInitFailure(t, result, "loopback:")
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("command ran despite network startup failure: stat error = %v", err)
				}
			})
		}
	})
}

func TestIntegration_InitChildrenPropagateCommandFailures(t *testing.T) {
	binary := buildTestBinaryWithoutSandboxProbe(t)
	workspace := t.TempDir()
	socketPath := filepath.Join(t.TempDir(), "proxy.sock")

	t.Run("mcp rejects inaccessible working directory", func(t *testing.T) {
		restrictedWorkspace := t.TempDir()
		if err := os.Chmod(restrictedWorkspace, 0o600); err != nil {
			t.Fatalf("restrict workspace: %v", err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(restrictedWorkspace, 0o750); err != nil { // #nosec G302 -- restores temp directory access.
				t.Errorf("restore workspace permissions: %v", err)
			}
		})

		result := runInitChildFailureCase(t, binary, []string{
			initEnvKey + "=1",
			childWorkspaceEnv + "=" + restrictedWorkspace,
			childCommandEnv + "=/bin/true",
			childPolicyEnv + "=" + instrumentedInitPolicy(t, restrictedWorkspace),
			noNetNSEnvKey + "=1",
		})
		requireInitFailure(t, result, "chdir "+restrictedWorkspace+":")
	})

	t.Run("late command failures", func(t *testing.T) {
		invalidExecutable := filepath.Join(workspace, "invalid-executable")
		// #nosec G306 -- executable permission is required to reach the
		// syscall.Exec invalid-format failure after sandbox setup.
		if err := os.WriteFile(invalidExecutable, []byte("not an executable format\n"), 0o700); err != nil {
			t.Fatalf("write invalid executable: %v", err)
		}

		tests := []struct {
			name       string
			modeEnv    string
			command    string
			wantStderr string
		}{
			{
				name:       "mcp exec",
				modeEnv:    initEnvKey + "=1",
				command:    invalidExecutable,
				wantStderr: "exec failed:",
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				env := []string{
					tc.modeEnv,
					childWorkspaceEnv + "=" + workspace,
					childCommandEnv + "=" + tc.command,
					childPolicyEnv + "=" + instrumentedInitPolicy(t, workspace),
					noNetNSEnvKey + "=1",
					"GOMAXPROCS=1",
				}
				result := runInitChildFailureCase(t, binary, env)
				requireInitFailure(t, result, tc.wantStderr)
			})
		}
	})

	tests := []struct {
		name       string
		modeEnv    string
		command    string
		socketEnv  string
		wantCode   int
		wantStderr string
	}{
		{
			name:       "mcp rejects missing command without bridge",
			modeEnv:    initEnvKey + "=1",
			command:    "/definitely/missing/pipelock-test-command",
			wantCode:   127,
			wantStderr: "command not found:",
		},
		{
			name:       "mcp bridge rejects missing command",
			modeEnv:    initEnvKey + "=1",
			command:    "/definitely/missing/pipelock-test-command",
			socketEnv:  sandboxSocketEnv + "=" + socketPath,
			wantCode:   127,
			wantStderr: "command not found:",
		},
		{
			name:       "standalone rejects missing command",
			modeEnv:    standaloneInitEnv + "=1",
			command:    "/definitely/missing/pipelock-test-command",
			socketEnv:  sandboxSocketEnv + "=" + socketPath,
			wantCode:   127,
			wantStderr: "command not found:",
		},
		{
			name:      "mcp bridge preserves exit code",
			modeEnv:   initEnvKey + "=1",
			command:   "/bin/sh\x1f-c\x1fexit 23",
			socketEnv: sandboxSocketEnv + "=" + socketPath,
			wantCode:  23,
		},
		{
			name:      "standalone preserves exit code",
			modeEnv:   standaloneInitEnv + "=1",
			command:   "/bin/sh\x1f-c\x1fexit 23",
			socketEnv: sandboxSocketEnv + "=" + socketPath,
			wantCode:  23,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{
				tc.modeEnv,
				childWorkspaceEnv + "=" + workspace,
				childCommandEnv + "=" + tc.command,
				childPolicyEnv + "=" + instrumentedInitPolicy(t, workspace),
				noNetNSEnvKey + "=1",
			}
			if tc.socketEnv != "" {
				env = append(env, tc.socketEnv)
			}
			runChild := runInitChildFailureCase
			if tc.socketEnv != "" {
				env = removeEnvKey(env, noNetNSEnvKey)
				runChild = runNamespacedInitChildFailureCase
			}
			result := runChild(t, binary, env)
			if result.exitCode != tc.wantCode {
				t.Fatalf("exit code = %d, want %d\nstderr: %s", result.exitCode, tc.wantCode, result.stderr)
			}
			if tc.wantStderr != "" && !strings.Contains(result.stderr, tc.wantStderr) {
				t.Fatalf("stderr missing %q:\n%s", tc.wantStderr, result.stderr)
			}
		})
	}
}

func TestIntegration_MCPInitBridgePropagatesSignals(t *testing.T) {
	binary := buildTestBinaryWithoutSandboxProbe(t)
	workspace := t.TempDir()
	socketPath := filepath.Join(t.TempDir(), "proxy.sock")

	probe := runNamespacedInitChildFailureCase(t, binary, []string{
		initEnvKey + "=1",
		childWorkspaceEnv + "=" + workspace,
		childCommandEnv + "=/bin/true",
		sandboxSocketEnv + "=" + socketPath,
		childPolicyEnv + "=" + instrumentedInitPolicy(t, workspace),
	})
	if probe.exitCode != 0 {
		t.Fatalf("sandbox namespace probe failed with code %d:\n%s", probe.exitCode, probe.stderr)
	}

	t.Run("command signal terminates wrapper with same signal", func(t *testing.T) {
		result := runNamespacedInitChildFailureCase(t, binary, []string{
			initEnvKey + "=1",
			childWorkspaceEnv + "=" + workspace,
			childCommandEnv + "=/bin/sh\x1f-c\x1fkill -TERM $$",
			sandboxSocketEnv + "=" + socketPath,
			childPolicyEnv + "=" + instrumentedInitPolicy(t, workspace),
		})
		if !result.waitState.Signaled() || result.waitState.Signal() != syscall.SIGTERM {
			t.Fatalf("wrapper status = %v, want SIGTERM\nstderr: %s", result.waitState, result.stderr)
		}
	})

	t.Run("wrapper forwards signal to command", func(t *testing.T) {
		marker := filepath.Join(workspace, "signal-ready")
		script := `trap 'exit 42' TERM; : > "$1"; while :; do :; done`

		stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-*")
		if err != nil {
			t.Fatalf("create stderr file: %v", err)
		}
		t.Cleanup(func() {
			if err := stderrFile.Close(); err != nil {
				t.Errorf("close stderr file: %v", err)
			}
		})

		cmdCtx, cancelCmd := context.WithCancel(context.Background())
		t.Cleanup(cancelCmd)
		cmd := exec.CommandContext(cmdCtx, binary) // #nosec G204 -- controlled test binary.
		cmd.Env = initChildEnvironment([]string{
			initEnvKey + "=1",
			childWorkspaceEnv + "=" + workspace,
			childCommandEnv + "=/bin/sh\x1f-c\x1f" + script + "\x1fsh\x1f" + marker,
			sandboxSocketEnv + "=" + socketPath,
			childPolicyEnv + "=" + instrumentedInitPolicy(t, workspace),
		})
		cmd.Stderr = stderrFile
		cmd.SysProcAttr = initChildNamespaceAttributes()
		if err := cmd.Start(); err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skipf("user namespaces unavailable: %v", err)
			}
			t.Fatalf("start sandbox init child: %v", err)
		}

		readyTicker := time.NewTicker(10 * time.Millisecond)
		defer readyTicker.Stop()
		readyTimeout := time.NewTimer(5 * time.Second)
		defer readyTimeout.Stop()
	waitForReady:
		for {
			select {
			case <-readyTicker.C:
				if _, err := os.Stat(marker); err == nil {
					break waitForReady
				} else if os.IsNotExist(err) {
					continue
				} else {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					t.Fatalf("stat signal marker: %v", err)
				}
			case <-readyTimeout.C:
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				data, _ := os.ReadFile(stderrFile.Name())
				t.Fatalf("command did not become ready\nstderr: %s", data)
			}
		}

		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("signal sandbox init child: %v", err)
		}

		waitDone := make(chan error, 1)
		go func() {
			waitDone <- cmd.Wait()
		}()
		select {
		case err := <-waitDone:
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 {
				data, _ := os.ReadFile(stderrFile.Name())
				t.Fatalf("wrapper exit = %v, want code 42\nstderr: %s", err, data)
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-waitDone
			t.Fatal("sandbox init child did not exit after SIGTERM")
		}
	})
}
