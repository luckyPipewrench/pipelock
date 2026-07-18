// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runSandboxInitBinary(t *testing.T, binary string, env []string) (string, int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary) // #nosec G204 -- controlled test binary.
	cmd.Env = initChildEnvironment(env)
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("sandbox init child timed out: %v\nstderr: %s", ctx.Err(), stderr.String())
	}
	if err == nil {
		return stderr.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("sandbox init child failed to execute: %v", err)
	}
	return stderr.String(), exitErr.ExitCode()
}

func TestIntegration_InitChildrenRejectMalformedLaunchState(t *testing.T) {
	binary := buildTestBinary(t)
	workspace := t.TempDir()
	socketPath := filepath.Join(t.TempDir(), "proxy.sock")

	tests := []struct {
		name     string
		env      []string
		wantCode int
		wantErr  string
	}{
		{
			name:     "mcp init requires workspace and command",
			env:      []string{initEnvKey + "=1"},
			wantCode: 1,
			wantErr:  "missing workspace or command",
		},
		{
			name:     "standalone init requires socket",
			env:      []string{standaloneInitEnv + "=1"},
			wantCode: 1,
			wantErr:  "missing workspace, command, or socket path",
		},
		{
			name: "mcp init rejects corrupted policy",
			env: []string{
				initEnvKey + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=true",
				"__PIPELOCK_SANDBOX_EXTRA_ENV=SAFE_ONE=1\x1fSAFE_TWO=2",
				"__PIPELOCK_SANDBOX_POLICY={",
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "FATAL: invalid policy JSON",
		},
		{
			name: "standalone init rejects corrupted policy",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=true",
				sandboxSocketEnv + "=" + socketPath,
				"__PIPELOCK_SANDBOX_EXTRA_ENV=SAFE_ONE=1\x1fSAFE_TWO=2",
				"__PIPELOCK_SANDBOX_POLICY={",
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "FATAL: invalid policy JSON",
		},
		{
			name: "mcp init rejects missing command",
			env: []string{
				initEnvKey + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=definitely-not-a-real-pipelock-test-command",
				noNetNSEnvKey + "=1",
			},
			wantCode: 127,
			wantErr:  "command not found",
		},
		{
			name: "standalone init rejects missing command",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=definitely-not-a-real-pipelock-test-command",
				sandboxSocketEnv + "=" + socketPath,
				noNetNSEnvKey + "=1",
			},
			wantCode: 127,
			wantErr:  "command not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stderr, code := runSandboxInitBinary(t, binary, tc.env)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d\nstderr: %s", code, tc.wantCode, stderr)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Fatalf("stderr missing %q:\n%s", tc.wantErr, stderr)
			}
		})
	}
}
