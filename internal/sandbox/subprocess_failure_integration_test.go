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
			name: "standalone init rejects corrupted guard declaration",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=true",
				sandboxSocketEnv + "=" + socketPath,
				standaloneGuardDeclarationEnv + "={",
				standaloneGuardPolicyHashEnv + "=hash",
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "guard declaration",
		},
		{
			name: "standalone init rejects missing guard policy hash",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=true",
				sandboxSocketEnv + "=" + socketPath,
				standaloneGuardDeclarationEnv + "={}",
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "guard policy hash is missing",
		},
		{
			name: "standalone init rejects nonnumeric guard status descriptor",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=true",
				sandboxSocketEnv + "=" + socketPath,
				standaloneGuardDeclarationEnv + "={}",
				standaloneGuardPolicyHashEnv + "=hash",
				guardStatusControlEnv + "=not-a-number",
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "[sandbox] guard status descriptor is invalid",
		},
		{
			name: "standalone init rejects reserved guard status descriptor",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				"__PIPELOCK_SANDBOX_COMMAND=true",
				sandboxSocketEnv + "=" + socketPath,
				standaloneGuardDeclarationEnv + "={}",
				standaloneGuardPolicyHashEnv + "=hash",
				guardStatusControlEnv + "=2",
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "[sandbox] guard status descriptor is invalid",
		},
		{
			name: "standalone init rejects malformed command transport",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				standaloneCommandJSONEnv + "={",
				sandboxSocketEnv + "=" + socketPath,
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "command transport",
		},
		{
			name: "standalone init rejects empty decoded command",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				standaloneCommandJSONEnv + "=[]",
				sandboxSocketEnv + "=" + socketPath,
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "decoded command is empty",
		},
		{
			name: "standalone init rejects decoded command NUL",
			env: []string{
				standaloneInitEnv + "=1",
				"__PIPELOCK_SANDBOX_WORKSPACE=" + workspace,
				standaloneCommandJSONEnv + `=["bad\u0000arg"]`,
				sandboxSocketEnv + "=" + socketPath,
				noNetNSEnvKey + "=1",
			},
			wantCode: 1,
			wantErr:  "decoded command contains NUL",
		},
		{
			name: "guard helper rejects invalid environment descriptor",
			env: []string{
				"__PIPELOCK_GUARD_EXEC=1",
				"__PIPELOCK_GUARD_ENVIRONMENT_FD=bad",
			},
			wantCode: 1,
			wantErr:  "[guard] REFUSED: invalid guard environment descriptor",
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
