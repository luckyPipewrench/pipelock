// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	mcpEnvironProofHelperEnv    = "PIPELOCK_MCP_ENVIRON_PROOF_HELPER"
	mcpEnvironProofBinaryEnv    = "PIPELOCK_MCP_ENVIRON_PROOF_BINARY"
	mcpEnvironProofWorkspaceEnv = "PIPELOCK_MCP_ENVIRON_PROOF_WORKSPACE"
	mcpEnvironProofServerEnv    = "PIPELOCK_MCP_ENVIRON_PROOF_SERVER"
	mcpEnvironProofConfigEnv    = "PIPELOCK_MCP_ENVIRON_PROOF_CONFIG"
	mcpEnvironProofProxyPIDEnv  = "PIPELOCK_TEST_PROXY_PID"
)

const (
	mcpEnvironProofDenied   = `{"jsonrpc":"2.0","id":1,"result":{"proxy_environ":"denied"}}` + "\n"
	mcpEnvironProofReadable = `{"jsonrpc":"2.0","id":1,"result":{"proxy_environ":"readable"}}` + "\n"
)

func TestIntegration_McpSandboxProxyEnvironDenied(t *testing.T) {
	if mode := os.Getenv(mcpEnvironProofHelperEnv); mode != "" {
		runMCPEnvironProofHelper(t, mode)
		return
	}

	binary := buildTestBinary(t)
	for _, mode := range []string{"default", "strict"} {
		t.Run(mode, func(t *testing.T) {
			runMCPEnvironProof(t, binary, mode)
		})
	}
}

func TestIntegration_McpSandboxBestEffortFallbackEnvironDenied(t *testing.T) {
	binary := buildTestBinaryWithoutSandboxProbe(t)
	runMCPEnvironProof(t, binary, "best-effort-fallback")
}

func runMCPEnvironProof(t *testing.T, binary, mode string) {
	t.Helper()
	workspace := t.TempDir()
	server := filepath.Join(workspace, "mcp-environ-server.sh")
	serverScript := "#!/bin/sh\n" +
		"IFS= read -r _ || exit 1\n" +
		"if cat \"/proc/${" + mcpEnvironProofProxyPIDEnv + "}/environ\" >/dev/null 2>&1; then\n" +
		"  printf '%s' '" + mcpEnvironProofReadable[:len(mcpEnvironProofReadable)-1] + "'\n" +
		"else\n" +
		"  printf '%s' '" + mcpEnvironProofDenied[:len(mcpEnvironProofDenied)-1] + "'\n" +
		"fi\n"
	if err := os.WriteFile(server, []byte(serverScript), 0o700); err != nil {
		t.Fatalf("write MCP environ proof server: %v", err)
	}
	config := filepath.Join(t.TempDir(), "pipelock.yaml")

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=^TestIntegration_McpSandboxProxyEnvironDenied$"}
	if mode == "best-effort-fallback" {
		// The host has more same-UID threads than the sandbox's 1024-process
		// ceiling. A parent user namespace gives this proof an isolated rlimit
		// accounting domain; seccomp in the helper still forces Pipelock itself
		// down the no-map best-effort branch.
		cmdPath = "unshare"
		cmdArgs = append([]string{"-Ur", os.Args[0]}, cmdArgs...)
	}
	cmd := exec.CommandContext(ctx, cmdPath, cmdArgs...) //nolint:gosec // fixed test binary helper executes Pipelock
	cmd.Env = append(os.Environ(),
		mcpEnvironProofHelperEnv+"="+mode,
		mcpEnvironProofBinaryEnv+"="+binary,
		mcpEnvironProofWorkspaceEnv+"="+workspace,
		mcpEnvironProofServerEnv+"="+server,
		mcpEnvironProofConfigEnv+"="+config,
	)
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}` + "\n")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s sandbox environ proof failed: %v\nstderr: %s\nstdout: %s", mode, err, stderr.String(), stdout.String())
	}
	if got := stdout.String(); got != mcpEnvironProofDenied {
		t.Fatalf("%s sandbox target read proxy environ: got %q, want %q\nstderr: %s", mode, got, mcpEnvironProofDenied, stderr.String())
	}
	if !strings.Contains(stderr.String(), "[SANDBOXED]") {
		t.Fatalf("%s sandbox proof missing sandbox status:\n%s", mode, stderr.String())
	}
	if mode == "best-effort-fallback" && !strings.Contains(stderr.String(), "network: DEGRADED") {
		t.Fatalf("best-effort fallback did not take degraded namespace path:\n%s", stderr.String())
	}
}

func runMCPEnvironProofHelper(t *testing.T, mode string) {
	t.Helper()
	binary := os.Getenv(mcpEnvironProofBinaryEnv)
	workspace := os.Getenv(mcpEnvironProofWorkspaceEnv)
	server := os.Getenv(mcpEnvironProofServerEnv)
	config := os.Getenv(mcpEnvironProofConfigEnv)
	if binary == "" || workspace == "" || server == "" || config == "" {
		t.Fatalf("MCP environ proof helper missing fixture path")
	}

	proxyPID := strconv.Itoa(os.Getpid())
	configBody := fmt.Sprintf("sandbox:\n  filesystem:\n    allow_read:\n      - /proc/%s\n", proxyPID)
	if err := os.WriteFile(config, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write MCP environ proof config: %v", err)
	}

	if mode == "best-effort-fallback" {
		if err := SetNoNewPrivs(); err != nil {
			t.Fatalf("set no_new_privs for fallback proof: %v", err)
		}
		status, err := ApplySeccomp()
		if err != nil || !status.Active {
			t.Fatalf("apply seccomp for fallback proof: status=%+v err=%v", status, err)
		}
	}

	args := []string{"mcp", "proxy", "--config", config, "--workspace", workspace}
	switch mode {
	case "default":
		args = append(args, "--sandbox")
	case "strict":
		args = append(args, "--sandbox-strict")
	case "best-effort-fallback":
		args = append(args, "--sandbox-best-effort")
	default:
		t.Fatalf("unknown MCP environ proof mode %q", mode)
	}
	args = append(args,
		"--env", mcpEnvironProofProxyPIDEnv+"="+proxyPID,
		"--", "/bin/sh", server,
	)
	if err := syscall.Exec(binary, append([]string{binary}, args...), os.Environ()); err != nil {
		t.Fatalf("exec MCP environ proof: %v", err)
	}
}
