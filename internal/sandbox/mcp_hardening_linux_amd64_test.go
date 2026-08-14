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
	mcpEnvironProofHelperEnv     = "PIPELOCK_MCP_ENVIRON_PROOF_HELPER"
	mcpEnvironProofBinaryEnv     = "PIPELOCK_MCP_ENVIRON_PROOF_BINARY"
	mcpEnvironProofWorkspaceEnv  = "PIPELOCK_MCP_ENVIRON_PROOF_WORKSPACE"
	mcpEnvironProofServerEnv     = "PIPELOCK_MCP_ENVIRON_PROOF_SERVER"
	mcpEnvironProofConfigEnv     = "PIPELOCK_MCP_ENVIRON_PROOF_CONFIG"
	mcpEnvironProofMarkerEnv     = "PIPELOCK_SANDBOX_HARDENING_PROOF_MARKER"
	mcpEnvironProofMarkerPathEnv = "PIPELOCK_MCP_ENVIRON_PROOF_MARKER_PATH"
)

const mcpEnvironProofDenied = `{"jsonrpc":"2.0","id":1,"result":{"proxy_environ":"denied","parent_hardening":"released"}}` + "\n"

func TestIntegration_McpSandboxProxyEnvironDenied(t *testing.T) {
	if mode := os.Getenv(mcpEnvironProofHelperEnv); mode != "" {
		runMCPEnvironProofHelper(t, mode)
		return
	}

	requireSandboxPrimitives(t)
	binary := buildMCPEnvironProofBinary(t)
	for _, mode := range []string{
		"default",
		"default-rerun",
		"strict",
		"best-effort-with-namespaces",
	} {
		t.Run(mode, func(t *testing.T) {
			runMCPEnvironProof(t, binary, mode)
		})
	}
}

func TestIntegration_McpSandboxBestEffortFallbackEnvironDenied(t *testing.T) {
	binary := buildMCPEnvironProofBinary(t)
	runMCPEnvironProof(t, binary, "best-effort-fallback")
}

func runMCPEnvironProof(t *testing.T, binary, mode string) {
	t.Helper()
	workspace := t.TempDir()
	marker := filepath.Join(workspace, "parent-hardened")
	server := filepath.Join(workspace, "mcp-environ-server.py")
	serverScript := "import os\n" +
		"import sys\n" +
		"proxy_pid = os.getppid()\n" +
		"marker = os.environ[\"" + mcpEnvironProofMarkerEnv + "\"]\n" +
		"try:\n" +
		"    fd = os.open(f\"/proc/{proxy_pid}/environ\", os.O_RDONLY)\n" +
		"    os.close(fd)\n" +
		"    result = 'readable'\n" +
		"except OSError as err:\n" +
		"    print(f'[mcp-environ-proof] errno={err.errno} uid={os.getuid()} ppid={os.getppid()} proxy={proxy_pid}', file=sys.stderr)\n" +
		"    result = 'denied'\n" +
		"parent_hardening = 'released' if os.path.exists(marker) else 'missing'\n" +
		"if not sys.stdin.readline():\n" +
		"    raise SystemExit(1)\n" +
		"sys.stdout.write('{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":1,\\\"result\\\":{\\\"proxy_environ\\\":\\\"' + result + '\\\",\\\"parent_hardening\\\":\\\"' + parent_hardening + '\\\"}}\\n')\n"
	if err := os.WriteFile(server, []byte(serverScript), 0o600); err != nil {
		t.Fatalf("write MCP environ proof server: %v", err)
	}
	config := filepath.Join(t.TempDir(), "pipelock.yaml")

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIntegration_McpSandboxProxyEnvironDenied$") // #nosec G204 G702 -- test re-execs its own binary with a fixed run filter
	cmd.Env = append(os.Environ(),
		mcpEnvironProofHelperEnv+"="+mode,
		mcpEnvironProofBinaryEnv+"="+binary,
		mcpEnvironProofWorkspaceEnv+"="+workspace,
		mcpEnvironProofServerEnv+"="+server,
		mcpEnvironProofConfigEnv+"="+config,
		mcpEnvironProofMarkerEnv+"="+marker,
		mcpEnvironProofMarkerPathEnv+"="+marker,
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

func buildMCPEnvironProofBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "pipelock-mcp-environ-proof")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-tags=mcp_hardening_test", "-o", binary, "./cmd/pipelock/") // #nosec G204 G702 -- fixed repository build for the integration proof
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build MCP environ proof binary: %v\n%s", err, out)
	}
	return binary
}

func runMCPEnvironProofHelper(t *testing.T, mode string) {
	t.Helper()
	binary := os.Getenv(mcpEnvironProofBinaryEnv)
	workspace := os.Getenv(mcpEnvironProofWorkspaceEnv)
	server := os.Getenv(mcpEnvironProofServerEnv)
	config := os.Getenv(mcpEnvironProofConfigEnv)
	marker := os.Getenv(mcpEnvironProofMarkerPathEnv)
	if binary == "" || workspace == "" || server == "" || config == "" || marker == "" {
		t.Fatalf("MCP environ proof helper missing fixture path")
	}

	proxyPID := strconv.Itoa(os.Getpid())
	configBody := fmt.Sprintf("sandbox:\n  filesystem:\n    allow_read:\n      - /proc/%s\n", proxyPID)
	if err := os.WriteFile(config, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write MCP environ proof config: %v", err)
	}

	if mode == "best-effort-fallback" {
		// Deny only namespace creation, not the whole production filter. See
		// applyUserNSDenyFilter for why: seccomp is inherited across fork and
		// exec, so ApplySeccomp here put the proxy and the CPython target under
		// a filter meant for a confined child and made this proof intermittent.
		applyUserNSDenyFilter(t)
	}

	args := []string{"mcp", "proxy", "--config", config, "--workspace", workspace}
	switch mode {
	case "default", "default-rerun":
		args = append(args, "--sandbox")
	case "strict":
		args = append(args, "--sandbox-strict")
	case "best-effort-with-namespaces", "best-effort-fallback":
		args = append(args, "--sandbox-best-effort")
	default:
		t.Fatalf("unknown MCP environ proof mode %q", mode)
	}
	args = append(args,
		"--env", mcpEnvironProofMarkerEnv+"="+marker,
		"--", "python3", server,
	)
	if err := syscall.Exec(binary, append([]string{binary}, args...), os.Environ()); err != nil { // #nosec G204 G702 -- controlled test helper re-execs its fixture binary
		t.Fatalf("exec MCP environ proof: %v", err)
	}
}
