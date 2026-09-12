// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cleanupCapabilityReport = "session descendant cleanup"

const cleanupStartupHelperStarted = "mcp cleanup startup helper started"

// TestMCPProxyCmd_ReportsCleanupCapabilityBeforeStdioChild starts the real
// McpCmd subprocess path with the existing bounded MCP helper. It covers both
// default construction and config.Load, while keeping stdout confined to the
// helper's JSON-RPC protocol output. The sandbox launch needs host kernel
// facilities (user namespaces and Landlock), so its capability report is
// covered by internal/mcp's platform-gated launch tests rather than making this
// portable command test claim a successful sandbox launch.
func TestMCPProxyCmd_ReportsCleanupCapabilityBeforeStdioChild(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	for _, tt := range []struct {
		name string
		args []string
	}{
		{
			name: "defaults without config",
			args: []string{
				"proxy",
				"--env", "PIPELOCK_TEST_MCP_CLEANUP_STARTUP_HELPER=1",
				"--", os.Args[0], "-test.run=TestMCPCleanupStartupHelperProcess$",
			},
		},
		{
			name: "loaded config",
			args: []string{
				"proxy", "--config", configPath,
				"--env", "PIPELOCK_TEST_MCP_CLEANUP_STARTUP_HELPER=1",
				"--", os.Args[0], "-test.run=TestMCPCleanupStartupHelperProcess$",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runMCPProxyCommandWithArgs(t, tt.args)
			if err != nil {
				t.Fatalf("McpCmd(%v): %v\nstderr:\n%s", tt.args, err, stderr)
			}
			if got := strings.Count(stderr, cleanupCapabilityReport); got != 1 {
				t.Fatalf("cleanup capability reports = %d, want exactly 1\nstderr:\n%s", got, stderr)
			}
			reportAt := strings.Index(stderr, cleanupCapabilityReport)
			childStartedAt := strings.Index(stderr, cleanupStartupHelperStarted)
			if childStartedAt < 0 {
				t.Fatalf("stderr lacks child-start marker:\n%s", stderr)
			}
			if reportAt > childStartedAt {
				t.Fatalf("cleanup capability was reported after child execution began:\n%s", stderr)
			}
			if strings.Contains(stderr, "Run with strict mode to fail closed instead.") {
				t.Fatalf("plain stdio report offered a sandbox-only strict-mode remedy:\n%s", stderr)
			}
			assertMCPProtocolOnly(t, stdout)
		})
	}
}

// TestMCPCleanupStartupHelperProcess records child execution on stderr, then
// delegates protocol behavior to the established MCP runtime helper. It is
// only executed by the re-exec in TestMCPProxyCmd_ReportsCleanupCapabilityBeforeStdioChild.
func TestMCPCleanupStartupHelperProcess(t *testing.T) {
	if os.Getenv("PIPELOCK_TEST_MCP_CLEANUP_STARTUP_HELPER") != "1" {
		return
	}
	if _, err := fmt.Fprintln(os.Stderr, cleanupStartupHelperStarted); err != nil {
		t.Fatalf("write child-start marker: %v", err)
	}
	if err := os.Setenv("PIPELOCK_TEST_MCP_HELPER", "1"); err != nil {
		t.Fatalf("enable MCP runtime helper: %v", err)
	}
	TestMCPRuntimeHelperProcess(t)
}

func assertMCPProtocolOnly(t *testing.T, stdout string) {
	t.Helper()

	lines := strings.FieldsFunc(stdout, func(r rune) bool { return r == '\n' || r == '\r' })
	if len(lines) == 0 {
		t.Fatal("MCP child produced no JSON-RPC protocol output")
	}
	for _, line := range lines {
		var message struct {
			JSONRPC string `json:"jsonrpc"`
		}
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			t.Fatalf("stdout contains non-protocol data %q: %v", line, err)
		}
		if message.JSONRPC != "2.0" {
			t.Fatalf("stdout protocol version = %q, want JSON-RPC 2.0", message.JSONRPC)
		}
	}
}

// TestMCPProxyCmd_RemoteRoutesDoNotReportSubprocessCleanup makes each remote
// routing branch run far enough to emit its own setup result. They must never
// claim a child-process cleanup capability because they do not launch a child.
func TestMCPProxyCmd_RemoteRoutesDoNotReportSubprocessCleanup(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		input   string
		wantErr string
		wantOut string
	}{
		{
			name:    "http upstream",
			args:    []string{"proxy", "--upstream", "http://" + unavailableTCPAddr(t) + "/mcp"},
			input:   `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n",
			wantOut: "upstream HTTP request failed",
		},
		{
			name:    "websocket upstream",
			args:    []string{"proxy", "--upstream", "ws://" + unavailableTCPAddr(t) + "/mcp"},
			wantErr: "connect",
		},
		{
			name:    "http listener",
			args:    []string{"proxy", "--listen", "127.0.0.1:0", "--upstream", "ws://api.vendor.example/mcp"},
			wantErr: "--listen with WebSocket upstream",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runMCPProxyCommandWithInput(t, tt.args, tt.input)
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("McpCmd(%v) error = %v, want %q\nstdout:\n%s\nstderr:\n%s", tt.args, err, tt.wantErr, stdout, stderr)
			}
			if tt.wantErr == "" && err != nil {
				t.Fatalf("McpCmd(%v): %v\nstdout:\n%s\nstderr:\n%s", tt.args, err, stdout, stderr)
			}
			if tt.wantOut != "" && !strings.Contains(stdout, tt.wantOut) {
				t.Fatalf("stdout = %q, want protocol error containing %q", stdout, tt.wantOut)
			}
			if strings.Contains(stderr, cleanupCapabilityReport) {
				t.Fatalf("remote route reported subprocess cleanup capability:\n%s", stderr)
			}
		})
	}
}
