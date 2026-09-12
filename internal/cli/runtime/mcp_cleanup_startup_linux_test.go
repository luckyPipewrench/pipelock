// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

const cleanupSandboxInitStarted = "cleanup sandbox init helper started"

const cleanupSandboxInitEnv = "PIPELOCK_TEST_CLEANUP_SANDBOX_INIT=1"

// The re-exec helper ends at sandbox-init entry. This test checks the CLI's
// diagnostic ordering, not whether this host can apply the sandbox layers.
func init() {
	if sandbox.IsInitMode() && slices.Contains(strings.Split(os.Getenv("__PIPELOCK_SANDBOX_EXTRA_ENV"), "\x1f"), cleanupSandboxInitEnv) {
		_, _ = fmt.Fprintln(os.Stderr, cleanupSandboxInitStarted)
		os.Exit(0)
	}
}

// TestMCPProxyCmd_ReportsCleanupBeforeSandboxInit exercises the sandbox CLI
// branch, including hosts that refuse the child after launch preparation.
func TestMCPProxyCmd_ReportsCleanupBeforeSandboxInit(t *testing.T) {
	args := []string{
		"proxy", "--sandbox", "--workspace", t.TempDir(),
		"--sandbox-best-effort", "--sandbox-best-effort-reason", "startup reporting test",
		"--sandbox-best-effort-expiry", "1h", "--env", cleanupSandboxInitEnv,
		"--", "/bin/true",
	}
	stdout, stderr, err := runMCPProxyCommandWithInput(t, args, "")
	if got := strings.Count(stderr, cleanupCapabilityReport); got != 1 {
		t.Fatalf("cleanup reports = %d, want 1; launch error: %v\nstderr:\n%s", got, err, stderr)
	}
	startedAt := strings.Index(stderr, cleanupSandboxInitStarted)
	if startedAt < 0 {
		if err == nil || !strings.Contains(err.Error(), "starting sandboxed MCP server") {
			t.Fatalf("sandbox-init helper did not start or report a launch refusal: %v\nstderr:\n%s", err, stderr)
		}
		t.Logf("host refused the child; startup report was still emitted: %v", err)
	} else if strings.Index(stderr, cleanupCapabilityReport) > startedAt {
		t.Fatalf("cleanup reported after sandbox-init began:\n%s", stderr)
	}
	if strings.Contains(stdout, cleanupCapabilityReport) || (err == nil && stdout != "") {
		t.Fatalf("startup diagnostics leaked to protocol stdout: %q", stdout)
	}
}
