// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package runtime

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMCPProxyCmdMakesProxyProcessNonDumpable(t *testing.T) {
	if os.Getenv("PIPELOCK_MCP_HARDEN_HELPER") == "1" {
		cmd := mcpProxyCmd()
		cmd.SetIn(bytes.NewReader(nil))
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--", "true"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("mcp proxy: %v", err)
		}
		got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil {
			t.Fatalf("get dumpable: %v", err)
		}
		if got != 0 {
			t.Fatalf("PR_GET_DUMPABLE = %d, want 0", got)
		}
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPProxyCmdMakesProxyProcessNonDumpable$") // #nosec G204 G702 -- test re-execs its own binary with fixed arguments
	child.Env = append(os.Environ(), "PIPELOCK_MCP_HARDEN_HELPER=1")
	out, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("non-dumpable MCP proxy helper: %v\n%s", err, out)
	}
}
