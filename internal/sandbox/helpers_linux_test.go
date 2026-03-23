// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestSummary_AllUnavailable(t *testing.T) {
	c := Capabilities{} // all zero/false
	s := c.Summary()
	if !contains(s, "Landlock: unavailable") {
		t.Errorf("expected Landlock unavailable, got: %s", s)
	}
	if !contains(s, "user namespaces: unavailable") {
		t.Errorf("expected userns unavailable, got: %s", s)
	}
	if !contains(s, "seccomp: unavailable") {
		t.Errorf("expected seccomp unavailable, got: %s", s)
	}
}

func TestSummary_AllAvailable(t *testing.T) {
	c := Capabilities{LandlockABI: 7, UserNamespaces: true, Seccomp: true}
	s := c.Summary()
	if !contains(s, "Landlock ABI v7") {
		t.Errorf("expected Landlock ABI v7, got: %s", s)
	}
	if !contains(s, "user namespaces: available") {
		t.Errorf("expected userns available, got: %s", s)
	}
	if !contains(s, "seccomp: available") {
		t.Errorf("expected seccomp available, got: %s", s)
	}
}

func TestCleanupSandboxCmd_WithProcess(t *testing.T) {
	// Create a short-lived process so we have a real PID.
	ctx := t.Context()
	cmd := exec.CommandContext(ctx, "true")
	if startErr := cmd.Start(); startErr != nil {
		t.Fatal(startErr)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()

	// Create the PID-based temp dir that Linux cleanup expects.
	pidDir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", pid)
	if mkErr := os.MkdirAll(pidDir, 0o750); mkErr != nil {
		t.Fatal(mkErr)
	}

	CleanupSandboxCmd(cmd)

	// Verify the PID-based dir was cleaned up.
	if _, statErr := os.Stat(pidDir); statErr == nil {
		_ = os.RemoveAll(pidDir)
		t.Error("expected PID-based sandbox dir to be cleaned up")
	}
}
