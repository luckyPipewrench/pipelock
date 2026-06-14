// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultCommandRunner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX 'echo'")
	}
	// Resolve a real, harmless command.
	echo, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("no echo on PATH")
	}
	out, err := defaultCommandRunner(context.Background(), echo, "hello-runner")
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	if !strings.Contains(string(out), "hello-runner") {
		t.Fatalf("output = %q", out)
	}
}

func TestDefaultCommandRunner_Error(t *testing.T) {
	_, err := defaultCommandRunner(context.Background(), "/nonexistent/binary/xyzzy")
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}
