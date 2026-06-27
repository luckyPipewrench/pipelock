// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestRunCmd_UnsupportedPlatformBeforeRootCheck(t *testing.T) {
	cmd := runCmd()
	cmd.SetArgs([]string{"claude"})
	cmd.SetIn(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected unsupported-platform error")
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "contain run is supported only on Linux") {
		t.Fatalf("error = %v, want unsupported-platform error", err)
	}
	if strings.Contains(err.Error(), "must be run as root") {
		t.Fatalf("unsupported platform must not be masked by root check: %v", err)
	}
}
