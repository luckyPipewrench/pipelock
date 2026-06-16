// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestConfigureContainedCommandRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root path depends on host user database")
	}

	err := configureContainedCommand(exec.CommandContext(t.Context(), "true"), defaultContainedAgentUser)
	if err == nil {
		t.Fatal("expected non-root contained command configuration to fail")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("error = %v, want root requirement", err)
	}
}
