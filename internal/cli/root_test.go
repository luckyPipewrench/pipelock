// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestRegisterCommand(t *testing.T) {
	// Save and restore global state.
	saved := extraCommands
	extraCommands = nil
	t.Cleanup(func() { extraCommands = saved })

	// Register a test command.
	RegisterCommand(&cobra.Command{Use: "test-cmd", Short: "test"})

	if len(extraCommands) != 1 {
		t.Fatalf("expected 1 registered command, got %d", len(extraCommands))
	}
	if extraCommands[0].Use != "test-cmd" {
		t.Errorf("command.Use = %q, want %q", extraCommands[0].Use, "test-cmd")
	}

	// Verify rootCmd picks up extra commands.
	cmd := rootCmd()
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "test-cmd" {
			found = true
			break
		}
	}
	if !found {
		t.Error("registered command not found in rootCmd subcommands")
	}
}
