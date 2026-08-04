//go:build !enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func TestGuardCommandRegisteredInCoreBuild(t *testing.T) {
	cmd := rootCmd()
	found, _, err := cmd.Find([]string{"guard", "explain"})
	if err != nil || found == nil || found.Name() != "explain" {
		t.Fatalf("guard explain command not registered: found=%v err=%v", found, err)
	}
}

func TestEnterpriseCommandsAbsentInCoreBuild(t *testing.T) {
	saved := extraCommands
	extraCommands = nil
	t.Cleanup(func() { extraCommands = saved })

	cmd := rootCmd()
	for _, name := range []string{"conductor", "fleet-sink"} {
		if found, _, err := cmd.Find([]string{name}); err == nil && found != nil && found.Name() == name {
			t.Fatalf("core build registered enterprise command %q", name)
		}
	}
}
