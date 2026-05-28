//go:build !enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

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
