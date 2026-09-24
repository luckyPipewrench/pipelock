// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points HOME at a throwaway directory for the whole package. Install
// and rollback write per-user files (agent-browser defaults) into the resolved
// home, so a test that forgets t.Setenv("HOME", ...) must never reach the
// developer's real home directory.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "pipelock-hermes-test-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "hermes tests: create temp home: %v\n", err)
		os.Exit(1)
	}
	// USERPROFILE is what os.UserHomeDir reads on Windows.
	for _, key := range []string{"HOME", "USERPROFILE"} {
		if err := os.Setenv(key, home); err != nil {
			fmt.Fprintf(os.Stderr, "hermes tests: set %s: %v\n", key, err)
			os.Exit(1)
		}
	}
	// An inherited value would turn verify's "present" into "overridden".
	_ = os.Unsetenv("AGENT_BROWSER_ARGS")
	// The command lock root comes from the account database, not the
	// environment, so point it at the throwaway home for the whole package.
	hermesUserCacheDir = func() (string, error) { return filepath.Join(home, ".cache"), nil }
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
