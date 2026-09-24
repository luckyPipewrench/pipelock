// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"fmt"
	"os"
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
	if err := os.Setenv("HOME", home); err != nil {
		fmt.Fprintf(os.Stderr, "hermes tests: set HOME: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
