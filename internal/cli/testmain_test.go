// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the rules directory for the cli package's tests so they
// don't inherit whatever rule bundles the developer has installed under
// ~/.local/share/pipelock/rules/. Without this, tests that exercise
// rules.MergeIntoConfig pick up the operator's installed bundles and fail
// when a bundle's min_pipelock requirement exceeds the dev-build version
// constant ("0.1.0-dev" from cliutil/version.go) — a coupling between the
// test binary and the developer's machine state.
//
// XDG_DATA_HOME must be an absolute path: rules.ResolveRulesDir only
// honors it when filepath.IsAbs returns true (merge.go:21). A relative
// $TMPDIR would silently fall back to $HOME and defeat the isolation.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "pipelock-cli-test-xdg-*")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "TestMain: create temp dir: %v\n", err)
		os.Exit(1)
	}
	dataHome, err := filepath.Abs(tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		_, _ = fmt.Fprintf(os.Stderr, "TestMain: resolve absolute path: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("XDG_DATA_HOME", dataHome); err != nil {
		_ = os.RemoveAll(tmp)
		_, _ = fmt.Fprintf(os.Stderr, "TestMain: set XDG_DATA_HOME: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}
