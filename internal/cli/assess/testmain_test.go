// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the rules directory for assess package tests so they
// don't inherit whatever rule bundles the developer has installed under
// ~/.local/share/pipelock/rules/. Without this, assess's verify-install
// step calls rules.MergeIntoConfig with the user's actual installed
// bundles and fails on any bundle whose min_pipelock requirement exceeds
// the dev-build version constant ("0.0.0-dev.unknown" from cliutil/version.go).
//
// XDG_DATA_HOME must be an absolute path: rules.ResolveRulesDir only
// honors it when filepath.IsAbs returns true (merge.go:21). A relative
// $TMPDIR would silently fall back to $HOME and defeat the isolation.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "pipelock-assess-test-xdg-*")
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
	if err := os.Setenv("PIPELOCK_HOME", filepath.Join(dataHome, "pipelock-home")); err != nil {
		_ = os.RemoveAll(tmp)
		_, _ = fmt.Fprintf(os.Stderr, "TestMain: set PIPELOCK_HOME: %v\n", err)
		os.Exit(1)
	}
	// resolveAssessSigningAgent falls back to PIPELOCK_AGENT before the
	// built-in default, so an ambient value in the developer's shell would
	// silently change which identity these tests sign under.
	if err := os.Unsetenv("PIPELOCK_AGENT"); err != nil {
		_ = os.RemoveAll(tmp)
		_, _ = fmt.Fprintf(os.Stderr, "TestMain: unset PIPELOCK_AGENT: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}
