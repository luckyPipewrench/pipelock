// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/rules"
)

// installUnversionedWarningBundle writes an unsigned bundle that declares a
// min_pipelock under $XDG_DATA_HOME/pipelock/rules. A test binary has no
// release stamp, so merging it yields the unprovable-version warning.
func installUnversionedWarningBundle(t *testing.T) {
	t.Helper()
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	bundleYAML := []byte(`format_version: 1
name: hook-warn-bundle
version: "2026.03.1"
author: Test Author
description: A bundle that declares a minimum version
min_pipelock: "0.1.0"
license: Apache-2.0
rules:
  - id: hook-warn-rule
    type: dlp
    status: stable
    name: Hook Warn Rule
    description: Detects a fixture token no other test uses
    severity: high
    confidence: high
    pattern:
      regex: "zz-hook-warning-fixture-[0-9]{6}"
`)
	bundleDir := filepath.Join(dataHome, "pipelock", "rules", "hook-warn-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), bundleYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundleYAML)
	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           "local:/tmp/hook-warn-rules",
		LastCheck:        "2026-03-15T10:00:00Z",
		BundleSHA256:     hex.EncodeToString(sum[:]),
		Unsigned:         true,
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatal(err)
	}
}

func TestHook_PrintsUnverifiableBundleVersionWarning(t *testing.T) {
	installUnversionedWarningBundle(t)

	cmd := hookCmd()
	cmd.SetIn(strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"shell","tool_input":{"command":"ls -la"}}`))
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("ExecuteContext: %v\nstderr:\n%s", err, errOut.String())
	}
	if !strings.Contains(errOut.String(), `warning: bundle "hook-warn-bundle" loaded although min_pipelock`) {
		t.Fatalf("hook did not print the unprovable-version warning to stderr\nstderr:\n%s", errOut.String())
	}
	if strings.Contains(out.String(), "loaded although min_pipelock") {
		t.Fatalf("warning leaked into the stdout decision contract:\n%s", out.String())
	}
}
