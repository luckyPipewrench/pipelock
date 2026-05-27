// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestPluginHookSignatures_AcceptHermesKwargs is the signature regression guard.
// It extracts the shipped plugin template and drives every registered hook the
// way Hermes' real dispatcher does -- cb(**kwargs) -- with the verified kwarg
// set from hermes_agent 0.13.0/0.14.0 (see testdata/plugin_signature_harness.py).
//
// This is the unit-level backstop for the most dangerous failure mode: Hermes
// swallows a hook TypeError and proceeds UNSCANNED (fail-open). If a hook
// signature ever stops accepting what Hermes passes, the harness exits non-zero
// and this test fails. The live-Hermes e2e is the durable guard against
// upstream renames; this proves our side of the contract on every CI run.
func TestPluginHookSignatures_AcceptHermesKwargs(t *testing.T) {
	t.Parallel()

	python, err := exec.LookPath("python3")
	if err != nil {
		// The signature contract must be enforced in CI. GitHub Actions sets
		// CI=true and ships python3 on every runner, so a missing interpreter
		// there is a misconfiguration we want to fail on, not skip past.
		if os.Getenv("CI") != "" {
			t.Fatalf("python3 not found but CI is set: the hook signature regression test must run in CI: %v", err)
		}
		t.Skipf("python3 not available; signature regression test requires python3: %v", err)
	}

	// Extract the shipped template so the harness drives the bytes that actually
	// install, not a hand-written copy.
	root := t.TempDir()
	if _, err := Install(PluginTarget{Root: root}); err != nil {
		t.Fatalf("install plugin template: %v", err)
	}

	harness, err := filepath.Abs(filepath.Join("testdata", "plugin_signature_harness.py"))
	if err != nil {
		t.Fatalf("resolve harness path: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//nolint:gosec // G204: args are the LookPath-resolved python3, a fixed
	// in-repo testdata harness, and a t.TempDir() install root — no external input.
	cmd := exec.CommandContext(ctx, python, harness, root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hook signature harness failed (a hook rejected Hermes' kwargs -> Hermes would swallow the TypeError and skip the scan):\n%s\nerror: %v", out, err)
	}
}
