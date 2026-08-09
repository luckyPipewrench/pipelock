// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// The detector reads the whole file before choosing a route, so an unreadable
// file must be refused rather than falling through to the other route. The
// assertion depends on Unix permission semantics, and root bypasses them, so
// both conditions are checked rather than assumed.
func TestChainRefusesUnreadableBareV1JSONL(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permission bits, so an unreadable fixture cannot be built")
	}
	fixture := newCompletenessFixture(t)
	path := writeCompletenessJSONL(t, []receipt.Receipt{
		fixture.open("run-unreadable", "open-unreadable"),
		fixture.close("run-unreadable", "open-unreadable"),
	})
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(filepath.Clean(path)); err == nil {
		t.Skip("fixture remained readable after chmod, so the permission path cannot be exercised")
	}

	stdout, stderr, code := runRoot(t, "chain", "--json", "--key", fixture.keyHex, path)
	if code == cliutil.ExitOK {
		t.Fatalf("unreadable evidence file accepted: stdout=%q stderr=%q", stdout, stderr)
	}
}
