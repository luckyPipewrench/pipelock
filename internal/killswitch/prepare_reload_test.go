// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareReloadWatchesCandidateAndCurrentSources(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old")
	newPath := filepath.Join(dir, "new")
	oldCfg := testConfig()
	oldCfg.KillSwitch.SentinelFile = oldPath
	newCfg := testConfig()
	newCfg.KillSwitch.SentinelFile = newPath

	c := New(oldCfg)
	c.PrepareReload(newCfg)
	if c.IsActive() {
		t.Fatal("active with neither sentinel present")
	}
	gen := c.DeferredGeneration()
	if err := os.WriteFile(newPath, nil, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if d := c.IsActiveMCP(nil); !d.Active || d.Source != "sentinel" {
		t.Fatalf("candidate sentinel ignored: %+v", d)
	}
	if _, ok := c.ClaimDeferredSendAt(gen); ok {
		t.Fatal("deferred send claimed after candidate sentinel appeared")
	}
	c.AbortReload()
	if c.IsActive() {
		t.Fatal("aborted candidate still honored")
	}

	enabled := testConfig()
	enabled.KillSwitch.Enabled = true
	c.PrepareReload(enabled)
	if !c.IsActive() {
		t.Fatal("candidate enabled flag ignored")
	}
	c.Reload(newCfg)
	if !c.IsActive() {
		t.Fatal("live candidate sentinel not honored after Reload")
	}
	if err := os.Remove(newPath); err != nil {
		t.Fatalf("remove sentinel: %v", err)
	}
	if c.IsActive() {
		t.Fatal("pending candidate survived Reload")
	}
}
