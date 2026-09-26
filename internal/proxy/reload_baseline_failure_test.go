// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReloadBaselineReconfigureFailureKeepsCurrentConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SessionProfiling.Enabled = true
	cfg.BehavioralBaseline.Enabled = true
	cfg.BehavioralBaseline.ProfileDir = t.TempDir()
	cfg.BehavioralBaseline.DeviationAction = config.ActionBlock
	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)
	before := p.sessionMgrPtr.Load().BaselineManager()

	blockedDir := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(filepath.Clean(blockedDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	next := *cfg
	next.BehavioralBaseline.ProfileDir = blockedDir
	next.BehavioralBaseline.DeviationAction = config.ActionWarn
	next.Mode = config.ModeStrict
	if p.Reload(&next, scanner.MustNew(&next)) {
		t.Fatal("reload succeeded despite invalid baseline profile directory")
	}
	if p.CurrentConfig() != cfg {
		t.Fatal("failed reload published the new config")
	}
	if got := p.CurrentConfig().BehavioralBaseline.DeviationAction; got != config.ActionBlock {
		t.Fatalf("live baseline action = %q, want %q", got, config.ActionBlock)
	}
	if p.sessionMgrPtr.Load().BaselineManager() != before {
		t.Fatal("failed reload replaced the baseline manager")
	}
}
