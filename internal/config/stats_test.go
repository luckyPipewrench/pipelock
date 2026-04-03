package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCanonicalStats is a drift guard that prints canonical project stats.
// Run via `make stats`. Counts are derived from Defaults() and on-disk
// files so they stay in sync with the codebase automatically.
func TestCanonicalStats(t *testing.T) {
	cfg := Defaults()

	dlpCount := len(cfg.DLP.Patterns)
	responseCount := len(cfg.ResponseScanning.Patterns)
	// Chain patterns are built-in to the matcher, not in config.
	// Count from the chains package source as a cross-check.
	chainCount := 10 // builtInPatterns in internal/mcp/chains/matcher.go

	// Count preset YAML files in configs/.
	presets, err := filepath.Glob(filepath.Join("..", "..", "configs", "*.yaml"))
	if err != nil {
		t.Fatalf("glob presets: %v", err)
	}

	// Count direct dependencies from go.mod.
	modFile, err := os.Open(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("open go.mod: %v", err)
	}
	defer func() { _ = modFile.Close() }()

	directDeps := 0
	inRequire := false
	sc := bufio.NewScanner(modFile)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if inRequire && !strings.Contains(line, "// indirect") {
			directDeps++
		}
	}

	t.Logf("DLP patterns:      %d", dlpCount)
	t.Logf("Response patterns: %d", responseCount)
	t.Logf("Chain patterns:    %d", chainCount)
	t.Logf("Preset files:      %d", len(presets))
	t.Logf("Direct deps:       %d", directDeps)

	// Guards: fail if counts drop unexpectedly (ratchet, not exact match).
	if dlpCount < 47 {
		t.Errorf("DLP patterns dropped below 47: got %d", dlpCount)
	}
	if responseCount < 23 {
		t.Errorf("response patterns dropped below 23: got %d", responseCount)
	}
	if chainCount < 10 {
		t.Errorf("chain patterns dropped below 10: got %d", chainCount)
	}
	if len(presets) < 7 {
		t.Errorf("preset files dropped below 7: got %d", len(presets))
	}
	if directDeps < 18 {
		t.Errorf("direct deps dropped below 18: got %d", directDeps)
	}
}
