// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoverConfigPath_PipelockConfigEnvWins exercises the highest-priority
// candidate so an operator override always beats the standard locations.
func TestDiscoverConfigPath_PipelockConfigEnvWins(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(override, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", override)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/dev/null")

	got := discoverConfigPath(filepath.Join(t.TempDir(), "system.yaml"))
	if got != override {
		t.Errorf("PIPELOCK_CONFIG override not honored: got %q, want %q", got, override)
	}
}

// TestDiscoverConfigPath_PipelockConfigEnvReturnsAbsolute prevents IDE
// wrappers from persisting a relative --config path that later resolves
// against the IDE's working directory rather than the install-time directory.
func TestDiscoverConfigPath_PipelockConfigEnvReturnsAbsolute(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("relative.yaml", []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "relative.yaml")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/dev/null")

	want := filepath.Join(dir, "relative.yaml")
	got := discoverConfigPath(filepath.Join(t.TempDir(), "system.yaml"))
	if got != want {
		t.Errorf("relative PIPELOCK_CONFIG not made absolute: got %q, want %q", got, want)
	}
}

// TestDiscoverConfigPath_XDGFallback exercises the XDG_CONFIG_HOME branch
// when no operator override is set.
func TestDiscoverConfigPath_XDGFallback(t *testing.T) {
	dir := t.TempDir()
	xdgDir := filepath.Join(dir, "xdg")
	pipelockDir := filepath.Join(xdgDir, "pipelock")
	if err := os.MkdirAll(pipelockDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(pipelockDir, "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", xdgDir)
	t.Setenv("HOME", "/dev/null")

	got := discoverConfigPath(filepath.Join(t.TempDir(), "system.yaml"))
	if got != cfg {
		t.Errorf("XDG fallback not honored: got %q, want %q", got, cfg)
	}
}

// TestDiscoverConfigPath_HomeFallback exercises the legacy ~/.config branch.
func TestDiscoverConfigPath_HomeFallback(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "pipelock")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	got := discoverConfigPath(filepath.Join(t.TempDir(), "system.yaml"))
	if got != cfg {
		t.Errorf("HOME fallback not honored: got %q, want %q", got, cfg)
	}
}

// TestDiscoverConfigPath_NoMatch returns the empty string when every
// candidate is absent rather than guessing or returning an arbitrary
// nonexistent path the caller cannot use.
func TestDiscoverConfigPath_NoMatch(t *testing.T) {
	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	got := discoverConfigPath(filepath.Join(t.TempDir(), "system.yaml"))
	if got != "" {
		t.Errorf("expected empty string when no candidate exists, got %q", got)
	}
}

// TestDiscoverConfigPath_NonRegularRejected ensures that a directory at the
// candidate path does not get returned as a config file.
func TestDiscoverConfigPath_NonRegularRejected(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "pipelock")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Create a DIRECTORY at the expected pipelock.yaml path.
	if err := os.MkdirAll(filepath.Join(dir, "pipelock.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	got := discoverConfigPath(filepath.Join(t.TempDir(), "system.yaml"))
	if got != "" {
		t.Errorf("non-regular candidate must not be returned, got %q", got)
	}
}
