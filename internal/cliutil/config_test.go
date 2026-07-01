// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

func TestDiscoverConfigPath_ExportedWrapper(t *testing.T) {
	xdg := t.TempDir()
	dir := filepath.Join(xdg, "pipelock")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())

	if got := DiscoverConfigPath(); got != cfg {
		t.Fatalf("DiscoverConfigPath() = %q, want %q", got, cfg)
	}
}

func TestDiscoverConfigPathStrict_ExportedWrapper(t *testing.T) {
	xdg := t.TempDir()
	dir := filepath.Join(xdg, "pipelock")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())

	got, err := DiscoverConfigPathStrict()
	if err != nil {
		t.Fatalf("DiscoverConfigPathStrict: %v", err)
	}
	if got != cfg {
		t.Fatalf("DiscoverConfigPathStrict() = %q, want %q", got, cfg)
	}
}

func TestResolveConfigForInstall_ExplicitSecureConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveConfigForInstall(cfg)
	if err != nil {
		t.Fatalf("ResolveConfigForInstall: %v", err)
	}
	if resolved.Path != cfg {
		t.Fatalf("Path = %q, want %q", resolved.Path, cfg)
	}
	if resolved.Source != "explicit --config" || !resolved.Explicit {
		t.Fatalf("unexpected resolution metadata: %#v", resolved)
	}
}

func TestResolveConfigForInstall_RejectsMalformedExplicitConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveConfigForInstall(cfg); err == nil {
		t.Fatal("expected malformed explicit config to be rejected")
	}
}

func TestResolveConfigForInstall_RejectsUnsafeExplicitConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeMode := os.FileMode(0o600 | 0o020)
	if err := os.Chmod(cfg, unsafeMode); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveConfigForInstall(cfg); err == nil {
		t.Fatal("expected unsafe explicit config to be rejected")
	}
}

func TestResolveConfigForInstall_AutoDiscoversEnvConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", cfg)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	resolved, err := ResolveConfigForInstall("")
	if err != nil {
		t.Fatalf("ResolveConfigForInstall: %v", err)
	}
	if resolved.Path != cfg {
		t.Fatalf("Path = %q, want %q", resolved.Path, cfg)
	}
	if resolved.Source != "auto-discovered" || resolved.Explicit {
		t.Fatalf("unexpected resolution metadata: %#v", resolved)
	}
}

func TestResolveConfigForInstall_RejectsMalformedDiscoveredConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", cfg)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	if _, err := ResolveConfigForInstall(""); err == nil {
		t.Fatal("expected malformed discovered config to be rejected")
	}
}

func TestResolveConfigForInstall_IgnoresCWDConfig(t *testing.T) {
	oldSystem := defaultSystemConfigPath
	defaultSystemConfigPath = filepath.Join(t.TempDir(), "missing-system.yaml")
	t.Cleanup(func() { defaultSystemConfigPath = oldSystem })

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
	if err := os.WriteFile("pipelock.yaml", []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	resolved, err := ResolveConfigForInstall("")
	if err != nil {
		t.Fatalf("ResolveConfigForInstall: %v", err)
	}
	if resolved.Path != "" || resolved.Source != "built-in defaults" {
		t.Fatalf("cwd-local config must not be discovered for installs: %#v", resolved)
	}
}

func TestWriteInstallConfigProvenance(t *testing.T) {
	t.Run("path", func(t *testing.T) {
		var out bytes.Buffer
		WriteInstallConfigProvenance(&out, "cursor install", InstallConfigResolution{
			Path:   "/secure/pipelock.yaml",
			Source: "auto-discovered",
		}, false)

		got := out.String()
		if !strings.Contains(got, "cursor install") || !strings.Contains(got, "/secure/pipelock.yaml") {
			t.Fatalf("provenance output missing install surface/path: %q", got)
		}
	})

	t.Run("built in defaults", func(t *testing.T) {
		var out bytes.Buffer
		WriteInstallConfigProvenance(&out, "git install-hooks", InstallConfigResolution{
			Source: "built-in defaults",
		}, false)

		got := out.String()
		if !strings.Contains(got, "git install-hooks") || !strings.Contains(got, "built-in defaults") {
			t.Fatalf("provenance output missing built-in defaults warning: %q", got)
		}
		if !strings.Contains(got, "reinstalled with --config") {
			t.Fatalf("provenance output missing reinstall guidance: %q", got)
		}
	})

	t.Run("quiet", func(t *testing.T) {
		var out bytes.Buffer
		WriteInstallConfigProvenance(&out, "cursor install", InstallConfigResolution{
			Path:   "/secure/pipelock.yaml",
			Source: "explicit --config",
		}, true)
		WriteInstallConfigProvenance(nil, "cursor install", InstallConfigResolution{
			Path:   "/secure/pipelock.yaml",
			Source: "explicit --config",
		}, false)

		if out.Len() != 0 {
			t.Fatalf("quiet provenance wrote output: %q", out.String())
		}
	})
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

func TestDiscoverConfigPath_GroupOrWorldWritableRejected(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "pipelock")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	groupWritable := os.FileMode(0o620)
	if err := os.Chmod(cfg, groupWritable); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	got := discoverConfigPath(filepath.Join(t.TempDir(), "system.yaml"))
	if got != "" {
		t.Errorf("group-writable candidate must not be returned, got %q", got)
	}
}

func TestDiscoverConfigPathStrict_UnsafeCandidateErrors(t *testing.T) {
	xdg := t.TempDir()
	xdgDir := filepath.Join(xdg, "pipelock")
	if err := os.MkdirAll(xdgDir, 0o750); err != nil {
		t.Fatal(err)
	}
	unsafeCfg := filepath.Join(xdgDir, "pipelock.yaml")
	if err := os.WriteFile(unsafeCfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeMode := os.FileMode(0o600 | 0o020)
	if err := os.Chmod(unsafeCfg, unsafeMode); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	homeDir := filepath.Join(home, ".config", "pipelock")
	if err := os.MkdirAll(homeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	homeCfg := filepath.Join(homeDir, "pipelock.yaml")
	if err := os.WriteFile(homeCfg, []byte("mode: permissive\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", home)

	got, err := discoverConfigPathStrict(filepath.Join(t.TempDir(), "system.yaml"))
	if err == nil {
		t.Fatal("expected unsafe higher-priority candidate to error")
	}
	if got != "" {
		t.Fatalf("strict discovery should not fall through after unsafe candidate, got %q", got)
	}
}

func TestDiscoverConfigPathStrict_NonRegularCandidateErrors(t *testing.T) {
	xdg := t.TempDir()
	xdgDir := filepath.Join(xdg, "pipelock")
	if err := os.MkdirAll(xdgDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(xdgDir, "pipelock.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	homeDir := filepath.Join(home, ".config", "pipelock")
	if err := os.MkdirAll(homeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	homeCfg := filepath.Join(homeDir, "pipelock.yaml")
	if err := os.WriteFile(homeCfg, []byte("mode: permissive\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", home)

	got, err := discoverConfigPathStrict(filepath.Join(t.TempDir(), "system.yaml"))
	if err == nil {
		t.Fatal("expected non-regular higher-priority candidate to error")
	}
	if got != "" {
		t.Fatalf("strict discovery should not fall through after non-regular candidate, got %q", got)
	}
}

func TestConfigPathIsSecure_OwnUserAccepted(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigPathIsSecure(cfg); err != nil {
		t.Fatalf("own-user 0600 config should be secure: %v", err)
	}
}

func TestConfigPathIsSecure_GroupOrWorldWritableRejected(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []os.FileMode{0o620, 0o602} {
		if err := os.Chmod(cfg, mode); err != nil {
			t.Fatal(err)
		}
		if err := ConfigPathIsSecure(cfg); err == nil {
			t.Fatalf("mode %04o config should be rejected", mode)
		}
	}
}

func TestConfigPathIsSecure_MissingRejected(t *testing.T) {
	if err := ConfigPathIsSecure(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing config should be rejected")
	}
}

func TestConfigPathIsSecure_NonRegularRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := ConfigPathIsSecure(dir); err == nil {
		t.Fatal("directory config path should be rejected")
	}
}

func TestConfigOwnershipSecure(t *testing.T) {
	euid := currentEUID()
	otherUID := euid + 1
	if otherUID == 0 {
		otherUID = 12345
	}

	tests := []struct {
		name     string
		ownerUID int
		want     bool
	}{
		{name: "root owner accepted", ownerUID: 0, want: true},
		{name: "effective user owner accepted", ownerUID: euid, want: true},
		{name: "other user owner rejected", ownerUID: otherUID, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := configOwnershipSecure(tc.ownerUID, euid)
			if got != tc.want {
				t.Fatalf("configOwnershipSecure(%d, %d) = %v, want %v", tc.ownerUID, euid, got, tc.want)
			}
		})
	}
}

func TestConfigOwnershipSecure_PipelockProxyAcceptedWhenPresent(t *testing.T) {
	u, err := user.Lookup("pipelock-proxy")
	if err != nil {
		t.Skip("pipelock-proxy user is not present")
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("parse pipelock-proxy uid %q: %v", u.Uid, err)
	}
	if !configOwnershipSecure(uid, currentEUID()) {
		t.Fatalf("pipelock-proxy-owned config should be trusted")
	}
}
