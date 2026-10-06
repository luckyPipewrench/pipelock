// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFilesystemMode(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestContainmentFilesystemMode_LoadStates(t *testing.T) {
	const base = "version: 1\nmode: balanced\n"
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "omitted", body: base, want: ContainmentFilesystemModeOff},
		{name: "null", body: base + "containment:\n  filesystem:\n    mode:\n", want: ContainmentFilesystemModeOff},
		{name: "blank", body: base + "containment:\n  filesystem:\n    mode: \"\"\n", want: ContainmentFilesystemModeOff},
		{name: "off", body: base + "containment:\n  filesystem:\n    mode: off\n", want: ContainmentFilesystemModeOff},
		{name: "enforce", body: base + "containment:\n  filesystem:\n    mode: enforce\n", want: ContainmentFilesystemModeEnforce},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadFilesystemMode(t, tt.body)
			if got := cfg.Containment.Filesystem.EffectiveMode(); got != tt.want {
				t.Fatalf("EffectiveMode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContainmentFilesystemMode_InvalidFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	body := "version: 1\nmode: balanced\ncontainment:\n  filesystem:\n    mode: sometimes\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "containment.filesystem.mode") {
		t.Fatalf("Load err = %v, want filesystem mode refusal", err)
	}
}

func TestContainmentFilesystemMode_ReloadWithChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	off := "version: 1\nmode: balanced\ncontainment:\n  filesystem:\n    mode: off\n"
	if err := os.WriteFile(path, []byte(off), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	if first.Containment.Filesystem.EffectiveMode() != ContainmentFilesystemModeOff {
		t.Fatal("first load should be off")
	}
	on := "version: 1\nmode: balanced\ncontainment:\n  filesystem:\n    mode: enforce\n"
	if err := os.WriteFile(path, []byte(on), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if second.Containment.Filesystem.EffectiveMode() != ContainmentFilesystemModeEnforce {
		t.Fatal("reload with change should observe enforce")
	}
}

func TestContainmentFilesystemMode_ReloadWithoutChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	body := "version: 1\nmode: balanced\ncontainment:\n  filesystem:\n    mode: enforce\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if first.Containment.Filesystem.EffectiveMode() != ContainmentFilesystemModeEnforce || second.Containment.Filesystem.EffectiveMode() != ContainmentFilesystemModeEnforce {
		t.Fatalf("reload without change = %q then %q", first.Containment.Filesystem.EffectiveMode(), second.Containment.Filesystem.EffectiveMode())
	}
}
