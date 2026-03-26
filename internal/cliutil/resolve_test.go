// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestResolveAgentName_InvalidName(t *testing.T) {
	// Ensure PIPELOCK_AGENT env var is clear.
	t.Setenv("PIPELOCK_AGENT", "")

	// Test with explicitly empty name (no flag, no env).
	_, err := ResolveAgentName("")
	if err == nil {
		t.Fatal("expected error for empty agent name")
	}
	if !strings.Contains(err.Error(), "agent name required") {
		t.Errorf("expected 'agent name required' error, got: %v", err)
	}
}

func TestResolveKeystoreDir_ExplicitPath(t *testing.T) {
	dir := t.TempDir()

	result, err := ResolveKeystoreDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != dir {
		t.Errorf("expected %q, got %q", dir, result)
	}
}

func TestResolveKeystoreDir_Default(t *testing.T) {
	// When no explicit dir is given, it should use the default path.
	t.Setenv("PIPELOCK_HOME", "")
	old := PipelockHome
	PipelockHome = ""
	t.Cleanup(func() { PipelockHome = old })

	result, err := ResolveKeystoreDir("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, wantErr := signing.DefaultKeystorePath()
	if wantErr != nil {
		t.Fatalf("DefaultKeystorePath: %v", wantErr)
	}
	if result != want {
		t.Errorf("got %q, want default %q", result, want)
	}
}

func TestResolveKeystoreDir_HomeFlagOverridesDefault(t *testing.T) {
	homeDir := t.TempDir()
	old := PipelockHome
	PipelockHome = homeDir
	t.Cleanup(func() { PipelockHome = old })

	result, err := ResolveKeystoreDir("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != homeDir {
		t.Errorf("expected --home value %q, got %q", homeDir, result)
	}
}

func TestResolveKeystoreDir_EnvFallback(t *testing.T) {
	homeDir := t.TempDir()
	old := PipelockHome
	PipelockHome = ""
	t.Cleanup(func() { PipelockHome = old })
	t.Setenv("PIPELOCK_HOME", homeDir)

	result, err := ResolveKeystoreDir("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != homeDir {
		t.Errorf("expected PIPELOCK_HOME %q, got %q", homeDir, result)
	}
}

func TestResolveAgentName_ValidEnvVar(t *testing.T) {
	t.Setenv("PIPELOCK_AGENT", "my-agent")

	name, err := ResolveAgentName("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "my-agent" {
		t.Errorf("expected 'my-agent', got %q", name)
	}
}

func TestResolveAgentName_FlagOverridesEnv(t *testing.T) {
	t.Setenv("PIPELOCK_AGENT", "env-agent")

	name, err := ResolveAgentName("flag-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "flag-agent" {
		t.Errorf("expected 'flag-agent', got %q", name)
	}
}
