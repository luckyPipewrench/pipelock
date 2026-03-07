// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"sort"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testProfileClaudeCode = "claude-code"
	testProfileDefault    = "_default"
	testProfileOnlyOne    = "only-one"
	testProfileCursor     = "cursor"
	testListenAddr        = ":8889"
	testListenAddr2       = ":8890"
)

func TestAgentRegistryLookup(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil // no SSRF in tests
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
		testProfileDefault:    {Mode: config.ModeAudit},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// Known profile
	agent := reg.Lookup(testProfileClaudeCode)
	if agent.Name != testProfileClaudeCode {
		t.Errorf("name = %q, want %s", agent.Name, testProfileClaudeCode)
	}
	if agent.Config.Mode != config.ModeStrict {
		t.Errorf("mode = %q, want strict", agent.Config.Mode)
	}

	// Unknown agent -> _default
	agent = reg.Lookup("unknown-agent")
	if agent.Name != testProfileDefault {
		t.Errorf("name = %q, want %s", agent.Name, testProfileDefault)
	}
	if agent.Config.Mode != config.ModeAudit {
		t.Errorf("mode = %q, want audit", agent.Config.Mode)
	}

	// When no _default is configured, fallback uses base config
	cfg2 := config.Defaults()
	cfg2.Internal = nil
	cfg2.Mode = config.ModeBalanced
	cfg2.Agents = map[string]config.AgentProfile{
		testProfileOnlyOne: {Mode: config.ModeStrict},
	}
	reg2, err := NewAgentRegistry(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	fallback := reg2.Lookup("nonexistent")
	if fallback.Config.Mode != config.ModeBalanced {
		t.Errorf("fallback mode = %q, want balanced", fallback.Config.Mode)
	}
}

func TestAgentRegistryPortLookup(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {
			Listeners: []string{testListenAddr},
			Mode:      config.ModeStrict,
		},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	name, ok := reg.ProfileForPort(testListenAddr)
	if !ok {
		t.Fatal("expected port mapping for", testListenAddr)
	}
	if name != testProfileClaudeCode {
		t.Errorf("port profile = %q, want %s", name, testProfileClaudeCode)
	}

	// Unregistered port returns false
	_, ok = reg.ProfileForPort(":9999")
	if ok {
		t.Error("expected no mapping for unregistered port")
	}
}

func TestAgentRegistryNoAgents(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Mode = config.ModeBalanced
	// No agents configured at all
	cfg.Agents = nil

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// Should still produce a valid registry with base fallback
	agent := reg.Lookup("anything")
	if agent.Name != testProfileDefault {
		t.Errorf("name = %q, want %s", agent.Name, testProfileDefault)
	}
	if agent.Config.Mode != config.ModeBalanced {
		t.Errorf("mode = %q, want balanced", agent.Config.Mode)
	}
	if agent.Scanner == nil {
		t.Error("expected non-nil scanner on fallback agent")
	}

	// Profiles() should return empty
	profiles := reg.Profiles()
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d: %v", len(profiles), profiles)
	}
}

func TestAgentRegistryProfiles(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
		testProfileCursor:     {Mode: config.ModeBalanced},
		testProfileDefault:    {Mode: config.ModeAudit},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	profiles := reg.Profiles()
	sort.Strings(profiles)
	expected := []string{testProfileDefault, testProfileClaudeCode, testProfileCursor}
	sort.Strings(expected)

	if len(profiles) != len(expected) {
		t.Fatalf("got %d profiles, want %d", len(profiles), len(expected))
	}
	for i, name := range profiles {
		if name != expected[i] {
			t.Errorf("profiles[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

func TestAgentRegistryMultipleListeners(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {
			Listeners: []string{testListenAddr, testListenAddr2},
			Mode:      config.ModeStrict,
		},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// Both listeners should map to the same profile
	for _, addr := range []string{testListenAddr, testListenAddr2} {
		name, ok := reg.ProfileForPort(addr)
		if !ok {
			t.Fatalf("expected port mapping for %s", addr)
		}
		if name != testProfileClaudeCode {
			t.Errorf("port %s profile = %q, want %s", addr, name, testProfileClaudeCode)
		}
	}
}

func TestAgentRegistryCloseIdempotent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Close should not panic when called multiple times
	reg.Close()
	reg.Close()
}

func TestAgentRegistryFallbackScannerNotNil(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup("anything")
	if agent.Scanner == nil {
		t.Error("expected non-nil scanner on fallback")
	}
	if agent.Config == nil {
		t.Error("expected non-nil config on fallback")
	}
}

func TestAgentRegistryDefaultProfileOverridesFallback(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Mode = config.ModeBalanced
	cfg.Agents = map[string]config.AgentProfile{
		testProfileDefault: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// _default profile should be the fallback, not the base config
	agent := reg.Lookup("nonexistent")
	if agent.Config.Mode != config.ModeStrict {
		t.Errorf("fallback mode = %q, want strict (_default profile should override base)", agent.Config.Mode)
	}
}
