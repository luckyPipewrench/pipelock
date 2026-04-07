// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestProxy_Accessors(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := scanner.New(cfg)
	m := metrics.New()

	p, err := New(cfg, nil, sc, m)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Run("SessionMgrPtr", func(t *testing.T) {
		ptr := p.SessionMgrPtr()
		if ptr == nil {
			t.Error("SessionMgrPtr() returned nil")
		}
	})

	t.Run("EntropyTrackerPtr", func(t *testing.T) {
		ptr := p.EntropyTrackerPtr()
		if ptr == nil {
			t.Error("EntropyTrackerPtr() returned nil")
		}
	})

	t.Run("FragmentBufferPtr", func(t *testing.T) {
		ptr := p.FragmentBufferPtr()
		if ptr == nil {
			t.Error("FragmentBufferPtr() returned nil")
		}
	})
}

func TestSessionManager_SessionExists(t *testing.T) {
	t.Parallel()

	sm := NewSessionManager(&config.SessionProfiling{Enabled: true}, nil, metrics.New())

	if sm.SessionExists("nonexistent") {
		t.Error("expected false for nonexistent session")
	}

	// Create a session.
	sm.GetOrCreate("test-session")

	if !sm.SessionExists("test-session") {
		t.Error("expected true after creating session")
	}

	if sm.SessionExists("other-session") {
		t.Error("expected false for different key")
	}
}
