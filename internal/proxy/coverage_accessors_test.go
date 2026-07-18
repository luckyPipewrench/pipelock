// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestProxy_Accessors(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := scanner.MustNew(cfg)
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

	t.Run("EnvelopeVerifierPtr", func(t *testing.T) {
		ptr := p.EnvelopeVerifierPtr()
		if ptr == nil {
			t.Error("EnvelopeVerifierPtr() returned nil")
		}
	})

	t.Run("V2EmitterPtr", func(t *testing.T) {
		ptr := p.V2EmitterPtr()
		if ptr == nil {
			t.Error("V2EmitterPtr() returned nil")
		}
	})

	t.Run("ContractLoaderPtr", func(t *testing.T) {
		ptr := p.ContractLoaderPtr()
		if ptr == nil {
			t.Error("ContractLoaderPtr() returned nil")
		}
	})
}

func TestProxy_OptionAndBlockedErrorBranches(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatalf("scanner.New: %v", err)
	}
	t.Cleanup(sc.Close)

	loader := &contractruntime.Loader{}
	receiptEmitter := &receipt.Emitter{}
	v2Emitter := &proxydecision.Emitter{}
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "hash"})

	p, err := New(cfg, nil, sc, metrics.New(),
		WithContractLoader(loader),
		WithReceiptEmitter(receiptEmitter),
		WithV2ReceiptEmitter(v2Emitter),
		WithEnvelopeEmitter(envEmitter),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.ContractLoaderPtr().Load(); got != loader {
		t.Fatalf("ContractLoaderPtr.Load() = %p, want %p", got, loader)
	}
	if got := p.ReceiptEmitterPtr().Load(); got != receiptEmitter {
		t.Fatalf("ReceiptEmitterPtr.Load() = %p, want %p", got, receiptEmitter)
	}
	if got := p.V2EmitterPtr().Load(); got != v2Emitter {
		t.Fatalf("V2EmitterPtr.Load() = %p, want %p", got, v2Emitter)
	}
	if got := p.EnvelopeEmitterPtr().Load(); got != envEmitter {
		t.Fatalf("EnvelopeEmitterPtr.Load() = %p, want %p", got, envEmitter)
	}

	var nilBlocked *blockedRequestError
	if got := nilBlocked.Error(); got != "" {
		t.Fatalf("nil blockedRequestError Error() = %q, want empty", got)
	}
	blocked := newBlockedRequestError("scanner", "blocked", "")
	if blocked.detail != "blocked" {
		t.Fatalf("empty detail should default to reason, got %q", blocked.detail)
	}
	redirect := newRedirectBlockedRequest("", "bad redirect")
	if redirect.layer != "redirect" {
		t.Fatalf("empty redirect layer = %q, want redirect", redirect.layer)
	}
}

func TestSessionManager_SessionExists(t *testing.T) {
	t.Parallel()

	// Non-zero CleanupIntervalSeconds + SessionTTLMinutes are required: with
	// zero values the cleanup goroutine fires time.NewTimer(0) immediately and
	// cutoff=now matches a freshly created session's lastActivity, racing the
	// test. Matches session_taint_test.go:43.
	sm := NewSessionManager(&config.SessionProfiling{
		Enabled:                true,
		MaxSessions:            10,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 60,
	}, nil, metrics.New())
	defer sm.Close()

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
