// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	guardfs "github.com/luckyPipewrench/pipelock/internal/guard"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// A Guard policy hash every receipt carries is retained content: a hit is a
// configuration refusal even when receipts are not required, while a hash
// Pipelock computed is a generated digest that no pattern can refuse.
func TestGuardRetainedPolicyHashIsAConfigurationRefusal(t *testing.T) {
	chosen := strings.Repeat("9a8b", 16)
	newEvidence := func(t *testing.T, canary string) *guardEvidence {
		t.Helper()
		_, key, err := signing.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keyPath := filepath.Join(t.TempDir(), "receipt.key")
		if err := signing.SavePrivateKey(key, keyPath); err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "evidence")
		cfg.FlightRecorder.SigningKeyPath = keyPath
		cfg.FlightRecorder.Redact = true
		cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "guard_hash", Value: canary}}}
		sc, err := scanner.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sc.Close)
		evidence, err := newGuardEvidence(t.Context(), cfg, sc, metrics.New(), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(evidence.close)
		if evidence.emitter == nil || evidence.shards != nil || evidence.require {
			t.Fatal("fixture must be a single-chain Guard whose receipts are not required")
		}
		return evidence
	}

	refused := newEvidence(t, chosen)
	err := refused.activateReceipts(guardfs.ExecutionProof{ConfigPolicyHash: chosen, EffectivePolicyHash: strings.Repeat("b", 64), Binary: "/usr/bin/true"})
	if !errors.Is(err, receipt.ErrRetainedContent) || strings.Contains(err.Error(), chosen) {
		t.Fatalf("activation err = %v, want a retained-content refusal without the value", err)
	}

	computed := config.Defaults().CanonicalPolicyHash()
	accepted := newEvidence(t, computed)
	if err := accepted.activateReceipts(guardfs.ExecutionProof{ConfigPolicyHash: computed, EffectivePolicyHash: strings.Repeat("b", 64), Binary: "/usr/bin/true"}); err != nil {
		t.Fatalf("computed policy hash refused: %v", err)
	}
}
