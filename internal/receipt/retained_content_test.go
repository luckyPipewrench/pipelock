// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A policy hash Pipelock computes from its configuration is a generated
// digest. A rule pattern that happens to match it must refuse neither
// activation, nor reload, nor any receipt; a chosen value with the same
// spelling is still content.
func TestComputedPolicyHashIsNeverDetectorInput(t *testing.T) {
	computed := config.Defaults().CanonicalPolicyHash()
	chosen := strings.Repeat("cd34", 16)
	f := newBoundaryFixture(t, computed, chosen)
	if f.sc.ScanTextForDLP(context.Background(), computed).Clean {
		t.Fatal("precondition: the detector must match the computed hash text")
	}
	for _, hash := range []string{computed, "sha256:" + computed} {
		if err := f.em.ValidateConfigHash(hash); err != nil {
			t.Fatalf("computed hash %q refused at reload: %v", hash[:12], err)
		}
	}
	if err := f.em.ValidateConfigHash(chosen); !errors.Is(err, ErrRetainedContent) || strings.Contains(err.Error(), chosen) {
		t.Fatalf("chosen hash err = %v, want a refusal that does not echo it", err)
	}
	f.em.UpdateConfigHash(computed)
	if err := f.em.Emit(baseOpts()); err != nil {
		t.Fatalf("receipt with the computed hash refused: %v", err)
	}
	em := NewEmitter(EmitterConfig{Recorder: f.rec, PrivKey: f.key, ConfigHash: computed, Principal: testPrincipal, Actor: testActor, Session: "computed-hash"})
	if em.InitError() != nil {
		t.Fatalf("activation with the computed hash: %v", em.InitError())
	}
	rs := f.receipts(t)
	if len(rs) != 1 || rs[0].ActionRecord.PolicyHash != computed {
		t.Fatalf("receipts = %d, policy hash kept intact = %t", len(rs), len(rs) == 1 && rs[0].ActionRecord.PolicyHash == computed)
	}
}

func TestReceiptShardActivationValidatesPolicyHashFirst(t *testing.T) {
	chosen := strings.Repeat("ef56", 16)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "chosen_hash", Value: chosen}}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	_, key := generateTestKey(t)
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true, Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := PrepareInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = set.Activate(chosen)
	if !errors.Is(err, ErrRetainedContent) || !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), "policy_hash") {
		t.Fatalf("activation err = %v, want a retained-content refusal naming policy_hash", err)
	}
	if got := set.Admit(EmitOpts{}); got.ShardSelected {
		t.Fatal("a refused activation admitted traffic")
	}
	if err := set.Activate(testConfigHash); err != nil {
		t.Fatalf("clean activation after a refusal: %v", err)
	}
}
