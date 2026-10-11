// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestClientFragmentsRemainCandidates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*EmitOpts)
	}{
		{"reversed target and method", func(o *EmitOpts) { o.Target = boundaryCanary[:11]; o.Method = boundaryCanary[11:] }},
		{"agent override and target", func(o *EmitOpts) { o.Agent = boundaryCanary[11:]; o.Target = boundaryCanary[:11] }},
		{"nonconstant transport and method", func(o *EmitOpts) { o.Transport = boundaryCanary[:11]; o.Method = boundaryCanary[11:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoundaryFixture(t)
			o := baseOpts()
			tc.mutate(&o)
			if err := f.em.Emit(o); !errors.Is(err, receiptcontent.ErrRejected) {
				t.Fatalf("client-controlled split accepted: %v", err)
			}
			if err := f.em.Emit(baseOpts()); err != nil {
				t.Fatal(err)
			}
			if len(f.receipts(t)) != 1 {
				t.Fatal("refusal advanced or poisoned the receipt chain")
			}
		})
	}
}

func TestActionReceiptFragmentCandidates(t *testing.T) {
	f := newBoundaryFixture(t)
	raw, err := json.Marshal(Receipt{Version: ReceiptVersion, ActionRecord: f.em.contentRecord(baseOpts(), ActionRead, SideEffectExternalRead, ReversibilityFull, testConfigHash)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.em.contentProducer().Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	var candidates []string
	for _, a := range p.Atoms() {
		if !a.Fixed {
			candidates = append(candidates, a.Field)
		}
	}
	if len(candidates) != 3 {
		t.Fatalf("candidates = %v, want method, policy_hash override and target", candidates)
	}
}

func TestActionReceiptDetectorCallBudget(t *testing.T) {
	f := newBoundaryFixture(t)
	for _, tc := range []struct {
		name     string
		opts     EmitOpts
		maxCalls int
	}{
		{"plain GET", baseOpts(), 200},
		{"block GET", EmitOpts{ActionID: NewActionID(), Target: testTarget, Verdict: "block", Transport: testTransport, Method: "GET", Layer: "dlp", Pattern: "credential"}, 700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(Receipt{Version: ReceiptVersion, ActionRecord: f.em.contentRecord(tc.opts, ActionRead, SideEffectExternalRead, ReversibilityFull, testConfigHash)})
			if err != nil {
				t.Fatal(err)
			}
			p, err := f.em.contentProducer().Project(raw)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			det := func(ctx context.Context, text string) scanner.TextDLPResult {
				calls++
				return f.sc.ScanTextForDLPQuiet(ctx, text)
			}
			rep, err := receiptcontent.Scan(t.Context(), det, p)
			if err != nil || !rep.Clean() || calls > tc.maxCalls {
				t.Fatalf("calls=%d, max=%d: %+v %v", calls, tc.maxCalls, rep, err)
			}
			t.Logf("%d detector calls", calls)
		})
	}
}

// TestSplitAroundFixedReceiptValueIsReassembled drives the detector a
// deployment runs, with the principal and actor the runtime configures. An
// environment secret that contains a receipt's own fixed word ("localhost"
// holds the principal "local") is split into a client method and a client
// target. Neither piece, nor the two together, reaches the detector's
// partial-match length, so only the receipt's own word completes it. Each
// piece is 12 bytes and the detector matches 16-byte runs of a known secret.
func TestSplitAroundFixedReceiptValueIsReassembled(t *testing.T) {
	const left, right = "Xk9mQ2vL7pR4", "Bn6Yc3Zd5Qa8"
	for _, tc := range []struct {
		name   string
		bridge string
		opts   func(*EmitOpts)
	}{
		{"principal", "local", func(*EmitOpts) {}},
		{"actor", "pipelock", func(*EmitOpts) {}},
		{"transport label", "proxy", func(o *EmitOpts) { o.Transport = "proxy" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := left + tc.bridge + right
			t.Setenv("PIPELOCK_FRAGMENT_TEST_SECRET", secret)
			key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = true
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			for label, text := range map[string]string{"left": left, "right": right, "client pieces together": left + right} {
				if !sc.ScanTextForDLPQuiet(t.Context(), text).Clean {
					t.Fatalf("precondition: %s alone matches the detector", label)
				}
			}
			if sc.ScanTextForDLPQuiet(t.Context(), secret).Clean {
				t.Fatal("precondition: the detector does not know the whole secret")
			}
			rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: "local", Actor: "pipelock"})
			if em == nil || em.InitError() != nil {
				t.Fatalf("emitter: %v", em.InitError())
			}
			o := baseOpts()
			tc.opts(&o)
			// Filler between the pieces keeps them apart in the joined-values
			// view, so only the fragment view can reassemble the split.
			o.Layer, o.Pattern, o.Severity = "L", "P", "S"
			o.Method, o.Target = left, right
			if err := em.Emit(o); !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), "Environment Variable Leak") {
				t.Fatalf("secret split around the receipt's own %q accepted or misreported: %v", tc.bridge, err)
			}
			if err := em.Emit(baseOpts()); err != nil {
				t.Fatalf("clean receipt after rejection: %v", err)
			}
		})
	}
}
