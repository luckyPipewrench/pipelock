// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/store"
	guardfs "github.com/luckyPipewrench/pipelock/internal/guard"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestOriginalWedgeWithBundleStylePattern(t *testing.T) {
	f := newBoundaryFixture(t)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     "dlp-phi-icd-10",
		Regex:    `(?i)\b(icd[\s_-]?10|diagnosis[\s_-]?code|dx)[\s:#=]{1,4}[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b`,
		Severity: config.SeverityHigh,
	})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	if sc.ScanTextForDLP(context.Background(), wedgedHead).Clean {
		t.Fatal("positive control: bundle-shaped rule must match the original generated head")
	}
	if err := f.rec.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: dir, Redact: true}, sc, f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.rec, f.dir = rec, dir
	f.em = NewEmitter(EmitterConfig{Recorder: rec, PrivKey: f.key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	for i := 0; i < 3; i++ {
		f.em.chainMu.Lock()
		f.em.chainPrevHash = wedgedHead
		f.em.chainMu.Unlock()
		if err := f.em.EmitDurable(baseOpts()); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.receipts(t)) != 3 {
		t.Fatal("wedge did not produce all receipts")
	}
}

func TestContractDigestsRemainIntactWhenDetectorMatches(t *testing.T) {
	contractHash, err := store.ContractHash(contract.Contract{})
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := store.ActiveManifestHash(contract.ActiveManifest{})
	if err != nil {
		t.Fatal(err)
	}
	f := newBoundaryFixture(t, strings.TrimPrefix(contractHash, "sha256:"), strings.TrimPrefix(manifestHash, "sha256:"))
	for _, hash := range []string{contractHash, manifestHash} {
		if f.sc.ScanTextForDLP(context.Background(), hash).Clean {
			t.Fatal("positive control: detector must match the computed digest")
		}
	}
	for i := 0; i < 3; i++ {
		opts := baseOpts()
		opts.ContractHash, opts.ActiveManifestHash = contractHash, manifestHash
		if err := f.em.EmitDurable(opts); err != nil {
			t.Fatalf("computed contract digests refused: %v", err)
		}
	}
	for _, r := range f.receipts(t) {
		if r.ActionRecord.ContractHash != contractHash || r.ActionRecord.ActiveManifestHash != manifestHash {
			t.Fatal("computed contract digests were redacted")
		}
	}
}

func TestGuardRequestDigestRemainsIntactWhenDetectorMatches(t *testing.T) {
	proof := guardfs.NewExecutionProof(guardfs.EnforcementRecord{}, guardfs.ExecControlOptions{PolicyHash: "policy", Binary: "/usr/bin/true"}, []string{"/usr/bin/true"})
	f := newBoundaryFixture(t, proof.EffectivePolicyHash)
	id := "guard-exec:" + proof.EffectivePolicyHash
	if f.sc.ScanTextForDLP(context.Background(), id).Clean {
		t.Fatal("positive control: detector must match the generated Guard request ID")
	}
	for i := 0; i < 3; i++ {
		opts := baseOpts()
		opts.RequestID = id
		if err := f.em.EmitDurable(opts); err != nil {
			t.Fatalf("computed Guard request ID refused: %v", err)
		}
	}
	for _, r := range f.receipts(t) {
		if r.ActionRecord.RequestID != id {
			t.Fatal("computed Guard request ID changed")
		}
	}
}

func TestUnprovenContractAndGuardDigestsStayContent(t *testing.T) {
	chosen := strings.Repeat("dc86", 16)
	for _, field := range []string{"contract", "manifest", "request"} {
		t.Run(field, func(t *testing.T) {
			f := newBoundaryFixture(t, chosen)
			opts := baseOpts()
			switch field {
			case "contract":
				opts.ContractHash = "sha256:" + chosen
			case "manifest":
				opts.ActiveManifestHash = "sha256:" + chosen
			case "request":
				opts.RequestID = "guard-exec:" + chosen
			}
			err := f.em.EmitDurable(opts)
			if field == "request" {
				if !errors.Is(err, receiptcontent.ErrRejected) {
					t.Fatalf("chosen request ID error = %v", err)
				}
				if err := f.em.EmitDurable(baseOpts()); err != nil {
					t.Fatalf("clean receipt after refusal: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, r := range f.receipts(t) {
				if strings.Contains(r.ActionRecord.ContractHash, chosen) || strings.Contains(r.ActionRecord.ActiveManifestHash, chosen) || strings.Contains(r.ActionRecord.RequestID, chosen) {
					t.Fatal("caller-selected digest persisted")
				}
			}
		})
	}
}
