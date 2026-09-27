// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const rotationTestPolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type rotationFixture struct {
	p        *Proxy
	cfg      *config.Config
	rec      *recorder.Recorder
	recDir   string
	keyPathB string
	v1       *receipt.Emitter
	v2       *proxydecision.Emitter
}

func newRotationFixture(t *testing.T) rotationFixture {
	t.Helper()
	recDir := t.TempDir()
	keyDir := t.TempDir()
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}
	keyPathA := filepath.Join(keyDir, "keyA.key")
	keyPathB := filepath.Join(keyDir, "keyB.key")
	if err := signing.SavePrivateKey(privA, keyPathA); err != nil {
		t.Fatalf("SavePrivateKey A: %v", err)
	}
	if err := signing.SavePrivateKey(privB, keyPathB); err != nil {
		t.Fatalf("SavePrivateKey B: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: recDir, CheckpointInterval: 1000}, nil, privA)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	v1 := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: privA, ConfigHash: "hash-a", Principal: "local", Actor: "pipelock"})
	if err := v1.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen A: %v", err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: rec, Signer: proxydecision.NewKeyedSigner(privA), Principal: "local", Actor: "pipelock",
	})

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FlightRecorder.SigningKeyPath = keyPathA
	cfg.SessionProfiling.Enabled = true
	cfg.BehavioralBaseline.Enabled = true
	cfg.BehavioralBaseline.ProfileDir = t.TempDir()
	cfg.BehavioralBaseline.DeviationAction = config.ActionBlock
	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New(),
		WithRecorder(rec), WithReceiptEmitter(v1), WithReceiptKeyPath(keyPathA), WithV2ReceiptEmitter(v2))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	return rotationFixture{p: p, cfg: cfg, rec: rec, recDir: recDir, keyPathB: keyPathB, v1: v1, v2: v2}
}

func rotationTestDecision() proxydecision.Decision {
	return proxydecision.Decision{
		ActionType:    "http_request",
		Transport:     "forward",
		Target:        "https://api.vendor.example/v1/things",
		Verdict:       config.ActionBlock,
		WinningSource: proxydecision.SourceScanner,
		PolicySources: []string{proxydecision.SourceScanner},
		RuleID:        "prompt_injection",
		PolicyHash:    rotationTestPolicyHash,
	}
}

func rotationSessionOpenCount(t *testing.T, dir string) int {
	t.Helper()
	count := 0
	for _, entry := range readAllEntries(t, dir) {
		if entry.Type != receiptEntryType {
			continue
		}
		body, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("marshal receipt: %v", err)
		}
		got, err := receipt.Unmarshal(body)
		if err != nil {
			t.Fatalf("unmarshal receipt: %v", err)
		}
		if got.ActionRecord.SessionControl != nil && got.ActionRecord.SessionControl.Kind == receipt.SessionControlOpen {
			count++
		}
	}
	return count
}

func TestReloadRotationBaselinePrepareFailureWritesNoReceipt(t *testing.T) {
	f := newRotationFixture(t)
	beforeEntries := rotationSessionOpenCount(t, f.recDir)
	before := f.p.sessionMgrPtr.Load().baselinePtr.Load()
	blockedDir := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(filepath.Clean(blockedDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	next := *f.cfg
	next.FlightRecorder.SigningKeyPath = f.keyPathB
	next.BehavioralBaseline.ProfileDir = blockedDir
	if f.p.Reload(&next, scanner.MustNew(&next)) {
		t.Fatal("reload succeeded despite invalid baseline profile directory")
	}
	if f.p.receiptEmitterPtr.Load() != f.v1 {
		t.Fatal("failed reload published a new receipt emitter")
	}
	if got := rotationSessionOpenCount(t, f.recDir); got != beforeEntries {
		t.Fatalf("session opens after failed prepare = %d, want %d", got, beforeEntries)
	}
	if got := f.p.sessionMgrPtr.Load().baselinePtr.Load(); got != before || got.action != config.ActionBlock {
		t.Fatalf("live baseline changed after failed prepare: %+v", got)
	}
}

func TestReloadRotationReceiptFailureKeepsBaseline(t *testing.T) {
	f := newRotationFixture(t)
	before := f.p.sessionMgrPtr.Load().baselinePtr.Load()
	if err := f.rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	next := *f.cfg
	next.FlightRecorder.SigningKeyPath = f.keyPathB
	next.BehavioralBaseline.DeviationAction = config.ActionWarn
	if f.p.Reload(&next, scanner.MustNew(&next)) {
		t.Fatal("reload succeeded despite closed recorder")
	}
	if got := f.p.sessionMgrPtr.Load().baselinePtr.Load(); got != before || got.action != config.ActionBlock {
		t.Fatalf("live baseline changed after receipt failure: %+v", got)
	}
}

func TestReloadRotationReceiptSuccessAppliesBaseline(t *testing.T) {
	f := newRotationFixture(t)
	beforeEntries := rotationSessionOpenCount(t, f.recDir)
	next := *f.cfg
	next.FlightRecorder.SigningKeyPath = f.keyPathB
	next.BehavioralBaseline.DeviationAction = config.ActionWarn
	if !f.p.Reload(&next, scanner.MustNew(&next)) {
		t.Fatal("rotation reload failed")
	}
	if got := f.p.sessionMgrPtr.Load().baselinePtr.Load(); got == nil || got.action != config.ActionWarn {
		t.Fatalf("live baseline action after rotation: %+v", got)
	}
	if got := rotationSessionOpenCount(t, f.recDir); got != beforeEntries+1 {
		t.Fatalf("session opens after successful rotation = %d, want %d", got, beforeEntries+1)
	}
}

// A request emitting on the old v2 emitter after Reload staged its resume
// point must not let the replacement reuse that chain position.
func TestReloadRotationHandsOffLiveV2ChainHead(t *testing.T) {
	f := newRotationFixture(t)
	f.p.reloadLocked = func() {
		if err := f.v2.Emit(rotationTestDecision()); err != nil {
			t.Errorf("in-flight emit on old v2 emitter: %v", err)
		}
	}
	next := *f.cfg
	next.FlightRecorder.SigningKeyPath = f.keyPathB
	if !f.p.Reload(&next, scanner.MustNew(&next)) {
		t.Fatal("rotation reload failed")
	}
	f.p.reloadLocked = nil
	replacement := f.p.v2EmitterPtr.Load()
	if replacement == f.v2 {
		t.Fatal("rotation reload did not replace the v2 emitter")
	}
	oldSeq, oldPrev := f.v2.ChainState()
	newSeq, newPrev := replacement.ChainState()
	if newSeq != oldSeq || newPrev != oldPrev {
		t.Fatalf("replacement resumed at seq=%d prev=%s, want live head seq=%d prev=%s", newSeq, newPrev, oldSeq, oldPrev)
	}
	if err := f.v2.Emit(rotationTestDecision()); err == nil {
		t.Fatal("retired v2 emitter still accepted an emit after hand-off")
	}
}

// A chain head that cannot be handed off aborts the reload before publication.
func TestReloadRotationRefusesUntrustedV2Head(t *testing.T) {
	f := newRotationFixture(t)
	before := f.p.sessionMgrPtr.Load().baselinePtr.Load()
	f.p.reloadLocked = func() {
		if _, _, err := f.v2.Retire(); err != nil {
			t.Errorf("Retire: %v", err)
		}
	}
	next := *f.cfg
	next.FlightRecorder.SigningKeyPath = f.keyPathB
	next.BehavioralBaseline.DeviationAction = config.ActionWarn
	if f.p.Reload(&next, scanner.MustNew(&next)) {
		t.Fatal("reload published a replacement from an untrusted v2 chain head")
	}
	f.p.reloadLocked = nil
	if f.p.v2EmitterPtr.Load() != f.v2 {
		t.Fatal("failed hand-off published the replacement v2 emitter")
	}
	if f.p.CurrentConfig() != f.cfg {
		t.Fatal("failed hand-off published the new config")
	}
	if got := f.p.sessionMgrPtr.Load().baselinePtr.Load(); got != before {
		t.Fatalf("failed hand-off changed live baseline snapshot: before=%p after=%p", before, got)
	}
}
