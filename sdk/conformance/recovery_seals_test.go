// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const recoveryFixtureDir = "testdata/recovery-seals/valid"

// Regenerate with go test ./sdk/conformance -run TestGenerateRecoverySealFixture -update.
// The source is the real recorder/emitter recovery path, not a hand-built seal.
func TestGenerateRecoverySealFixture(t *testing.T) {
	if !*update {
		t.Skip("use -update to regenerate recovery fixture")
	}
	seed := sha256.Sum256([]byte("pipelock-recovery-seal-conformance-v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	dir := t.TempDir()
	run := func(session string) {
		r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AcquireSession(session); err != nil {
			t.Fatal(err)
		}
		e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: r, PrivKey: key, Session: session, Principal: "local", Actor: "pipelock", ConfigHash: "fixture", Notices: io.Discard})
		if err := e.EmitSessionOpen(); err != nil {
			t.Fatal(err)
		}
		if err := e.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Target: "https://api.vendor.example/resource", Verdict: config.ActionAllow, Transport: "fetch"}); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	pred := "proxy.run." + strings.Repeat("1", 32)
	succ := "proxy.run." + strings.Repeat("2", 32)
	run(pred)
	files, err := filepath.Glob(filepath.Join(dir, "evidence-"+pred+"-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("shards=%v err=%v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], append(raw, 0, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	run(succ)
	out := filepath.Join(recoveryFixtureDir, "evidence")
	if err := os.MkdirAll(out, 0o750); err != nil {
		t.Fatal(err)
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if !strings.HasPrefix(name.Name(), "evidence-") && !strings.HasPrefix(name.Name(), receipt.ChainLinkFilePrefix) {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name.Name())))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seal, err := os.ReadFile(filepath.Clean(filepath.Join(dir, receipt.ChainLinkFileName(pred))))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recoveryFixtureDir, "seal.json"), seal, 0o600); err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if err := os.WriteFile(filepath.Join(recoveryFixtureDir, "signer.pub"), []byte(pub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// This fixture has a legitimate signer rotation in the damaged predecessor.
// It exercises observation separately from the offline operator's key pins.
func TestGenerateRotatedRecoverySealFixture(t *testing.T) {
	if !*update {
		t.Skip("use -update to regenerate recovery fixture")
	}
	seed := sha256.Sum256([]byte("pipelock-recovery-seal-conformance-v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	rotatedSeed := sha256.Sum256([]byte("pipelock-recovery-seal-rotated-conformance-v1"))
	rotatedKey := ed25519.NewKeyFromSeed(rotatedSeed[:])
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	rotatedPub := hex.EncodeToString(rotatedKey.Public().(ed25519.PublicKey))
	dir := t.TempDir()
	pred := "proxy.run." + strings.Repeat("4", 32)
	succ := "proxy.run." + strings.Repeat("5", 32)
	r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AcquireSession(pred); err != nil {
		t.Fatal(err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: r, PrivKey: key, Session: pred, Notices: io.Discard})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	rotated := receipt.NewEmitter(receipt.EmitterConfig{Recorder: r, PrivKey: rotatedKey, Session: pred, PriorSignerKeys: []string{pub}, Notices: io.Discard})
	if err := rotated.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "evidence-"+pred+"-0.jsonl")
	raw, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(raw, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err = recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, rotatedKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AcquireSession(succ); err != nil {
		t.Fatal(err)
	}
	e = receipt.NewEmitter(receipt.EmitterConfig{Recorder: r, PrivKey: rotatedKey, Session: succ, Notices: io.Discard})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	out := "testdata/recovery-seals/rotated"
	if err := os.MkdirAll(filepath.Join(out, "evidence"), 0o750); err != nil {
		t.Fatal(err)
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if !strings.HasPrefix(name.Name(), "evidence-") && !strings.HasPrefix(name.Name(), receipt.ChainLinkFilePrefix) {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name.Name())))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "evidence", name.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if name.Name() == receipt.ChainLinkFileName(pred) {
			if err := os.WriteFile(filepath.Join(out, "seal.json"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(out, "signer.pub"), []byte(pub+"\n"+rotatedPub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverySealRotatedConformance(t *testing.T) {
	const fixture = "testdata/recovery-seals/rotated"
	raw, err := os.ReadFile(filepath.Join(fixture, "seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := receipt.UnmarshalRecoverySeal(raw)
	if err != nil {
		t.Fatal(err)
	}
	keysRaw, err := os.ReadFile(filepath.Join(fixture, "signer.pub"))
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Fields(string(keysRaw))
	dir := filepath.Join(fixture, "evidence")
	if err := receipt.VerifyRecoveryBinding(dir, seal, keys); err != nil {
		t.Fatal(err)
	}
	for _, pins := range [][]string{nil, keys[:1]} {
		if err := receipt.VerifyRecoveryBinding(dir, seal, pins); err == nil {
			t.Fatal("unpinned predecessor rotation was accepted")
		}
	}
	for _, opts := range []receipt.BaseVerifyOptions{{TrustedKeys: keys}, {LinksOnly: true}} {
		report, err := receipt.VerifyBase(dir, "proxy", opts)
		if err != nil {
			t.Fatal(err)
		}
		if report.Healthy() || !slices.ContainsFunc(report.Chains, func(c receipt.BaseChain) bool { return c.RecoverySeal != nil }) {
			t.Fatalf("rotated recovery lost its unhealthy attested edge: %+v", report)
		}
	}
}

func TestRecoverySealConformance(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(recoveryFixtureDir, "seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := receipt.UnmarshalRecoverySeal(raw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(recoveryFixtureDir, "signer.pub"))
	if err != nil {
		t.Fatal(err)
	}
	trusted := []string{strings.TrimSpace(string(key))}
	dir := filepath.Join(recoveryFixtureDir, "evidence")
	if err := receipt.VerifyRecoveryBinding(dir, s, trusted); err != nil {
		t.Fatal(err)
	}
	report, err := receipt.VerifyBase(dir, "proxy", receipt.BaseVerifyOptions{TrustedKeys: trusted})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() || len(report.Unlinked()) != 1 || report.LinkCount() != 0 {
		t.Fatalf("misleading continuity verdict: %+v", report)
	}
	if !slices.ContainsFunc(report.Chains, func(c receipt.BaseChain) bool { return c.Session == s.SuccessorSession && c.RecoverySeal != nil }) {
		t.Fatalf("seal not attached: %+v", report)
	}
	if !slices.ContainsFunc(report.Findings, func(f receipt.BaseFinding) bool { return f.Kind == receipt.FindingAttestedDiscontinuity }) {
		t.Fatal("missing discontinuity")
	}
	if _, err := receipt.UnmarshalChainLink(raw); err == nil {
		t.Fatal("old link parser accepted recovery seal")
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["damage_offset"] = float64(s.DamageOffset - 1)
	tampered, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.UnmarshalRecoverySeal(tampered); err == nil {
		t.Fatal("tampered seal accepted")
	}
}
