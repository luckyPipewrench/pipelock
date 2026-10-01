// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func recoveryFixture(t *testing.T) (string, RecoverySeal, ed25519.PrivateKey) {
	t.Helper()
	root := "../../sdk/conformance/testdata/recovery-seals/valid"
	dir := t.TempDir()
	files, err := os.ReadDir(filepath.Join(root, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, "evidence", f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := UnmarshalRecoverySeal(raw)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("pipelock-recovery-seal-conformance-v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	if err := VerifyRecoveryBinding(dir, s, []string{s.SuccessorSignerKey}); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	return dir, s, key
}

func TestRecoverySealShardReplay(t *testing.T) {
	dir, seal, _ := recoveryFixture(t)
	path := filepath.Join(dir, seal.Shard)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	// The signature and readable prefix remain valid, but these are no longer
	// the bytes the original observation signed.
	if err := os.WriteFile(path, append(data, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifyRecoveryBinding(dir, seal, []string{seal.SuccessorSignerKey})
	if err == nil || !strings.Contains(err.Error(), "shard or prefix binding mismatch") {
		t.Fatalf("replayed seal accepted or wrong rejection: %v", err)
	}
}

func TestRecoverySealBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*RecoverySeal)
	}{
		{"offset", func(s *RecoverySeal) { s.DamageOffset-- }},
		{"size", func(s *RecoverySeal) { s.ShardSize++ }},
		{"raw_hash", func(s *RecoverySeal) { s.ShardSHA256 = strings.Repeat("0", 64) }},
		{"outer_hash", func(s *RecoverySeal) { s.LastGoodHash = strings.Repeat("0", 64) }},
		{"outer_seq", func(s *RecoverySeal) { s.LastGoodSeq++ }},
		{"receipt_hash", func(s *RecoverySeal) { s.PredecessorTailHash = strings.Repeat("0", 64) }},
		{"receipt_seq", func(s *RecoverySeal) { s.PredecessorTailSeq++ }},
		{"opening", func(s *RecoverySeal) { s.SuccessorOpenHash = strings.Repeat("0", 64) }},
		{"successor", func(s *RecoverySeal) { s.SuccessorSession = "proxy.run." + strings.Repeat("3", 32) }},
		{"shard", func(s *RecoverySeal) { s.Shard = "evidence-" + s.PredecessorSession + "-9.jsonl" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, s, key := recoveryFixture(t)
			tc.mutate(&s)
			s, err := SignRecoverySeal(s, key)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyRecoverySeal(s); err != nil {
				t.Fatalf("re-signed control: %v", err)
			}
			if err := VerifyRecoveryBinding(dir, s, []string{s.SuccessorSignerKey}); err == nil {
				t.Fatal("wrong archive claim accepted")
			}
		})
	}
}

func TestRecoverySealStrictDecode(t *testing.T) {
	_, s, _ := recoveryFixture(t)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalChainLink(raw); err == nil {
		t.Fatal("old verifier accepted new record")
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown", bytes.Replace(raw, []byte(`"kind":`), []byte(`"extra":1,"kind":`), 1)},
		{"duplicate", bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)},
		{"alias", bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1)},
		{"null", bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1)},
		{"missing", bytes.Replace(raw, []byte(`"version":1,`), nil, 1)},
		{"trailing", append(bytes.Clone(raw), []byte(` {}`)...)},
		{"version", bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1)},
		{"tampered", bytes.Replace(raw, []byte(`"last_good_seq":2`), []byte(`"last_good_seq":3`), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.raw, raw) {
				t.Fatal("mutation missed fixture")
			}
			if _, err := UnmarshalRecoverySeal(tc.raw); err == nil {
				t.Fatal("invalid seal accepted")
			}
		})
	}
	if _, err := SignRecoverySeal(s, nil); err == nil {
		t.Fatal("nil key accepted")
	}
	s.ShardSize = maxRecoveryInteger + 1
	if err := VerifyRecoverySeal(s); err == nil {
		t.Fatal("unsafe numeric range accepted")
	}
}

func TestRecoverySealBaseVerdicts(t *testing.T) {
	for _, mode := range []string{"sealed", "missing", "tampered", "wrong_claim_slot", "doctor"} {
		t.Run(mode, func(t *testing.T) {
			dir, s, _ := recoveryFixture(t)
			path := filepath.Join(dir, ChainLinkFileName(s.PredecessorSession))
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "tampered":
				s.LastGoodSeq++
				b, err := json.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0o600); err != nil {
					t.Fatal(err)
				}
			case "wrong_claim_slot":
				if err := os.Rename(path, filepath.Join(dir, ChainLinkFileName("proxy.run."+strings.Repeat("3", 32)))); err != nil {
					t.Fatal(err)
				}
			}
			opts := BaseVerifyOptions{TrustedKeys: []string{s.SuccessorSignerKey}, LinksOnly: mode == "doctor"}
			report, err := VerifyBase(dir, "proxy", opts)
			if err != nil {
				t.Fatal(err)
			}
			if report.Healthy() {
				t.Fatal("damage reported healthy")
			}
			attached := slices.ContainsFunc(report.Chains, func(c BaseChain) bool { return c.RecoverySeal != nil })
			if attached != (mode == "sealed" || mode == "doctor") {
				t.Fatalf("wrong discontinuity result: %+v", report)
			}
			if mode == "missing" && !slices.Contains(report.Unlinked(), s.SuccessorSession) {
				t.Fatal("missing seal concealed gap")
			}
		})
	}
}

func TestRecoverySealReloadPublicationRetry(t *testing.T) {
	dir := t.TempDir()
	_, key := generateTestKey(t)
	first := startRun(t, dir, key)
	defer first.close(t)
	first.openAndEmit(t, 1)
	files, err := recorderFiles(dir, first.session)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[len(files)-1], append(raw, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := first.rec.RecoverTornRunSession("proxy")
	if err != nil {
		t.Fatal(err)
	}
	oldLink := linkFile
	linkFile = func(string, string) error { return errors.New("publication fault") }
	t.Cleanup(func() { linkFile = oldLink })
	e := NewEmitter(EmitterConfig{Recorder: first.rec, PrivKey: key, Session: next})
	if err := e.EmitSessionOpen(); err == nil || e.HealthError() == nil {
		t.Fatal("unsealed reload became healthy")
	}
	linkFile = oldLink
	retry := NewEmitter(EmitterConfig{Recorder: first.rec, PrivKey: key, Session: next})
	if err := retry.InitError(); err != nil {
		t.Fatal(err)
	}
	if retry.recoverySeal == nil {
		t.Fatal("retry skipped recovery publication")
	}
	if err := VerifyRecoveryBinding(dir, *retry.recoverySeal, []string{retry.SignerKeyHex()}); err != nil {
		t.Fatal(err)
	}
	if got := first.rec.RecoveryPredecessor(); got != "" {
		t.Fatalf("successful recovery remained pending: %s", got)
	}
	_, rotatedKey := generateTestKey(t)
	rotated := NewEmitter(EmitterConfig{Recorder: first.rec, PrivKey: rotatedKey, Session: next, PriorSignerKeys: []string{retry.SignerKeyHex()}})
	if err := rotated.InitError(); err != nil {
		t.Fatalf("ordinary post-recovery rotation tried to republish the seal: %v", err)
	}
	if err := rotated.EmitSessionOpen(); err != nil {
		t.Fatalf("post-recovery rotation could not emit: %v", err)
	}
	if err := VerifyRecoveryBinding(dir, *retry.recoverySeal, []string{retry.SignerKeyHex(), rotated.SignerKeyHex()}); err != nil {
		t.Fatalf("later rotation invalidated original recovery binding: %v", err)
	}
}
