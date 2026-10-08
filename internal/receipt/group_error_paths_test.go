// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestReceiptShardSetRejectsAdmissionWithoutReadyGroup(t *testing.T) {
	var absent *ReceiptShardSet
	if got := absent.Admit(EmitOpts{}); got.ShardSelected {
		t.Fatal("nil group selected a shard")
	}
	if _, err := absent.SelectedEmitter(EmitOpts{ShardSelected: true}); err == nil {
		t.Fatal("nil group returned an emitter")
	}
	if err := absent.Emit(EmitOpts{ShardSelected: true}); err == nil {
		t.Fatal("nil group emitted a receipt")
	}
	if err := absent.EmitDurable(EmitOpts{ShardSelected: true}); err == nil {
		t.Fatal("nil group durably emitted a receipt")
	}
	if err := absent.Activate("hash"); err == nil {
		t.Fatal("nil group activated")
	}
	if _, err := absent.PublishClose(); err == nil {
		t.Fatal("nil group published a close")
	}
	if absent.ShardCount() != 0 || absent.ProcessEmitter() != nil || absent.Emitters() != nil {
		t.Fatal("nil group exposed shards")
	}
	open, hash := absent.Opening()
	if open.GroupID != "" || hash != "" {
		t.Fatal("nil group exposed membership")
	}
	absent.MarkUnhealthy(nil)

	unready := &ReceiptShardSet{emitters: make([]*Emitter, 2)}
	if got := unready.Admit(EmitOpts{}); got.ShardSelected {
		t.Fatal("unready group selected a shard")
	}
	if _, err := unready.SelectedEmitter(EmitOpts{ShardSelected: true}); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("unready group admission: %v", err)
	}
	unready.ready.Store(true)
	if err := unready.Activate("hash"); err == nil || !strings.Contains(err.Error(), "no emitter") {
		t.Fatalf("group with missing emitter activated: %v", err)
	}
	for _, opts := range []EmitOpts{{}, {ShardSelected: true, ShardIndex: -1}, {ShardSelected: true, ShardIndex: 2}, {ShardSelected: true, ShardIndex: 0}} {
		if _, err := unready.SelectedEmitter(opts); err == nil || !strings.Contains(err.Error(), "not selected") {
			t.Fatalf("invalid shard selection accepted: %+v, %v", opts, err)
		}
	}
}

func TestReceiptGroupStartupRejectsInvalidWriterConfiguration(t *testing.T) {
	_, key := generateTestKey(t)
	for _, tc := range []struct {
		name  string
		base  string
		count int
		index int
		want  string
	}{
		{"one shard", "proxy", 1, 0, "2 to 32"},
		{"too many shards", "proxy", 33, 0, "2 to 32"},
		{"invalid process index", "proxy", 2, 2, "process index"},
		{"unsafe base", "bad/session", 2, 0, "base session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key}, tc.base, tc.count, tc.index)
			if err == nil || set != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unsafe group startup: set=%v err=%v", set, err)
			}
		})
	}
	if set, err := OpenInitialReceiptShardSet(EmitterConfig{PrivKey: key}, "proxy", 2, 0); err == nil || set != nil {
		t.Fatalf("group without persistent recorder started: set=%v err=%v", set, err)
	}
	if set, err := OpenSuccessorReceiptShardSet(EmitterConfig{PrivKey: key}, "proxy", 2, 0, strings.Repeat("1", 32)); err == nil || set != nil {
		t.Fatalf("successor without persistent recorder started: set=%v err=%v", set, err)
	}
}

func TestReceiptGroupPrefixAndGateRejectUnboundEvidence(t *testing.T) {
	key := testGroupKey(t)
	open, raw, openHash := testGroupOpen(t, key)
	dir := t.TempDir()
	if _, err := verifyGroupShardPrefix(dir, open, openHash, -1); err == nil {
		t.Fatal("negative predecessor shard accepted")
	}
	if _, err := verifyGroupShardPrefix(dir, open, openHash, len(open.Shards)); err == nil {
		t.Fatal("out-of-range predecessor shard accepted")
	}
	if _, err := verifyGroupShardPrefix(dir, open, openHash, 0); err == nil {
		t.Fatal("missing predecessor evidence accepted")
	}
	if _, err := VerifyGroupShardHead(dir, open, openHash, -1); err == nil {
		t.Fatal("negative close shard accepted")
	}
	badSigner := open
	badSigner.SignerKey = "bad"
	if _, err := VerifyGroupShardHead(dir, badSigner, openHash, 0); err == nil {
		t.Fatal("invalid shard signer accepted")
	}
	for _, tc := range []struct {
		name   string
		entry  recorder.Entry
		gated  bool
		failed bool
	}{
		{"legacy", recorder.Entry{Type: "legacy"}, false, false},
		{"malformed", recorder.Entry{Type: recorder.GroupGateEntryType, Detail: "bad"}, true, true},
		{"empty ID", recorder.Entry{Type: recorder.GroupGateEntryType, Detail: ReceiptGroupBinding{}}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, gated, err := groupGateFromFirstEntry(tc.entry)
			if gated != tc.gated || (err != nil) != tc.failed {
				t.Fatalf("gate classification: gated=%v err=%v", gated, err)
			}
		})
	}
	name, _ := ReceiptGroupFileName(open.GroupID, "open")
	gate := groupBinding(open, openHash, 0)
	if err := verifyInventoryGate(dir, open.Shards[0].SessionID, gate, []string{open.SignerKey}); err == nil {
		t.Fatal("missing opening accepted by gate inventory")
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyInventoryGate(dir, open.Shards[0].SessionID, gate, []string{open.SignerKey}); err != nil {
		t.Fatalf("valid opening gate rejected: %v", err)
	}
	wrong := gate
	wrong.OpenManifestSHA256 = strings.Repeat("0", 64)
	if err := verifyInventoryGate(dir, open.Shards[0].SessionID, wrong, []string{open.SignerKey}); err == nil {
		t.Fatal("gate with false opening digest accepted")
	}
	if err := verifyInventoryGate(dir, open.Shards[0].SessionID, gate, nil); err == nil {
		t.Fatal("untrusted opening gate accepted")
	}
	wrong.GroupID = "bad"
	if err := verifyInventoryGate(dir, open.Shards[0].SessionID, wrong, []string{open.SignerKey}); err == nil {
		t.Fatal("invalid group ID accepted by gate inventory")
	}
}

func TestReceiptGroupCheckpointRejectsMalformedDetailAndSignature(t *testing.T) {
	key := testGroupKey(t)
	pub := key.Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		name   string
		detail any
	}{
		{"unmarshalable", func() {}},
		{"wrong type", "not a checkpoint"},
		{"invalid signature", recorder.CheckpointDetail{Signature: "bad"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyGroupCheckpoint(recorder.Entry{Type: "checkpoint", Detail: tc.detail}, pub); err == nil {
				t.Fatal("malformed checkpoint accepted")
			}
		})
	}
}

func TestGroupAELClaimIndexRejectsDuplicateRun(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := OpenInitialReceiptShardSet(EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
	err = indexAELClaimsForSession(dir, open.Shards[0].SessionID, open.GroupID, "", []string{open.SignerKey}, func(_, _, _, _ string, _ bool) error {
		return errors.New("run already claimed")
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate signed native AEL run") {
		t.Fatalf("duplicate native run accepted: %v", err)
	}
}

func TestReceiptGroupSigningRejectsInvalidKeysAndManifestBindings(t *testing.T) {
	key := testGroupKey(t)
	open, _, openHash := testGroupOpen(t, key)
	if _, err := SignReceiptGroupOpen(open, ed25519.PrivateKey("short")); err == nil {
		t.Fatal("invalid opening key accepted")
	}
	malformed := open
	malformed.ShardCount++
	if _, err := SignReceiptGroupOpen(malformed, key); err == nil {
		t.Fatal("invalid opening membership signed")
	}
	if _, err := SignReceiptGroupClose(ReceiptGroupClose{}, open, openHash, ed25519.PrivateKey("short")); err == nil {
		t.Fatal("invalid close key accepted")
	}
	if _, err := SignReceiptGroupClose(ReceiptGroupClose{}, open, openHash, key); err == nil {
		t.Fatal("invalid close membership signed")
	}
	if _, err := SignReceiptGroupTransition(ReceiptGroupTransition{}, open, open, openHash, openHash, "", ed25519.PrivateKey("short")); err == nil {
		t.Fatal("invalid transition key accepted")
	}
	if _, err := SignReceiptGroupTransition(ReceiptGroupTransition{}, open, open, openHash, openHash, "", key); err == nil {
		t.Fatal("invalid transition binding signed")
	}
	for _, tc := range []struct{ name, domain, signer, signature string }{
		{"invalid signer", groupOpenDomain, "bad", open.Signature},
		{"invalid signature", groupOpenDomain, open.SignerKey, "bad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyOpen := open
			copyOpen.Signature = ""
			if err := verifyGroupArtifact(tc.domain, copyOpen, tc.signature, tc.signer, []string{open.SignerKey}); err == nil {
				t.Fatal("invalid signed artifact accepted")
			}
		})
	}
	validClose, err := SignReceiptGroupClose(ReceiptGroupClose{
		GroupID: open.GroupID, OpenManifestSHA256: openHash, Shards: testGroupHeads(open),
		ClosedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
	}, open, openHash, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(validClose)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceiptGroupClose(raw, open, openHash, nil); err == nil {
		t.Fatal("close without trusted signer accepted")
	}
}
