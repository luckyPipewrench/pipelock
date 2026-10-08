// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestPreparedReceiptShardSetWithholdsAdmissionUntilActivated(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	metrics := &stubMetrics{}
	set, err := PrepareInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Metrics: metrics}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Admit(EmitOpts{}); got.ShardSelected {
		t.Fatalf("prepared group admitted request: %+v", got)
	}
	if _, err := set.SelectedEmitter(EmitOpts{ShardSelected: true, ShardIndex: 0}); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("prepared group selected writer: %v", err)
	}
	open, _ := set.Opening()
	for _, shard := range open.Shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("prepared shard files=%v err=%v", paths, err)
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil || len(entries) != 2 || entries[0].Type != recorder.GroupGateEntryType || entries[1].Type != "checkpoint" {
			t.Fatalf("prepared shard entries=%v err=%v", entries, err)
		}
	}
	if err := set.Activate(testConfigHash); err != nil {
		t.Fatal(err)
	}
	if got := set.Admit(EmitOpts{}); !got.ShardSelected || got.ShardIndex != 0 {
		t.Fatalf("activated group did not admit first shard: %+v", got)
	}
	if got := set.ShardCount(); got != 2 {
		t.Fatalf("activated shard count=%d", got)
	}
	if err := set.Emit(EmitOpts{}); err == nil || !strings.Contains(err.Error(), "not selected") {
		t.Fatalf("unselected request was emitted: %v", err)
	}
	if reasons := metrics.snapshot(); len(reasons) != 1 || reasons[0] != FailReasonUnavailable {
		t.Fatalf("missing selection failure metric: %v", reasons)
	}
	opts := set.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"})
	if err := set.Emit(opts); err != nil {
		t.Fatalf("selected shard failed ordinary emission: %v", err)
	}
	set.MarkUnhealthy(os.ErrPermission)
	for i, emitter := range set.Emitters() {
		if !errors.Is(emitter.HealthError(), os.ErrPermission) {
			t.Fatalf("shard %d stayed healthy after group failure: %v", i, emitter.HealthError())
		}
	}
}

func TestReceiptGroupWriterRejectsMismatchedTrustAndOwnership(t *testing.T) {
	_, key := generateTestKey(t)
	other := testGroupKey(t)
	if _, err := TrustedGroupSignerKeys(EmitterConfig{}); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("missing group key accepted: %v", err)
	}
	if _, err := TrustedGroupSignerKeys(EmitterConfig{PrivKey: key, PriorSignerKeys: []string{"invalid"}}); err == nil || !strings.Contains(err.Error(), "prior signer") {
		t.Fatalf("invalid prior signer accepted: %v", err)
	}
	if got, err := TrustedGroupSignerKeys(EmitterConfig{PrivKey: key, PriorSignerKeys: []string{groupKeyHex(other)}}); err != nil || len(got) != 2 || got[1] != groupKeyHex(other) {
		t.Fatalf("trusted signer set=%v err=%v", got, err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	for _, tc := range []struct {
		name, want string
		cfg        EmitterConfig
		previous   *receiptGroupPredecessor
	}{
		{"checkpoint signer", "signer differs", EmitterConfig{Recorder: rec, PrivKey: other}, nil},
		{"successor base", "base differs", EmitterConfig{Recorder: rec, PrivKey: key}, &receiptGroupPredecessor{open: ReceiptGroupOpen{BaseSession: "other"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := openReceiptShardSet(tc.cfg, "proxy", 2, 0, false, tc.previous)
			if set != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("mismatched writer set=%v err=%v, want %q", set, err, tc.want)
			}
		})
	}
	if set, err := OpenSuccessorReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: ed25519.PrivateKey("bad")}, "proxy", 2, 0, strings.Repeat("a", 32)); set != nil || err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("invalid successor signer set=%v err=%v", set, err)
	}
	if err := os.Rename(dir, dir+"-removed"); err != nil {
		t.Fatal(err)
	}
	if set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key}, "proxy", 2, 0); set != nil || err == nil || !strings.Contains(err.Error(), "inventory receipt groups") {
		t.Fatalf("missing evidence directory set=%v err=%v", set, err)
	}
}

func TestReceiptGroupWriterDoesNotPublishAfterGateSyncFailure(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	rec.SetSyncForTest(func(*os.File) error { return errors.New("injected gate sync failure") })
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if set != nil || err == nil || !strings.Contains(err.Error(), "record receipt group shard 0 gate") {
		t.Fatalf("group opened after gate failure: set=%v err=%v", set, err)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, "receipt-group-*-close.json")); err != nil || len(matches) != 0 {
		t.Fatalf("failed opening published a close: %v, %v", matches, err)
	}
}

func groupKeyHex(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}
