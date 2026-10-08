// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestSessionOpenGroupBindingSignatureAndLegacyOmission(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	open := testSessionOpen(sessionOpenTestRunA, "open-a", 0)
	genesis := ComputeSessionOpenGenesis(open)
	open.GenesisHash = genesis
	legacy := signSessionReceipt(t, key, 0, genesis, time.Unix(0, 0).UTC(), sessionOpenTestRunA, &SessionControl{Kind: SessionControlOpen, Open: &open}, nil)
	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacyJSON), "group_binding") {
		t.Fatal("legacy session_open acquired a group_binding field")
	}
	if err := VerifyWithKey(legacy, legacy.SignerKey); err != nil {
		t.Fatalf("legacy signature: %v", err)
	}

	open.GroupBinding = &ReceiptGroupBinding{
		GroupID: strings.Repeat("a", 32), ShardIndex: 1,
		SessionID:          "proxy.run." + strings.Repeat("b", 32),
		OpenManifestSHA256: strings.Repeat("c", 64),
		SignerKey:          legacy.SignerKey,
	}
	if got := ComputeSessionOpenGenesis(open); got != genesis {
		t.Fatalf("group binding changed frozen genesis: %q != %q", got, genesis)
	}
	bound := signSessionReceipt(t, key, 0, genesis, time.Unix(0, 0).UTC(), sessionOpenTestRunA, &SessionControl{Kind: SessionControlOpen, Open: &open}, nil)
	if err := VerifyWithKey(bound, bound.SignerKey); err != nil {
		t.Fatalf("bound signature: %v", err)
	}
	bound.ActionRecord.SessionControl.Open.GroupBinding.ShardIndex = 0
	if err := VerifyWithKey(bound, bound.SignerKey); err == nil {
		t.Fatal("signature-only verification accepted a swapped group binding")
	}
}

func TestEmitterSessionOpenUsesFixedGroupBinding(t *testing.T) {
	publicKey, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	sessions := make([]string, 2)
	for i := range sessions {
		sessions[i], err = recorder.NewRunSessionID("proxy")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	binding := ReceiptGroupBinding{
		GroupID: strings.Repeat("a", 32), ShardIndex: 1,
		SessionID: sessions[1], OpenManifestSHA256: strings.Repeat("b", 64),
		SignerKey: hex.EncodeToString(publicKey),
	}
	emitter := NewEmitter(EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor, Session: sessions[1], GroupBinding: &binding,
	})
	if err := emitter.InitError(); err != nil {
		t.Fatal(err)
	}
	binding.ShardIndex = 0
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	receipts := readAllReceiptsFromDir(t, dir, publicKey)
	if len(receipts) != 1 || receipts[0].ActionRecord.SessionControl.Open.GroupBinding == nil ||
		receipts[0].ActionRecord.SessionControl.Open.GroupBinding.ShardIndex != 1 {
		t.Fatalf("session_open did not preserve the configured binding: %+v", receipts)
	}
	if err := VerifyWithKey(receipts[0], receipts[0].SignerKey); err != nil {
		t.Fatal(err)
	}
	if bad := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, Session: sessions[0], GroupBinding: &binding}); bad.InitError() == nil {
		t.Fatal("accepted a binding for a different shard session")
	}
}
