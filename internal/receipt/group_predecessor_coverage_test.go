// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestLoadGroupPredecessorRejectsAbsentDamagedAndIncompleteEvidence(t *testing.T) {
	dir := t.TempDir()
	groupID := strings.Repeat("a", 32)
	if _, err := loadClosedGroupPredecessor(dir, "bad", nil); err == nil {
		t.Fatal("invalid predecessor ID accepted")
	}
	if _, err := loadClosedGroupPredecessor(dir, groupID, nil); err == nil || !os.IsNotExist(err) {
		t.Fatalf("missing predecessor opening accepted: %v", err)
	}
	name, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClosedGroupPredecessor(dir, groupID, []string{strings.Repeat("0", 64)}); err == nil {
		t.Fatal("damaged predecessor opening accepted")
	}
	key := testGroupKey(t)
	open, _, _ := testGroupOpen(t, key)
	openName, err := ReceiptGroupFileName(open.GroupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishReceiptGroupArtifact(dir, openName, open); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClosedGroupPredecessor(dir, open.GroupID, []string{open.SignerKey}); err == nil || !strings.Contains(err.Error(), "not complete") {
		t.Fatalf("predecessor without shard evidence accepted: %v", err)
	}
}

func TestOpenReceiptShardSetDoesNotStealEstablishedRecorderOwnership(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if err := rec.AcquireGroupSessions([]string{"proxy.run." + strings.Repeat("a", 32), "proxy.run." + strings.Repeat("b", 32)}); err != nil {
		t.Fatal(err)
	}
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key}, "proxy", 2, 0)
	if set != nil || err == nil || !strings.Contains(err.Error(), "acquire receipt group sessions") {
		t.Fatalf("second group stole recorder ownership: set=%v err=%v", set, err)
	}
}

func TestPreparedReceiptShardSetFailsClosedWhenEmitterCannotOpen(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := PrepareInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	set.emitters[0].MarkUnhealthy(os.ErrPermission)
	if err := set.Activate(testConfigHash); err == nil || !strings.Contains(err.Error(), "open receipt group shard 0") {
		t.Fatalf("unhealthy prepared emitter activated: %v", err)
	}
	if got := set.Admit(EmitOpts{}); got.ShardSelected {
		t.Fatalf("failed activation admitted request: %+v", got)
	}
}
