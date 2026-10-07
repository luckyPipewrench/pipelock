// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func newGroupRecorder(t *testing.T) (*Recorder, ed25519.PrivateKey, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r, err := New(Config{Enabled: true, Dir: dir, SignCheckpoints: true, CheckpointInterval: 3}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, key, dir
}

func groupSessionIDs(t *testing.T, n int) []string {
	t.Helper()
	sessions := make([]string, n)
	for i := range sessions {
		var err error
		sessions[i], err = NewRunSessionID("proxy")
		if err != nil {
			t.Fatal(err)
		}
	}
	return sessions
}

func TestRecorderGroupOwnerAllowsOneLiveGroupPerDirectory(t *testing.T) {
	if !supportsEvidenceCeremonyLock() {
		t.Skip("directory locking unavailable")
	}
	first, key, dir := newGroupRecorder(t)
	second, err := New(Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if err := first.AcquireGroupSessions(groupSessionIDs(t, 2)); err != nil {
		t.Fatal(err)
	}
	secondSessions := groupSessionIDs(t, 2)
	if err := second.AcquireGroupSessions(secondSessions); err == nil || !strings.Contains(err.Error(), "another receipt group writer") {
		t.Fatalf("concurrent group owner accepted: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.AcquireGroupSessions(secondSessions); err != nil {
		t.Fatalf("released group owner stayed locked: %v", err)
	}
}

func TestRecorderGroupSessionsKeepIndependentChains(t *testing.T) {
	r, key, dir := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 4)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	if err := r.AcquireSession(sessions[0]); err == nil {
		t.Fatal("single-session acquisition accepted after group acquisition")
	}
	foreign, err := NewRunSessionID("proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Record(Entry{SessionID: foreign, Type: "test", Summary: "foreign"}); err == nil {
		t.Fatal("unacquired session wrote to a group recorder")
	}

	var wg sync.WaitGroup
	errorsCh := make(chan error, len(sessions)*12)
	for _, session := range sessions {
		wg.Add(1)
		go func(session string) {
			defer wg.Done()
			for i := range 12 {
				entry := Entry{SessionID: session, Type: "test", Summary: fmt.Sprintf("entry-%d", i)}
				if err := r.RecordDurable(entry); err != nil {
					errorsCh <- err
					return
				}
			}
		}(session)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("session %s paths = %v, %v", session, paths, err)
		}
		entries, err := ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 16 { // 12 data + 4 interval checkpoints
			t.Fatalf("session %s entries = %d, want 16", session, len(entries))
		}
		if err := VerifyChain(entries, key.Public().(ed25519.PublicKey)); err != nil {
			t.Fatalf("session %s chain: %v", session, err)
		}
		for _, entry := range entries {
			if entry.SessionID != session {
				t.Fatalf("cross-shard entry in %s: %s", session, entry.SessionID)
			}
		}
	}
}

func TestRecorderGroupAcquireRollbackAndBounds(t *testing.T) {
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	for _, bad := range [][]string{nil, sessions[:1], {sessions[0], sessions[0]}, {sessions[0], "proxy.run.invalid"}} {
		if err := r.AcquireGroupSessions(bad); err == nil {
			t.Fatalf("accepted invalid group acquisition %v", bad)
		}
		if r.sessionID != "" || r.groupSessions != nil || r.runPresence != nil {
			t.Fatal("failed group acquisition left owner state bound")
		}
	}
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatalf("valid acquisition after rollback: %v", err)
	}
}

func TestRecorderGroupFDCountAtThirtyTwo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/fd is Linux-specific")
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("fd inventory unavailable: %v", err)
	}
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 32)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if err := r.RecordDurable(Entry{SessionID: session, Type: "test", Summary: "one"}); err != nil {
			t.Fatal(err)
		}
	}
	during, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(during) - len(before); got > 2*len(sessions)+8 {
		t.Fatalf("fd growth = %d, want at most %d", got, 2*len(sessions)+8)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(after) - len(before); got > 8 {
		t.Fatalf("fd leak after group close = %d", got)
	}
}

func TestRecorderGroupOwnerSelectionWaitsForAcquisition(t *testing.T) {
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	r.groupMu.Lock()
	result := make(chan error, 1)
	go func() {
		result <- r.Record(Entry{SessionID: sessions[0], Type: "test", Summary: "before acquisition"})
	}()
	select {
	case err := <-result:
		r.groupMu.Unlock()
		t.Fatalf("record bypassed the ownership lock: %v", err)
	default:
	}
	r.groupMu.Unlock()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := r.AcquireGroupSessions(sessions); err == nil {
		t.Fatal("group acquisition accepted after a single-session write")
	}
}

func TestRecorderGroupGatePrecedesAndCheckpointsShard(t *testing.T) {
	r, key, dir := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		gate := Entry{SessionID: session, Type: GroupGateEntryType, Detail: map[string]any{"group_id": "group"}}
		if err := r.RecordGroupGate(gate); err != nil {
			t.Fatal(err)
		}
		if err := r.RecordGroupGate(gate); err == nil {
			t.Fatal("duplicate group gate accepted")
		}
		if err := r.RecordDurable(Entry{SessionID: session, Type: "test", Summary: "after gate"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("session %s paths = %v, %v", session, paths, err)
		}
		entries, err := ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 4 || entries[0].Type != GroupGateEntryType || entries[1].Type != checkpointType || entries[2].Type != "test" {
			t.Fatalf("unexpected group shard entry order: %+v", entries)
		}
		if err := VerifyChain(entries, key.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecorderGroupGateSyncFailureStopsOpening(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("sync_%d", failAt), func(t *testing.T) {
			r, _, _ := newGroupRecorder(t)
			sessions := groupSessionIDs(t, 2)
			if err := r.AcquireGroupSessions(sessions); err != nil {
				t.Fatal(err)
			}
			calls := 0
			r.SetSyncForTest(func(f *os.File) error {
				calls++
				if calls == failAt {
					return errors.New("injected sync failure")
				}
				return f.Sync()
			})
			gate := Entry{SessionID: sessions[0], Type: GroupGateEntryType, Detail: map[string]any{"group_id": "group"}}
			if err := r.RecordGroupGate(gate); err == nil || !strings.Contains(err.Error(), "injected sync failure") {
				t.Fatalf("group gate sync result = %v", err)
			}
			if err := r.RecordGroupGate(gate); err == nil {
				t.Fatal("group gate retried after partial publication")
			}
		})
	}
}

func TestRecorderFinalizeGroupSessionsRetainsOwnership(t *testing.T) {
	r, key, dir := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if err := r.Record(Entry{SessionID: session, Type: "test", Summary: "pending checkpoint"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.FinalizeGroupSessions(); err != nil {
		t.Fatal(err)
	}
	if err := r.FinalizeGroupSessions(); err == nil {
		t.Fatal("second finalization accepted")
	}
	if err := r.Record(Entry{SessionID: sessions[0], Type: "test"}); err == nil {
		t.Fatal("write accepted after finalization")
	}
	for _, session := range sessions {
		gone, err := EvidenceRunWriterGone(dir, session)
		if err != nil || gone {
			t.Fatalf("finalization released run presence before close: gone=%v err=%v", gone, err)
		}
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("session %s paths = %v, %v", session, paths, err)
		}
		entries, err := ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 || entries[1].Type != checkpointType {
			t.Fatalf("session %s final entries = %+v", session, entries)
		}
		if err := VerifyChain(entries, key.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		gone, err := EvidenceRunWriterGone(dir, session)
		if err != nil || !gone {
			t.Fatalf("session %s presence lock remained: gone=%v err=%v", session, gone, err)
		}
	}
}

func TestRecorderFinalizeGroupSessionsSyncFailureCleansWithoutNewEvidence(t *testing.T) {
	r, _, dir := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if err := r.Record(Entry{SessionID: session, Type: "test", Summary: "pending checkpoint"}); err != nil {
			t.Fatal(err)
		}
	}
	r.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := r.FinalizeGroupSessions(); err == nil || !strings.Contains(err.Error(), "injected sync failure") {
		t.Fatalf("finalization error = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("session %s paths = %v, %v", session, paths, err)
		}
		entries, err := ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Type != "test" {
			t.Fatalf("close appended evidence after failed finalization: %+v", entries)
		}
		gone, err := EvidenceRunWriterGone(dir, session)
		if err != nil || !gone {
			t.Fatalf("session %s presence lock remained: gone=%v err=%v", session, gone, err)
		}
	}
}
