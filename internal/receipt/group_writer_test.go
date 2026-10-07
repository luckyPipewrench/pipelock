// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestOpenInitialReceiptShardSetWritesBoundGatesAndOpens(t *testing.T) {
	publicKey, key := generateTestKey(t)
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
	open, openHash := set.Opening()
	name, err := ReceiptGroupFileName(open.GroupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceiptGroupOpen(raw, []string{open.SignerKey}); err != nil {
		t.Fatal(err)
	}
	if openHash == "" || len(open.Shards) != 2 {
		t.Fatalf("incomplete opening: %+v %q", open, openHash)
	}
	for i := range 4 {
		opts := set.Admit(EmitOpts{
			ActionID: NewActionID(), Verdict: config.ActionAllow,
			Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data",
		})
		if opts.ShardIndex != i%2 || !opts.ShardSelected {
			t.Fatalf("admission %d selected shard %d", i, opts.ShardIndex)
		}
		if err := set.EmitDurable(opts); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Emit(EmitOpts{ActionID: NewActionID()}); err == nil {
		t.Fatal("missing admission shard was accepted")
	}
	if err := set.Emit(EmitOpts{ShardSelected: true, ShardIndex: 2}); err == nil {
		t.Fatal("out-of-range shard was accepted")
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	for i, shard := range open.Shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("shard %d paths = %v, %v", i, paths, err)
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) < 5 || entries[0].Type != recorder.GroupGateEntryType || entries[1].Type != "checkpoint" || entries[2].Type != recorderEntryType {
			t.Fatalf("shard %d entry order: %+v", i, entries)
		}
		if err := recorder.VerifyChain(entries, publicKey); err != nil {
			t.Fatal(err)
		}
		var legacy WholeRecorderWalker
		legacy.Add(entries[0])
		if !errors.Is(legacy.Err(), ErrUnexpectedRecorderEntryType) {
			t.Fatalf("legacy walker accepted a grouped shard: %v", legacy.Err())
		}
		group := NewGroupRecorderWalker()
		for _, entry := range entries {
			group.Add(entry)
		}
		if err := group.Err(); err != nil {
			t.Fatalf("group walker rejected shard %d: %v", i, err)
		}
		missing := NewGroupRecorderWalker()
		missing.Add(entries[1])
		if missing.Err() == nil {
			t.Fatal("group walker accepted a missing opening gate")
		}
		duplicate := NewGroupRecorderWalker()
		duplicate.Add(entries[0])
		duplicate.Add(entries[0])
		if !errors.Is(duplicate.Err(), ErrUnexpectedRecorderEntryType) {
			t.Fatalf("group walker accepted a repeated gate: %v", duplicate.Err())
		}
		opening, err := receiptFromEntry(entries[2])
		if err != nil {
			t.Fatal(err)
		}
		binding := opening.ActionRecord.SessionControl.Open.GroupBinding
		if binding == nil || binding.GroupID != open.GroupID || binding.ShardIndex != i || binding.SessionID != shard.SessionID || binding.OpenManifestSHA256 != openHash {
			t.Fatalf("shard %d binding = %+v", i, binding)
		}
		if err := VerifyWithKey(*opening, opening.SignerKey); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key}, "proxy", 2, 0); err == nil || !strings.Contains(err.Error(), "existing receipt group") {
		t.Fatalf("second initial group result = %v", err)
	}
}

func TestReceiptShardSetPublishCloseRequiresEveryVerifiedShard(t *testing.T) {
	for _, omitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "missing_shard_close"}[omitted], func(t *testing.T) {
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
			open, openHash := set.Opening()
			for i, e := range set.Emitters() {
				if omitted && i == 1 {
					continue
				}
				if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
					t.Fatal(err)
				}
				if err := e.EmitTranscriptRoot(e.Session()); err != nil {
					t.Fatal(err)
				}
			}
			_, err = set.PublishClose()
			name, nameErr := ReceiptGroupFileName(open.GroupID, "close")
			if nameErr != nil {
				t.Fatal(nameErr)
			}
			raw, readErr := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- name comes from ReceiptGroupFileName in this test.
			if omitted {
				if err == nil || !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("incomplete group published close: close=%v read=%v", err, readErr)
				}
				if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupIncomplete {
					t.Fatalf("unclosed group verdict = %+v", got)
				}
				return
			}
			if err != nil || readErr != nil {
				t.Fatalf("complete group close=%v read=%v", err, readErr)
			}
			closed, err := UnmarshalReceiptGroupClose(raw, open, openHash, []string{open.SignerKey})
			if err != nil || len(closed.Shards) != 2 {
				t.Fatalf("signed close = %+v, %v", closed, err)
			}
			for i, head := range closed.Shards {
				verified, err := VerifyGroupShardHead(dir, open, openHash, i)
				if err != nil || head != verified {
					t.Fatalf("shard %d claimed %+v, verified %+v: %v", i, head, verified, err)
				}
			}
			if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupValid {
				t.Fatalf("complete directory verdict = %+v", got)
			}
			unknown := filepath.Join(dir, "receipt-group-"+open.GroupID+"-unknown.json")
			if err := os.WriteFile(unknown, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupInvalid || !strings.Contains(got.Error, "unknown receipt group artifact") {
				t.Fatalf("unknown group artifact verdict = %+v", got)
			}
			if err := os.Remove(unknown); err != nil {
				t.Fatal(err)
			}
			orphan := filepath.Join(dir, "ael", strings.Repeat("f", 32))
			if err := os.Mkdir(orphan, 0o750); err != nil {
				t.Fatal(err)
			}
			if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupInvalid || !strings.Contains(got.Error, "no signed session owner") {
				t.Fatalf("orphan native AEL verdict = %+v", got)
			}
			if err := os.Remove(orphan); err != nil {
				t.Fatal(err)
			}
			firstFiles, err := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-0.jsonl"))
			if err != nil || len(firstFiles) != 1 {
				t.Fatalf("first shard files = %v, %v", firstFiles, err)
			}
			firstBytes, err := os.ReadFile(firstFiles[0])
			if err != nil {
				t.Fatal(err)
			}
			extra := filepath.Join(dir, "evidence-proxy.run."+strings.Repeat("e", 32)+"-0.jsonl")
			if err := os.WriteFile(extra, firstBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupInvalid || !strings.Contains(got.Error, "unlisted gated session") {
				t.Fatalf("extra group session verdict = %+v", got)
			}
			if err := os.Remove(extra); err != nil {
				t.Fatal(err)
			}
			paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[1].SessionID+"-*.jsonl"))
			if err != nil || len(paths) == 0 {
				t.Fatalf("shard evidence files = %v, %v", paths, err)
			}
			if err := os.Remove(paths[0]); err != nil {
				t.Fatal(err)
			}
			if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupInvalid {
				t.Fatalf("deleted shard group verdict = %+v", got)
			}
		})
	}
}

func TestPublishLateReceiptGroupCloseRequiresOriginalKeyAndNoSuccessor(t *testing.T) {
	for _, mode := range []string{"complete", "rotated_key", "successor", "duplicate_close", "invalid_transition", "changed_directory", "missing_shard", "corrupt_opening", "damaged_legacy_ael", "torn_earlier_segment"} {
		t.Run(mode, func(t *testing.T) {
			_, key := generateTestKey(t)
			dir := t.TempDir()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			set, err := OpenInitialReceiptShardSet(EmitterConfig{
				Recorder: rec, PrivKey: key, ConfigHash: testConfigHash,
				Principal: testPrincipal, Actor: testActor,
			}, "proxy", 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			open, openHash := set.Opening()
			for _, e := range set.Emitters() {
				if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
					t.Fatal(err)
				}
				if err := e.EmitTranscriptRoot(e.Session()); err != nil {
					t.Fatal(err)
				}
			}
			if err := rec.FinalizeGroupSessions(); err != nil {
				t.Fatal(err)
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "successor" {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				successor, err := SignReceiptGroupOpen(ReceiptGroupOpen{
					GroupID: strings.Repeat("2", 32), BaseSession: "proxy", ShardCount: 2,
					ProcessShardIndex: 0, PreviousGroupID: open.GroupID,
					PreviousOpenManifestSHA256: openHash, CreatedAt: now,
					Shards: []ReceiptGroupShard{
						{ShardIndex: 0, SessionID: "proxy.run." + strings.Repeat("c", 32)},
						{ShardIndex: 1, SessionID: "proxy.run." + strings.Repeat("d", 32)},
					},
				}, key)
				if err != nil {
					t.Fatal(err)
				}
				newName, _ := ReceiptGroupFileName(successor.GroupID, "open")
				newHash, err := PublishReceiptGroupArtifact(dir, newName, successor)
				if err != nil {
					t.Fatal(err)
				}
				predecessors := make([]ReceiptGroupPredecessor, 2)
				for i := range predecessors {
					head, err := VerifyGroupShardHead(dir, open, openHash, i)
					if err != nil {
						t.Fatal(err)
					}
					predecessors[i] = ReceiptGroupPredecessor{ShardIndex: i, SessionID: head.SessionID, FinalChainSeq: head.FinalChainSeq, FinalChainHash: head.FinalChainHash}
				}
				tr, err := SignReceiptGroupTransition(ReceiptGroupTransition{
					NewGroupID: successor.GroupID, NewOpenManifestSHA256: newHash,
					PreviousGroupID: open.GroupID, PreviousOpenManifestSHA256: openHash,
					Predecessors: predecessors, CreatedAt: now,
				}, successor, open, newHash, openHash, "", key)
				if err != nil {
					t.Fatal(err)
				}
				trName, _ := ReceiptGroupFileName(successor.GroupID, "transition")
				if _, err := PublishReceiptGroupArtifact(dir, trName, tr); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "invalid_transition" {
				name, _ := ReceiptGroupFileName(strings.Repeat("2", 32), "transition")
				if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing_shard" {
				if err := os.Remove(filepath.Join(dir, "evidence-"+open.Shards[1].SessionID+"-0.jsonl")); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "corrupt_opening" {
				name, _ := ReceiptGroupFileName(open.GroupID, "open")
				if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "damaged_legacy_ael" || mode == "torn_earlier_segment" {
				maxEntries := 0
				if mode == "torn_earlier_segment" {
					maxEntries = 1
				}
				legacyRec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true, MaxEntriesPerFile: maxEntries}, nil, key)
				if err != nil {
					t.Fatal(err)
				}
				session, err := recorder.AcquireRunSession(legacyRec, "proxy")
				if err != nil {
					t.Fatal(err)
				}
				legacy := NewEmitter(EmitterConfig{Recorder: legacyRec, PrivKey: key, Session: session, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
				if err := legacy.EmitSessionOpen(); err != nil {
					t.Fatal(err)
				}
				if err := legacy.EmitSessionClose("graceful_shutdown"); err != nil {
					t.Fatal(err)
				}
				if err := legacy.EmitTranscriptRoot(legacy.Session()); err != nil {
					t.Fatal(err)
				}
				if err := legacyRec.Close(); err != nil {
					t.Fatal(err)
				}
				stream := filepath.Join(legacy.nativeAEL.Dir(), "recorders", "pipelock.jsonl")
				if mode == "torn_earlier_segment" {
					segments, listErr := recorderFiles(dir, session)
					if listErr != nil || len(segments) < 2 {
						t.Fatalf("legacy run did not rotate: %v %v", segments, listErr)
					}
					stream = segments[0]
				}
				f, err := os.OpenFile(stream, os.O_APPEND|os.O_WRONLY, 0) // #nosec G304 -- test-created native AEL stream or evidence segment.
				if err != nil {
					t.Fatal(err)
				}
				damage := "damaged\n"
				if mode == "torn_earlier_segment" {
					damage = `{"partial":`
				}
				if _, err := f.WriteString(damage); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "duplicate_close" {
				if _, err := PublishLateReceiptGroupClose(dir, open.GroupID, key); err != nil {
					t.Fatalf("first late close: %v", err)
				}
			}
			closingKey := key
			if mode == "rotated_key" {
				_, closingKey = generateTestKey(t)
			}
			if mode == "changed_directory" {
				_, err = publishLateReceiptGroupClose(dir, open.GroupID, closingKey, func() {
					if writeErr := os.WriteFile(filepath.Join(dir, "out-of-band-change"), []byte("changed"), 0o600); writeErr != nil {
						t.Fatal(writeErr)
					}
				})
				if err == nil || !strings.Contains(err.Error(), "directory changed before late close") {
					t.Fatalf("out-of-band directory change accepted: %v", err)
				}
				closeName, _ := ReceiptGroupFileName(open.GroupID, "close")
				if _, statErr := os.Stat(filepath.Join(dir, closeName)); !os.IsNotExist(statErr) {
					t.Fatalf("late close published after directory change: %v", statErr)
				}
				return
			}
			_, err = PublishLateReceiptGroupClose(dir, open.GroupID, closingKey)
			if mode == "complete" && err != nil {
				t.Fatalf("complete late close: %v", err)
			}
			if mode != "complete" && err == nil {
				t.Fatalf("late close accepted %s", mode)
			}
			if mode == "missing_shard" && !strings.Contains(err.Error(), "late receipt group close shard") {
				t.Fatalf("missing shard failure was not reported: %v", err)
			}
			if mode == "corrupt_opening" && !strings.Contains(err.Error(), "exact opening key and manifest") {
				t.Fatalf("corrupt opening failure was not reported: %v", err)
			}
			if (mode == "damaged_legacy_ael" || mode == "torn_earlier_segment") && !strings.Contains(err.Error(), "AEL inventory") {
				t.Fatalf("late close did not report the damaged native run: %v", err)
			}
		})
	}
}

func TestPublishLateReceiptGroupCloseRejectsMissingOrUnsafeOpening(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
		t.Fatal(err)
	}
	groupID := strings.Repeat("1", 32)
	for _, tc := range []struct {
		name string
		id   string
		key  []byte
		want string
	}{
		{name: "missing key", id: groupID, want: "opening private key"},
		{name: "invalid id", id: "bad", key: key, want: "invalid receipt group ID"},
		{name: "missing opening", id: groupID, key: key, want: "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PublishLateReceiptGroupClose(dir, tc.id, tc.key); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("late close error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyReceiptGroupKeepsLegacyAELClaim(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	groupRec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	set, err := OpenInitialReceiptShardSet(EmitterConfig{
		Recorder: groupRec, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
	for _, emitter := range set.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if err := groupRec.Close(); err != nil {
		t.Fatal(err)
	}
	legacyRec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacyRec.Close() })
	legacySession, err := recorder.AcquireRunSession(legacyRec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	legacy := NewEmitter(EmitterConfig{
		Recorder: legacyRec, PrivKey: key, Session: legacySession,
		ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor,
	})
	if legacy == nil {
		t.Fatal("legacy emitter initialization returned nil")
	}
	if legacy.InitError() != nil {
		t.Fatalf("legacy emitter initialization: %v", legacy.InitError())
	}
	if err := legacy.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := legacy.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
	if err := legacy.EmitTranscriptRoot(legacy.Session()); err != nil {
		t.Fatal(err)
	}
	if err := legacyRec.Close(); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupValid {
		t.Fatalf("legacy run and AEL stream changed group verdict: %+v", got)
	}
}

func TestOpenSuccessorReceiptShardSetBindsClosedPredecessor(t *testing.T) {
	_, firstKey := generateTestKey(t)
	_, secondKey := generateTestKey(t)
	_, thirdKey := generateTestKey(t)
	dir := t.TempDir()
	newRecorder := func(key ed25519.PrivateKey) *recorder.Recorder {
		t.Helper()
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	config := func(rec *recorder.Recorder, key ed25519.PrivateKey) EmitterConfig {
		return EmitterConfig{
			Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor,
			PriorSignerKeys: []string{fmt.Sprintf("%x", firstKey.Public()), fmt.Sprintf("%x", secondKey.Public())},
		}
	}
	assertTerminal := func(want string) {
		t.Helper()
		got, found, err := FindTerminalReceiptGroup(dir, "proxy", []string{fmt.Sprintf("%x", firstKey.Public()), fmt.Sprintf("%x", secondKey.Public()), fmt.Sprintf("%x", thirdKey.Public())})
		if err != nil || !found || got != want {
			t.Fatalf("terminal group = %q found=%v err=%v; want %q", got, found, err, want)
		}
	}
	seal := func(set *ReceiptShardSet) {
		t.Helper()
		for _, emitter := range set.Emitters() {
			if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
				t.Fatal(err)
			}
			if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := set.PublishClose(); err != nil {
			t.Fatal(err)
		}
	}
	firstRecorder := newRecorder(firstKey)
	first, err := OpenInitialReceiptShardSet(config(firstRecorder, firstKey), "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstOpen, firstHash := first.Opening()
	seal(first)
	if err := firstRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	assertTerminal(firstOpen.GroupID)
	secondRecorder := newRecorder(secondKey)
	t.Cleanup(func() { _ = secondRecorder.Close() })
	second, err := OpenSuccessorReceiptShardSet(config(secondRecorder, secondKey), "proxy", 2, 0, firstOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	secondOpen, secondHash := second.Opening()
	assertTerminal(secondOpen.GroupID)
	if secondOpen.PreviousGroupID != firstOpen.GroupID || secondOpen.PreviousOpenManifestSHA256 != firstHash {
		t.Fatalf("successor opening lost predecessor: %+v", secondOpen)
	}
	transitionName, _ := ReceiptGroupFileName(secondOpen.GroupID, "transition")
	transitionBytes, err := readBoundedGroupFile(dir, transitionName)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := VerifyReceiptGroup(dir, firstOpen.GroupID, []string{firstOpen.SignerKey, secondOpen.SignerKey})
	if firstResult.Verdict != GroupValid {
		t.Fatalf("predecessor became invalid after successor opening: %+v", firstResult)
	}
	if _, err := UnmarshalReceiptGroupTransition(transitionBytes, secondOpen, firstOpen, secondHash, firstHash, firstResult.CloseManifestSHA, []string{firstOpen.SignerKey, secondOpen.SignerKey}); err != nil {
		t.Fatalf("signed successor transition: %v", err)
	}
	seal(second)
	if err := secondRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	if result := VerifyReceiptGroup(dir, secondOpen.GroupID, []string{firstOpen.SignerKey, secondOpen.SignerKey}); result.Verdict != GroupValid {
		t.Fatalf("successor group verdict = %+v", result)
	}
	staleRecorder := newRecorder(thirdKey)
	if _, err := OpenSuccessorReceiptShardSet(config(staleRecorder, thirdKey), "proxy", 2, 0, firstOpen.GroupID); err == nil || !strings.Contains(err.Error(), "predecessor changed") {
		t.Fatalf("stale predecessor accepted: %v", err)
	}
	if err := staleRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	thirdRecorder := newRecorder(thirdKey)
	t.Cleanup(func() { _ = thirdRecorder.Close() })
	third, err := OpenSuccessorReceiptShardSet(config(thirdRecorder, thirdKey), "proxy", 2, 0, secondOpen.GroupID)
	if err != nil {
		t.Fatalf("second signer rotation: %v", err)
	}
	thirdOpen, _ := third.Opening()
	assertTerminal(thirdOpen.GroupID)
	seal(third)
	if err := thirdRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	if result := VerifyReceiptGroup(dir, thirdOpen.GroupID, []string{firstOpen.SignerKey, secondOpen.SignerKey, thirdOpen.SignerKey}); result.Verdict != GroupValid {
		t.Fatalf("third group verdict = %+v", result)
	}
	if result := VerifyReceiptGroup(dir, thirdOpen.GroupID, []string{secondOpen.SignerKey, thirdOpen.SignerKey}); result.Verdict != GroupInvalid {
		t.Fatalf("unpinned historical owner accepted: %+v", result)
	}
}

func TestOpenSuccessorReceiptShardSetBindsUnclosedPredecessor(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	firstRecorder, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	first, err := OpenInitialReceiptShardSet(EmitterConfig{
		Recorder: firstRecorder, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := first.Opening()
	if err := firstRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	secondRecorder, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondRecorder.Close() })
	second, err := OpenSuccessorReceiptShardSet(EmitterConfig{
		Recorder: secondRecorder, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, "proxy", 2, 0, opening.GroupID)
	if err != nil {
		t.Fatalf("unclosed predecessor startup: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "receipt-group-*-open.json"))
	if err != nil || len(files) != 2 {
		t.Fatalf("successor opening inventory: %v, %v", files, err)
	}
	if result := VerifyReceiptGroup(dir, opening.GroupID, []string{opening.SignerKey}); result.Verdict != GroupIncomplete {
		t.Fatalf("unclosed predecessor verdict = %+v", result)
	}
	for _, emitter := range second.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := second.PublishClose(); err != nil {
		t.Fatal(err)
	}
	secondOpen, _ := second.Opening()
	if result := VerifyReceiptGroup(dir, secondOpen.GroupID, []string{opening.SignerKey}); result.Verdict != GroupValid {
		t.Fatalf("successor group verdict = %+v", result)
	}
}

func TestOpenSuccessorReceiptShardSetSealsTornPredecessor(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	newRecorder := func() *recorder.Recorder {
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	config := func(rec *recorder.Recorder) EmitterConfig {
		return EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	}
	firstRecorder := newRecorder()
	first, err := OpenInitialReceiptShardSet(config(firstRecorder), "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstOpen, _ := first.Opening()
	if err := firstRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+firstOpen.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("predecessor shard paths: %v, %v", paths, err)
	}
	file, err := os.OpenFile(paths[0], os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"torn":`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	secondRecorder := newRecorder()
	t.Cleanup(func() { _ = secondRecorder.Close() })
	second, err := OpenSuccessorReceiptShardSet(config(secondRecorder), "proxy", 2, 0, firstOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	secondOpen, _ := second.Opening()
	transitionName, _ := ReceiptGroupFileName(secondOpen.GroupID, "transition")
	transitionBytes, err := readBoundedGroupFile(dir, transitionName)
	if err != nil {
		t.Fatal(err)
	}
	var transition ReceiptGroupTransition
	if err := json.Unmarshal(transitionBytes, &transition); err != nil {
		t.Fatal(err)
	}
	if transition.PreviousCloseManifestSHA256 != "" || transition.Predecessors[0].RecoverySealSHA256 == "" || transition.Predecessors[1].RecoverySealSHA256 != "" {
		t.Fatalf("torn predecessor transition = %+v", transition)
	}
	for _, emitter := range second.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := second.PublishClose(); err != nil {
		t.Fatal(err)
	}
	trusted := []string{firstOpen.SignerKey}
	if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != GroupValid {
		t.Fatalf("sealed successor verdict = %+v", got)
	}
	sealPath := filepath.Join(dir, ChainLinkFileName(firstOpen.Shards[0].SessionID))
	if err := os.Remove(sealPath); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != GroupInvalid {
		t.Fatalf("missing recovery seal verdict = %+v", got)
	}
}

func TestPreparedSuccessorKeepsAdmissionClosedOnPrefixFailure(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	newRecorder := func() *recorder.Recorder {
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	groupConfig := func(rec *recorder.Recorder) EmitterConfig {
		return EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	}
	firstRecorder := newRecorder()
	first, err := OpenInitialReceiptShardSet(groupConfig(firstRecorder), "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstOpen, _ := first.Opening()
	if err := firstRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	secondRecorder := newRecorder()
	t.Cleanup(func() { _ = secondRecorder.Close() })
	second, err := PrepareSuccessorReceiptShardSet(groupConfig(secondRecorder), "proxy", 2, 0, firstOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	intent := EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}
	if admitted := second.Admit(intent); admitted.ShardSelected {
		t.Fatalf("prepared successor admitted traffic before transition: %+v", admitted)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+firstOpen.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("predecessor shard paths: %v, %v", paths, err)
	}
	if err := os.Remove(paths[0]); err != nil {
		t.Fatal(err)
	}
	if err := second.Activate(testConfigHash); err == nil {
		t.Fatal("successor activated after predecessor shard disappeared")
	}
	if admitted := second.Admit(intent); admitted.ShardSelected {
		t.Fatalf("failed successor admitted traffic: %+v", admitted)
	}
	if err := second.EmitDurable(EmitOpts{ShardSelected: true, ShardIndex: 0}); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("failed successor emission = %v", err)
	}
}

func TestSuccessorPublicationEdgesNeverVerifyComplete(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	newRecorder := func() *recorder.Recorder {
		t.Helper()
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	groupConfig := func(rec *recorder.Recorder) EmitterConfig {
		return EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	}
	firstRecorder := newRecorder()
	first, err := OpenInitialReceiptShardSet(groupConfig(firstRecorder), "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstOpen, _ := first.Opening()
	for _, emitter := range first.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := first.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if err := firstRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	secondRecorder := newRecorder()
	t.Cleanup(func() { _ = secondRecorder.Close() })
	second, err := PrepareSuccessorReceiptShardSet(groupConfig(secondRecorder), "proxy", 2, 0, firstOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	secondOpen, _ := second.Opening()
	trusted := []string{firstOpen.SignerKey, secondOpen.SignerKey}
	checkUnaccepted := func(edge string, want ReceiptGroupVerdict) {
		t.Helper()
		if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != want {
			t.Fatalf("%s: verdict = %+v, want %s", edge, got, want)
		}
		if selected := second.Admit(EmitOpts{}); selected.ShardSelected {
			t.Fatalf("%s: successor admitted before transition", edge)
		}
	}
	checkUnaccepted("after manifest and gates", GroupInvalid)
	for i, emitter := range second.Emitters() {
		if err := emitter.EmitSessionOpen(); err != nil {
			t.Fatal(err)
		}
		want := GroupInvalid // Another native run still has no signed owner.
		if i == len(second.Emitters())-1 {
			want = GroupIncomplete
		}
		checkUnaccepted(fmt.Sprintf("after session open %d", i), want)
	}
	if err := second.publishTransition(); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != GroupIncomplete {
		t.Fatalf("after transition: verdict = %+v, want incomplete before close", got)
	}
	for _, emitter := range second.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := second.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != GroupValid {
		t.Fatalf("complete successor: %+v", got)
	}
	transitionName, _ := ReceiptGroupFileName(secondOpen.GroupID, "transition")
	transitionPath := filepath.Join(dir, transitionName)
	transition, err := readBoundedGroupFile(dir, transitionName)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(transitionPath); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != GroupInvalid {
		t.Fatalf("deleted transition: %+v", got)
	}
	if err := os.WriteFile(transitionPath, transition, 0o600); err != nil {
		t.Fatal(err)
	}
	transition[len(transition)/2] ^= 1
	if err := os.WriteFile(transitionPath, transition, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != GroupInvalid {
		t.Fatalf("forged transition: %+v", got)
	}
}

func TestDecodeGroupGateRejectsUnknownAliasAndDuplicate(t *testing.T) {
	valid := ReceiptGroupBinding{
		GroupID: strings.Repeat("a", 32), ShardIndex: 0,
		SessionID:          "proxy.run." + strings.Repeat("b", 32),
		OpenManifestSHA256: strings.Repeat("c", 64), SignerKey: strings.Repeat("d", 64),
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var got ReceiptGroupBinding
	if err := decodeGroupEntryDetail(json.RawMessage(raw), &got); err != nil || got != valid {
		t.Fatalf("valid gate detail = %+v, %v", got, err)
	}
	for _, mutation := range []string{
		strings.Replace(string(raw), `"group_id":`, `"extra":1,"group_id":`, 1),
		strings.Replace(string(raw), `"group_id":`, `"Group_ID":"alias","group_id":`, 1),
		strings.Replace(string(raw), `"group_id":`, `"group_id":"duplicate","group_id":`, 1),
	} {
		if err := decodeGroupEntryDetail(json.RawMessage(mutation), &got); err == nil {
			t.Fatalf("accepted malformed group gate: %s", mutation)
		}
	}
}

func TestOpenInitialReceiptShardSetRejectsMismatchedSigner(t *testing.T) {
	_, recorderKey := generateTestKey(t)
	_, differentKey := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, recorderKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if _, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: differentKey}, "proxy", 2, 0); err == nil {
		t.Fatal("group opener accepted a checkpoint signer mismatch")
	}
	if _, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: ed25519.PrivateKey{}}, "proxy", 2, 0); err == nil {
		t.Fatal("group opener accepted an empty signer")
	}
}
