// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifySuccessorRejectsPredecessorCloseHeadDisagreement(t *testing.T) {
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
	config := func(rec *recorder.Recorder) EmitterConfig {
		return EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
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
	firstRecorder := newRecorder()
	first, err := OpenInitialReceiptShardSet(config(firstRecorder), "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	seal(first)
	if err := firstRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	firstOpen, firstHash := first.Opening()
	secondRecorder := newRecorder()
	second, err := OpenSuccessorReceiptShardSet(config(secondRecorder), "proxy", 2, 0, firstOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	seal(second)
	if err := secondRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	secondOpen, secondHash := second.Opening()
	trusted := []string{firstOpen.SignerKey}
	if got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted); got.Verdict != GroupValid {
		t.Fatalf("valid control = %+v", got)
	}
	closeName, _ := ReceiptGroupFileName(firstOpen.GroupID, "close")
	closePath := filepath.Join(dir, closeName)
	raw, err := os.ReadFile(closePath) // #nosec G304 -- closePath is under this test's temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	originalCloseDigest := sha256.Sum256(raw)
	closed, err := UnmarshalReceiptGroupClose(raw, firstOpen, firstHash, trusted)
	if err != nil {
		t.Fatal(err)
	}
	closed.Shards[0].FinalChainHash = strings.Repeat("0", 64)
	closed, err = SignReceiptGroupClose(closed, firstOpen, firstHash, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(closed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(closePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	closeDigest := sha256.Sum256(raw)
	transitionName, _ := ReceiptGroupFileName(secondOpen.GroupID, "transition")
	transitionPath := filepath.Join(dir, transitionName)
	transitionRaw, err := os.ReadFile(transitionPath) // #nosec G304 -- transitionPath is under this test's temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	transition, err := UnmarshalReceiptGroupTransition(transitionRaw, secondOpen, firstOpen, secondHash, firstHash, hex.EncodeToString(originalCloseDigest[:]), trusted)
	if err != nil {
		t.Fatal(err)
	}
	transition.PreviousCloseManifestSHA256 = hex.EncodeToString(closeDigest[:])
	transition, err = SignReceiptGroupTransition(transition, secondOpen, firstOpen, secondHash, firstHash, transition.PreviousCloseManifestSHA256, key)
	if err != nil {
		t.Fatal(err)
	}
	transitionRaw, err = json.Marshal(transition)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transitionPath, transitionRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	got := VerifyReceiptGroup(dir, secondOpen.GroupID, trusted)
	if got.Verdict != GroupInvalid || !strings.Contains(got.Error, "differs from signed close") {
		t.Fatalf("mismatched signed predecessor evidence accepted: %+v", got)
	}
}

func TestVerifyReceiptGroupRejectsDeletedShardEvidence(t *testing.T) {
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
	open, _ := set.Opening()
	if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupValid {
		t.Fatalf("complete group = %+v", got)
	}
	shard := filepath.Join(dir, "evidence-"+open.Shards[1].SessionID+"-0.jsonl")
	if err := os.Remove(shard); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupInvalid {
		t.Fatalf("deleted shard accepted as complete group: %+v", got)
	}
}

func TestVerifyReceiptGroupRejectsFalseSignedCloseHead(t *testing.T) {
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
	open, openHash := set.Opening()
	closeName, _ := ReceiptGroupFileName(open.GroupID, "close")
	closePath := filepath.Join(dir, closeName)
	// #nosec G304 -- closePath uses this test's temporary directory and validated group ID.
	raw, err := os.ReadFile(closePath)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := UnmarshalReceiptGroupClose(raw, open, openHash, []string{open.SignerKey})
	if err != nil {
		t.Fatal(err)
	}
	closed.Shards[1].FinalChainHash = strings.Repeat("0", 64)
	forged, err := SignReceiptGroupClose(closed, open, openHash, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(closePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != GroupInvalid {
		t.Fatalf("false signed close head accepted: %+v", got)
	}
}

func TestVerifyReceiptGroupNeverPassesMissingOrMalformedClose(t *testing.T) {
	for _, mode := range []string{"missing", "malformed"} {
		t.Run(mode, func(t *testing.T) {
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
			open, _ := set.Opening()
			trusted := []string{open.SignerKey}
			if got := VerifyReceiptGroup(dir, open.GroupID, trusted); got.Verdict != GroupValid {
				t.Fatalf("valid fixture rejected: %+v", got)
			}
			closeName, _ := ReceiptGroupFileName(open.GroupID, "close")
			closePath := filepath.Join(dir, closeName)
			if mode == "missing" {
				if err := os.Remove(closePath); err != nil {
					t.Fatal(err)
				}
				if got := VerifyReceiptGroup(dir, open.GroupID, trusted); got.Verdict != GroupIncomplete {
					t.Fatalf("missing close = %+v, want GROUP_INCOMPLETE", got)
				}
				return
			}
			if err := os.WriteFile(closePath, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := VerifyReceiptGroup(dir, open.GroupID, trusted); got.Verdict != GroupInvalid {
				t.Fatalf("malformed close = %+v, want GROUP_INVALID", got)
			}
		})
	}
}
