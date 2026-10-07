// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

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
