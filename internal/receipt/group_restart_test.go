// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestFreshRecorderCannotSkipUnpublishedSuccessorTransition(t *testing.T) {
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
	cfg := func(rec *recorder.Recorder) EmitterConfig {
		return EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	}

	predecessorRecorder := newRecorder()
	predecessor, err := OpenInitialReceiptShardSet(cfg(predecessorRecorder), "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	predecessorOpen, _ := predecessor.Opening()
	if err := predecessorRecorder.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash after the successor session opens are durable but before
	// the signed transition is published. The open already claims a predecessor,
	// so a later process must not build a third group on top of this gap.
	successorRecorder := newRecorder()
	successor, err := PrepareSuccessorReceiptShardSet(cfg(successorRecorder), "proxy", 2, 0, predecessorOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	successorOpen, _ := successor.Opening()
	for _, emitter := range successor.Emitters() {
		if err := emitter.EmitSessionOpen(); err != nil {
			t.Fatal(err)
		}
	}
	if err := successorRecorder.Close(); err != nil {
		t.Fatal(err)
	}

	restartRecorder := newRecorder()
	defer func() { _ = restartRecorder.Close() }()
	if result := VerifyReceiptGroup(dir, successorOpen.GroupID, []string{successorOpen.SignerKey, predecessorOpen.SignerKey}); result.Verdict == GroupValid {
		t.Fatalf("untransitioned successor verified complete after restart: %+v", result)
	}
	if _, err := OpenSuccessorReceiptShardSet(cfg(restartRecorder), "proxy", 2, 0, successorOpen.GroupID); err == nil {
		t.Fatal("fresh recorder accepted a successor whose own incoming transition was never published")
	}
}
