// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// An unclosed predecessor that cannot be read is not a crashed predecessor.
// Startup must stop without publishing successor artifacts, so a transient
// read failure never turns into durable lifecycle state.
func TestOpenSuccessorRefusesUnreadablePredecessorWithoutPublishing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial does not apply to root")
	}
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
	shards, err := filepath.Glob(filepath.Join(dir, "evidence-"+opening.Shards[1].SessionID+"-*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("predecessor shard files: %v %v", shards, err)
	}
	if err := os.Chmod(shards[0], 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shards[0], 0o600) })
	if _, err := os.ReadFile(shards[0]); err == nil {
		t.Skip("process can read mode-0 files")
	}
	before, err := filepath.Glob(filepath.Join(dir, "receipt-group-*"))
	if err != nil {
		t.Fatal(err)
	}

	secondRecorder, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondRecorder.Close() })
	if _, err := OpenSuccessorReceiptShardSet(EmitterConfig{
		Recorder: secondRecorder, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, "proxy", 2, 0, opening.GroupID); err == nil {
		t.Fatal("successor opened over an unreadable predecessor")
	}
	after, err := filepath.Glob(filepath.Join(dir, "receipt-group-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("refused startup published group artifacts: before=%v after=%v", before, after)
	}
}
