// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"golang.org/x/sys/unix"
)

func TestStartupPublicationReprobesWriter(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	r := startupTestRecorder(t, dir, key)
	cfg := EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	set, err := OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, set, r, false)
	opening, _ := set.Opening()
	cfg.Recorder = startupTestRecorder(t, dir, key)
	next, err := PrepareSuccessorReceiptShardSet(cfg, "proxy", 2, 0, opening.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	// Acquire the writer's actual advisory lock without changing its metadata:
	// the consumed-input guard cannot substitute for the live-writer re-probe.
	f, err := os.OpenFile(filepath.Clean(filepath.Join(dir, recorder.RunWriterLockPrefix+opening.Shards[0].SessionID+recorder.RunWriterLockSuffix)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	if err = next.Activate(testConfigHash); err == nil || !strings.Contains(err.Error(), "writer still present") {
		t.Fatalf("publication accepted live writer: %v", err)
	}
	successor, _ := next.Opening()
	name, _ := ReceiptGroupFileName(successor.GroupID, "transition")
	if _, err = os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("live writer transition published: %v", err)
	}
}
