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

func TestStartupPrefixWriterProbeRefusals(t *testing.T) {
	for _, mode := range []string{"missing", "live"} {
		t.Run(mode, func(t *testing.T) {
			c, open, hash, _ := startupCoverageGroup(t, false)
			path := filepath.Join(c.dir, recorder.RunWriterLockPrefix+open.Shards[0].SessionID+recorder.RunWriterLockSuffix)
			if mode == "missing" {
				if err := os.Rename(path, filepath.Join(t.TempDir(), "old-lock")); err != nil {
					t.Fatal(err)
				}
			} else {
				f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
			}
			if mode == "live" {
				_, err := verifyGroupShardPrefixWithSession(c.dir, open, hash, 0, nil)
				if err == nil || !strings.Contains(err.Error(), "writer still present") {
					t.Fatalf("live predecessor prefix=%v", err)
				}
			}
			c.prepareShards(open, hash, true)
			proof := c.proofs[open.Shards[0].SessionID]
			want := "writer still present"
			if mode == "missing" {
				want = "probe receipt group predecessor writer"
			}
			if proof == nil || proof.err == nil || !strings.Contains(proof.err.Error(), want) {
				t.Fatalf("proof=%+v", proof)
			}
			_, err := verifyGroupShardPrefixUsing(c.dir, open, hash, 0, c)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("cached proof bypassed re-probe: %v", err)
			}
		})
	}
}
