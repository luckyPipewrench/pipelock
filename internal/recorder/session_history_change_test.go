// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionHistoryRefusesChangedMembership(t *testing.T) {
	for _, mutation := range []string{"remove future shard", "add earlier shard", "add final shard", "replace directory"} {
		t.Run(mutation, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "evidence")
			if err := os.Mkdir(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			for i := range 5 {
				writeHistoryShard(t, dir, "change", uint64(i+1), 1)
			}
			seen := 0
			err := walkSessionHistoryEntries(historyLocation(t, dir), "change", 2, func(Entry) error {
				seen++
				if seen != 1 {
					return nil
				}
				switch mutation {
				case "remove future shard":
					return os.Remove(filepath.Join(dir, "evidence-change-5.jsonl"))
				case "add earlier shard":
					writeHistoryShard(t, dir, "change", 0, 1)
				case "add final shard":
					writeHistoryShard(t, dir, "change", 6, 1)
				case "replace directory":
					if err := os.Rename(dir, dir+"-old"); err != nil {
						return err
					}
					if err := os.Mkdir(dir, 0o750); err != nil {
						return err
					}
					for i := range 5 {
						writeHistoryShard(t, dir, "change", uint64(i+1), 1)
					}
				}
				return nil
			})
			if err == nil {
				t.Fatalf("changed membership accepted after %d entries", seen)
			}
		})
	}
}

func TestReadHistoryEntriesRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	name := writeHistoryShard(t, dir, "safe", 0, 1)
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(filepath.Join(dir, name), link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := ReadHistoryEntries(link); err == nil {
		t.Fatal("symlinked history accepted")
	}
}

func TestSessionHistoryIgnoresUnrelatedChanges(t *testing.T) {
	dir := t.TempDir()
	for i := range 5 {
		writeHistoryShard(t, dir, "steady", uint64(i), 1)
	}
	seen := 0
	err := walkSessionHistoryEntries(historyLocation(t, dir), "steady", 2, func(Entry) error {
		seen++
		writeHistoryShard(t, dir, "other", 0, seen)
		return os.WriteFile(filepath.Join(dir, "sidecar"), []byte("unrelated"), 0o600)
	})
	if err != nil || seen != 5 {
		t.Fatalf("unrelated changes: entries=%d err=%v", seen, err)
	}
}

func TestWalkHistorySessionsCompleteAndOrdered(t *testing.T) {
	dir := t.TempDir()
	// More names than one ordering window, with two shards for each name.
	for i := sessionHistoryWindow + 2; i >= 0; i-- {
		session := fmt.Sprintf("session%04d", i)
		writeHistoryShard(t, dir, session, 0, 1)
		writeHistoryShard(t, dir, session, 1, 1)
	}
	seen := 0
	err := WalkHistorySessions(dir, func(session string) error {
		want := fmt.Sprintf("session%04d", seen)
		if session != want {
			t.Fatalf("session %q want %q", session, want)
		}
		seen++
		return nil
	})
	if err != nil || seen != sessionHistoryWindow+3 {
		t.Fatalf("sessions=%d err=%v", seen, err)
	}
	if err := WalkHistorySessions(dir, nil); err == nil {
		t.Fatal("nil consumer accepted")
	}
	stop := errors.New("stop sessions")
	if err := WalkHistorySessions(dir, func(string) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("consumer error = %v", err)
	}
	if err := WalkHistorySessions(dir, func(string) error {
		writeHistoryShard(t, dir, "added", 0, 1)
		return nil
	}); err == nil {
		t.Fatal("changed inventory accepted")
	}
}
