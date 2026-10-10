// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoryDetectsSameInodeRewriteWithRestoredMtime(t *testing.T) {
	for _, viaLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "hard link"}[viaLink], func(t *testing.T) {
			dir := t.TempDir()
			name := writeHistoryShard(t, dir, "rewrite", 0, 1)
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			target := path
			if viaLink {
				target = filepath.Join(dir, "alias")
				if err := os.Link(path, target); err != nil {
					t.Skipf("hard links unsupported: %v", err)
				}
			}
			err = WalkSessionHistory(dir, "rewrite", func(Entry) error {
				changed := bytes.Replace(raw, []byte(`"summary":"s"`), []byte(`"summary":"x"`), 1)
				if bytes.Equal(raw, changed) {
					t.Fatal("mutation did not change fixture")
				}
				if err := os.WriteFile(target, changed, 0o600); err != nil {
					return err
				}
				return os.Chtimes(target, info.ModTime(), info.ModTime())
			})
			if err == nil {
				t.Fatal("same-inode evidence rewrite accepted with restored size and mtime")
			}
		})
	}
}

func TestHistoryLargeInventoryRetainsOnlyWindow(t *testing.T) {
	dir := t.TempDir()
	const total = 10000
	for i := range total {
		name := fmt.Sprintf("evidence-large-%d.jsonl", i)
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys, more, inventory, err := scanHistoryWindow(historyLocation(t, dir), "large", nil, sessionHistoryWindow)
	if err != nil || !more || len(keys) != sessionHistoryWindow || inventory.count != total {
		t.Fatalf("large inventory: keys=%d more=%v count=%d err=%v", len(keys), more, inventory.count, err)
	}
	for i, key := range keys {
		if key.seq != uint64(i) {
			t.Fatalf("key %d = %+v", i, key)
		}
	}
}

func TestSessionSnapshotBindsSeparateReads(t *testing.T) {
	for _, fail := range []bool{false, true} {
		dir := t.TempDir()
		writeHistoryShard(t, dir, "paired", 0, 1)
		location := historyLocation(t, dir)
		failure := errors.New("second parser rejected")
		err := WithSessionHistorySnapshot(location, "paired", func() error {
			if err := WalkSessionHistoryResolved(location, "paired", func(Entry) error { return nil }); err != nil {
				return err
			}
			writeHistoryShard(t, dir, "paired", 1, 1)
			if fail {
				return failure
			}
			return WalkSessionHistoryResolved(location, "paired", func(Entry) error { return nil })
		})
		if !errors.Is(err, ErrEvidenceChanged) || errors.Is(err, failure) {
			t.Fatalf("separate snapshots mixed: %v", err)
		}
	}
}

func TestHistoryChangedFutureShardIsUnavailable(t *testing.T) {
	for _, mutation := range []string{"remove", "malformed", "torn", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			writeHistoryShard(t, dir, "active", 0, 1)
			name := writeHistoryShard(t, dir, "active", 1, 1)
			path := filepath.Join(dir, name)
			err := WalkSessionHistory(dir, "active", func(e Entry) error {
				if e.Sequence != 0 {
					return nil
				}
				switch mutation {
				case "remove":
					return os.Remove(path)
				case "malformed":
					return os.WriteFile(path, []byte("{malformed}\n"), 0o600)
				case "torn":
					return os.WriteFile(path, []byte("{torn"), 0o600)
				case "symlink":
					if err := os.Remove(path); err != nil {
						return err
					}
					return os.Symlink(filepath.Join(dir, "evidence-active-0.jsonl"), path)
				}
				return nil
			})
			if err == nil || !errors.Is(err, ErrEvidenceChanged) {
				t.Fatalf("changing shard should give unavailable result, got %v", err)
			}
		})
	}
}

func TestHistoryReadChecksSnapshotOnConsumerError(t *testing.T) {
	for _, surface := range []string{"session entries", "session files", "per file", "open reader"} {
		t.Run(surface, func(t *testing.T) {
			dir := t.TempDir()
			name := writeHistoryShard(t, dir, "errors", 0, 1)
			path := filepath.Join(dir, name)
			failure := errors.New("signature mismatch")
			mutate := func() error {
				if err := os.WriteFile(path, []byte("{changed}\n"), 0o600); err != nil {
					return err
				}
				return failure
			}
			var err error
			switch surface {
			case "session entries":
				err = WalkSessionHistory(dir, "errors", func(Entry) error { return mutate() })
			case "session files":
				err = WalkSessionHistoryFiles(historyLocation(t, dir), "errors", func(SessionHistoryShard, io.Reader) error { return mutate() })
			case "per file":
				_, err = WalkEvidenceFile(path, nil, func(Entry) error { return mutate() })
			case "open reader":
				file, openErr := os.Open(filepath.Clean(path))
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer func() { _ = file.Close() }()
				err = WalkHistoryEntriesFromReader(file, func(Entry) error { return mutate() })
			}
			if !errors.Is(err, ErrEvidenceChanged) || errors.Is(err, failure) || errors.Is(err, ErrTornTail) {
				t.Fatalf("changed read must replace the consumer verdict: %v", err)
			}
		})
	}
}

func TestHistoryInventoryTracksConsumedFileRewrite(t *testing.T) {
	dir := t.TempDir()
	name := writeHistoryShard(t, dir, "consumed", 0, 1)
	writeHistoryShard(t, dir, "consumed", 1, 1)
	path := filepath.Join(dir, name)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	err = WalkSessionHistory(dir, "consumed", func(e Entry) error {
		if e.Sequence == 0 {
			return nil
		}
		changed := bytes.Replace(raw, []byte(`"summary":"s"`), []byte(`"summary":"x"`), 1)
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			return err
		}
		return os.Chtimes(path, before.ModTime(), before.ModTime())
	})
	if !errors.Is(err, ErrEvidenceChanged) {
		t.Fatalf("consumed file rewrite: %v", err)
	}
}

func TestStandaloneHistoryDetectsPathReplacement(t *testing.T) {
	for _, replace := range []string{"rename", "symlink", "remove"} {
		t.Run(replace, func(t *testing.T) {
			dir := t.TempDir()
			name := writeHistoryShard(t, dir, "paths", 0, 1)
			path := filepath.Join(dir, name)
			err := WalkEvidenceFileReader(path, func(input io.ReadSeeker) error {
				if _, err := io.Copy(io.Discard, input); err != nil {
					return err
				}
				if err := os.Rename(path, path+".old"); err != nil {
					return err
				}
				switch replace {
				case "rename":
					writeHistoryShard(t, dir, "paths", 0, 1)
				case "symlink":
					return os.Symlink(path+".old", path)
				}
				return nil
			})
			if !errors.Is(err, ErrEvidenceChanged) {
				t.Fatalf("replaced evidence path: %v", err)
			}
		})
	}
}
