// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestConcurrentRecordersEmitParseableLines proves a record and its newline
// reach the evidence file together.
//
// Concurrent recorder processes append to one shared file holding a shared
// lock, so a record written as two writes leaves a window for another writer to
// append between the record and its terminating newline. The result is a
// physical line carrying two JSON objects, which destroys both records: a
// run-aware reader cannot recover bytes that were merged.
//
// Buffering masks this below the buffer size, because the record and newline
// coalesce into one flush. Records larger than the buffer are written straight
// through and the newline follows separately, so the payload here is
// deliberately larger than the default 4096-byte buffer.
func TestConcurrentRecordersEmitParseableLines(t *testing.T) {
	dir := t.TempDir()
	const (
		writers          = 4
		entriesPerWriter = 40
		payloadBytes     = 6000 // over the 4096-byte buffer, so the pair cannot coalesce
	)

	recs := make([]*Recorder, 0, writers)
	for range writers {
		rec, err := New(Config{Enabled: true, Dir: dir, CheckpointInterval: 1_000_000}, nil, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = rec.Close() })
		recs = append(recs, rec)
	}

	payload := strings.Repeat("p", payloadBytes)
	var wg sync.WaitGroup
	for _, rec := range recs {
		wg.Add(1)
		go func(rec *Recorder) {
			defer wg.Done()
			for range entriesPerWriter {
				if err := rec.Record(Entry{
					SessionID: "proxy",
					Type:      "action_receipt",
					Summary:   payload,
				}); err != nil {
					t.Errorf("Record: %v", err)
					return
				}
			}
		}(rec)
	}
	wg.Wait()
	for _, rec := range recs {
		if err := rec.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	shards, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(shards) == 0 {
		t.Fatal("no evidence files written")
	}

	lines := 0
	for _, shard := range shards {
		f, openErr := os.Open(filepath.Clean(shard))
		if openErr != nil {
			t.Fatalf("Open(%q): %v", shard, openErr)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			lines++
			var probe map[string]any
			if unmarshalErr := json.Unmarshal(scanner.Bytes(), &probe); unmarshalErr != nil {
				_ = f.Close()
				t.Fatalf("line %d of %s is not a single JSON object, so two records shared one line: %v",
					lines, filepath.Base(shard), unmarshalErr)
			}
		}
		scanErr := scanner.Err()
		_ = f.Close()
		if scanErr != nil {
			t.Fatalf("scanning %q: %v", shard, scanErr)
		}
	}
	// Each recorder also writes its own genesis entry, so the floor is the
	// recorded entries. Falling below it means a merged line swallowed records.
	if floor := writers * entriesPerWriter; lines < floor {
		t.Fatalf("parsed %d lines, want at least %d: a merged line loses more than one record", lines, floor)
	}
}
